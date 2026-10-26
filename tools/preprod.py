#!/usr/bin/env python3
"""Build, inspect, and record three Wave 1 runs on a disposable Linux VM.

Storage mutation and cleanup belong exclusively to tests/integration/loop_matrix.py.
The default check command is read-only. Python 3.10+; standard library only.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

BINARIES = {
    'storagemgr': None,
    'lsm-disposable-loop-harness': 'disposable-loop-harness',
    'lsm-disposable-swap-loop-harness': 'disposable-swap-migration-harness',
    'lsm-production-loop-harness': 'production-loop-harness',
    'lsm-production-swap-loop-harness': 'production-swap-loop-harness',
    'lsm-production-create-loop-harness': 'production-create-loop-harness',
}
SOURCE_FILES = ('tools/preprod.py', 'tests/integration/loop_matrix.py')
TOOLS = ('losetup', 'sfdisk', 'partx', 'mkfs.ext4', 'mkfs.xfs', 'pvcreate',
         'vgcreate', 'vgchange', 'lvcreate', 'lvrename', 'vgremove', 'vgs', 'pvs', 'lvs',
         'mount', 'umount', 'findmnt', 'vgcfgbackup', 'vgcfgrestore', 'pvresize',
         'lvextend', 'resize2fs', 'e2fsck', 'xfs_growfs', 'xfs_scrub', 'udevadm',
         'mkswap', 'swapon', 'swapoff', 'lsblk')
REQUIRED_MARKERS = frozenset((
    'DISPOSABLE_RECOVERY_REQUIRED_OK=pre-spawn-failure-no-storage-change',
    'PV_RECOVERY_REQUIRED_OK=post-pvresize-pre-lvextend',
    'LV_RECOVERY_REQUIRED_OK=post-lvextend-pre-filesystem-grow',
    'FILESYSTEM_RECOVERY_REQUIRED_OK=post-resize2fs-pre-terminal-verification',
    'PV_LV_FILESYSTEM_EXECUTOR_OK=exact-pv-lv-fs-boundaries',
    'MULTI_PARTITION_SELECTION_OK=both-visible-tail-growable-neighbor-blocked',
    'MULTI_TARGET_ISOLATION_OK=selected-grown-sibling-unchanged',
    'EXT4_OFFLINE_EXECUTOR_OK=e2fsck-no-modify-lv-resize2fs',
    'XFS_ONLINE_EXECUTOR_OK=xfs-growfs-mounted-rw',
    'PRODUCTION_LOOP_E2E_OK=lvextend-resize2fs-verified-completed',
    'PRODUCTION_CHAINED_LOOP_E2E_OK=partition-pv-lv-resize2fs-verified-completed',
    'DISPOSABLE_SWAP_REPLACEMENT_OK=activate-verify-fault-boundary-swapoff-no-partition-mutation',
    'PRODUCTION_SWAP_REPLACEMENT_OK=runtime-persistence-partition-removal-completed',
    'LOOP_MATRIX_OK cleanup=complete',
)) | frozenset(
    f'{prefix}={table}-{suffix}'
    for table in ('gpt', 'dos')
    for prefix, suffix in (
        ('PARTITION_RECOVERY_REQUIRED_OK', 'post-write-pre-kernel-refresh'),
        ('PARTITION_PV_LV_FILESYSTEM_EXECUTOR_OK', 'size-only-boundaries'))
) | frozenset(
    f'PRODUCTION_CREATE_PERSISTENT_E2E_OK={table}-{fs}:create-format-mount-fstab-restart-restore-unmount'
    for table in ('gpt', 'dos') for fs in ('ext4', 'xfs')
)

class PreprodError(RuntimeError):
    pass


def command(argv, root=None):
    result = subprocess.run([str(a) for a in argv], cwd=root, text=True,
                            capture_output=True, check=False,
                            env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
    if result.returncode:
        raise PreprodError(f'{argv!r} exited {result.returncode}: {result.stderr.strip()}')
    return result.stdout.strip()


def digest(path):
    with path.open('rb') as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def source_sha(root):
    sha = command(['git', 'rev-parse', 'HEAD'], root)
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise PreprodError('source HEAD is not a full commit SHA')
    if command(['git', 'status', '--porcelain', '--untracked-files=all'], root):
        raise PreprodError('requires a clean checkout, including untracked source files')
    return sha


def atomic_text(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path, value):
    atomic_text(path, json.dumps(value, indent=2, sort_keys=True) + '\n')


def build(root):
    sha = source_sha(root)
    rust = command(['rustc', '--version'], root)
    if not rust.startswith('rustc 1.88.0 '):
        raise PreprodError(f'requires Rust 1.88.0; got {rust}')
    verbose = command(['rustc', '-vV'], root)
    match = re.search(r'^host: ([A-Za-z0-9_-]+)$', verbose, re.MULTILINE)
    if match is None:
        raise PreprodError('rustc -vV did not identify a native host target')
    host = match.group(1)
    target = root / 'target/preprod'
    target.mkdir(parents=True, exist_ok=True)
    manifest_path = target / 'build.json'
    # An interrupted build must not leave an earlier usable manifest.
    if manifest_path.exists() or manifest_path.is_symlink():
        manifest_path.unlink()
    for name, feature in BINARIES.items():
        argv = ['cargo', 'build', '--locked', '--release', '--target-dir', str(target), '--target', host]
        if feature:
            argv += ['-p', 'lsm-executor', '--features', feature, '--bin', name]
        else:
            argv += ['-p', 'linux-storage-manager-cli', '--bin', name]
        subprocess.run(argv, cwd=root, check=True)
    stage = target / 'release'
    if stage.is_symlink():
        raise PreprodError('binary staging directory must not be a symlink')
    stage.mkdir(exist_ok=True)
    for name in BINARIES:
        produced = target / host / 'release' / name
        if not stat.S_ISREG(produced.lstat().st_mode) or not os.access(produced, os.X_OK):
            raise PreprodError(f'build did not produce a native executable: {produced}')
        destination = stage / name
        if destination.is_symlink():
            raise PreprodError(f'binary staging path must not be a symlink: {destination}')
        shutil.copyfile(produced, destination)
        destination.chmod(0o755)
    if source_sha(root) != sha:
        raise PreprodError('source changed during build')
    paths = [f'target/preprod/release/{name}' for name in BINARIES] + list(SOURCE_FILES)
    manifest = {'source_sha': sha, 'rustc': rust, 'native_target': host,
                'files': {name: digest(root / name) for name in paths}}
    atomic_json(manifest_path, manifest)
    print(f'BUILD_READY source={sha} manifest={manifest_path}')
    return manifest


def tool_inventory():
    result = {}
    # Version flags vary. Preserve every status/output; do not execute format tools without flags.
    flags = {'mkfs.ext4': '-V', 'mkfs.xfs': '-V', 'e2fsck': '-V', 'resize2fs': '-V',
             'xfs_growfs': '-V', 'xfs_scrub': '-V', 'udevadm': '--version'}
    lvm = {'pvcreate', 'vgcreate', 'vgchange', 'lvcreate', 'lvrename', 'vgremove',
           'vgs', 'pvs', 'lvs', 'vgcfgbackup', 'vgcfgrestore', 'pvresize', 'lvextend'}
    for name in TOOLS:
        path = shutil.which(name)
        if path is None:
            raise PreprodError(f'required storage tool missing: {name}')
        flag = '--version' if name in lvm else flags.get(name, '--version')
        completed = subprocess.run([path, flag], capture_output=True, text=True,
                                   check=False, timeout=15,
                                   env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
        result[name] = {'path': path, 'resolved_path': os.path.realpath(path),
                        'version_argv': [path, flag], 'returncode': completed.returncode,
                        'stdout': completed.stdout, 'stderr': completed.stderr}
    return result


def check(root, expected):
    sha = source_sha(root)
    if expected is None or not re.fullmatch('[0-9a-f]{40}', expected) or sha != expected:
        raise PreprodError('requires --expected-source matching the exact clean source SHA')
    manifest = json.loads((root / 'target/preprod/build.json').read_text())
    if manifest.get('source_sha') != sha or not manifest.get('rustc', '').startswith('rustc 1.88.0 '):
        raise PreprodError('build manifest source or Rust version mismatch')
    paths = {f'target/preprod/release/{name}' for name in BINARIES} | set(SOURCE_FILES)
    if set(manifest.get('files', {})) != paths:
        raise PreprodError('build manifest does not identify all six binaries and runner/matrix sources')
    for name in paths:
        path = root / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or digest(path) != manifest['files'][name]:
            raise PreprodError(f'build artifact changed or is not a regular file: {name}')
        if name.startswith('target/') and not os.access(path, os.X_OK):
            raise PreprodError(f'build binary is not executable: {name}')
    return {**manifest, 'tools': tool_inventory()}


def stable_rows(rows):
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))


def parse_swaps(text):
    lines = text.splitlines()
    if not lines or lines[0].split() != ['Filename', 'Type', 'Size', 'Used', 'Priority']:
        raise PreprodError('invalid /proc/swaps header')
    result = []
    for line in lines[1:]:
        row = line.split()
        if len(row) != 5 or not all(re.fullmatch(r'-?[0-9]+', value) for value in row[2:]):
            raise PreprodError('invalid /proc/swaps row')
        result.append(dict(zip(('name', 'type', 'size', 'priority'),
                               (row[0], row[1], int(row[2]), int(row[4])))))
    return stable_rows(result)


def snapshot():
    raw = {}
    def collect(name, argv):
        data = json.loads(command(argv))
        raw[name] = data
        return data
    fstab = Path('/etc/fstab')
    info = fstab.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PreprodError('/etc/fstab must be a regular file')
    loops = collect('losetup', ['losetup', '--json', '--list', '--output',
                              'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT'])['loopdevices']
    mounts = collect('findmnt', ['findmnt', '--json', '--list', '--output',
                                'SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN'])['filesystems']
    raw['proc_swaps'] = Path('/proc/swaps').read_text()
    swaps = parse_swaps(raw['proc_swaps'])
    groups = []
    for tool, key, fields in (('vgs', 'vg', 'vg_name,vg_uuid'),
                              ('pvs', 'pv', 'pv_name,pv_uuid,vg_uuid'),
                              ('lvs', 'lv', 'lv_name,lv_uuid,vg_uuid')):
        data = collect(tool, [tool, '--reportformat', 'json', '--options', fields])
        groups.extend({'kind': key, **row} for report in data['report'] for row in report[key])
    collect('lsblk', ['lsblk', '--json', '--bytes', '--output',
                     'NAME,KNAME,TYPE,SIZE,FSTYPE,UUID,MOUNTPOINT,MAJ:MIN'])
    fixtures = []
    for parent, pattern in ((Path(tempfile.gettempdir()), 'lsm-loop-matrix-*'),
                            (Path('/mnt'), 'lsm-*-e2e-*')):
        for path in parent.glob(pattern):
            item = path.lstat()
            fixtures.append({'path': str(path), 'dev': item.st_dev, 'ino': item.st_ino})
    return {'fstab': {'sha256': digest(fstab), 'mode': stat.S_IMODE(info.st_mode),
                      'uid': info.st_uid, 'gid': info.st_gid},
            'loops': stable_rows(loops), 'mounts': stable_rows(mounts),
            'swaps': stable_rows(swaps), 'lvm': stable_rows(groups),
            'fixtures': stable_rows(fixtures), 'raw': raw}


def host_info():
    return {'os_release': Path('/etc/os-release').read_text(),
            'kernel': platform.release(), 'uname': list(platform.uname()),
            'arch': platform.machine(), 'python': sys.version}


def matrix_command(root):
    binary = root / 'target/preprod/release'
    return [sys.executable, '-I', str(root / 'tests/integration/loop_matrix.py'),
            '--allow-disposable-loop-tests', str(binary / 'storagemgr'),
            str(binary / 'lsm-disposable-loop-harness'),
            '--swap-executor-binary', str(binary / 'lsm-disposable-swap-loop-harness'),
            '--production-executor-binary', str(binary / 'lsm-production-loop-harness'),
            '--production-swap-executor-binary', str(binary / 'lsm-production-swap-loop-harness'),
            '--production-create-executor-binary', str(binary / 'lsm-production-create-loop-harness')]


def execute_matrix(argv, logfile):
    """Forward signals only to Python; wait without timeout for ownership-aware cleanup."""
    markers = set()
    interrupted = False
    child = None
    pending = []
    def forward(signum, _frame):
        nonlocal interrupted
        interrupted = True
        # One signal is enough; repeated signals can interrupt the child's finally block.
        if child is None:
            pending.append(signum)
        elif child.poll() is None and len(pending) == 0:
            pending.append(signum)
            child.send_signal(signum)
    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        with logfile.open('x', encoding='utf-8') as log:
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding='utf-8', errors='replace',
                                     start_new_session=True, bufsize=1)
            if pending and child.poll() is None:
                child.send_signal(pending[0])
            assert child.stdout is not None
            output_error = None
            try:
                for line in child.stdout:
                    if output_error is None:
                        try:
                            log.write(line)
                            log.flush()
                            print(line, end='', flush=True)
                        except (OSError, UnicodeError) as error:
                            # Keep draining: a closed terminal/full disk must not strand cleanup.
                            output_error = error
                    value = line.strip()
                    markers.add(value)
                    if value.startswith('LOOP_MATRIX_OK ') and value.endswith(' cleanup=complete'):
                        markers.add('LOOP_MATRIX_OK cleanup=complete')
            finally:
                # Never leave an active matrix child behind, including on a read error.
                # Do not send a second signal: its finally block may already be cleaning.
                child.wait()
                child.stdout.close()
            code = child.returncode
            if output_error is not None:
                raise output_error
        if any(line.startswith(('INTEGRATION_FAILED:', 'CLEANUP_INCOMPLETE:')) for line in markers):
            code = code or 1
        return code, markers, interrupted
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def save_report(output, report):
    atomic_json(output / 'report.json', report)
    lines = [f"RESULT={report['result']}", f"SOURCE_SHA={report['expected_source']}",
             f"WAVE1_REPETITIONS={sum(a.get('passed', False) for a in report['attempts'])}/3",
             'Evidence: report.json and attempt-N.log; successful low-level command output may be hidden by the matrix.']
    for attempt in report['attempts']:
        if attempt.get('returncode'):
            lines.append(f"ATTEMPT_{attempt['number']}: child exited {attempt['returncode']}")
        if attempt.get('missing_markers'):
            lines.append(f"ATTEMPT_{attempt['number']}: missing markers: " + ', '.join(attempt['missing_markers']))
        if attempt.get('changed'):
            lines.append(f"ATTEMPT_{attempt['number']}: changed resources: " + ', '.join(attempt['changed']))
        if attempt.get('execution_error'):
            lines.append(f"ATTEMPT_{attempt['number']}: " + attempt['execution_error'])
    if report.get('error'):
        lines.append('ERROR=' + report['error'])
    atomic_text(output / 'SUMMARY.txt', '\n'.join(lines) + '\n')


def run(root, expected, output):
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'result': 'IN_PROGRESS', 'expected_source': expected, 'attempts': [],
              'started': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    save_report(output, report)
    def interrupted_outside_child(signum, _frame):
        raise KeyboardInterrupt(f'received signal {signum}')
    previous = {sig: signal.signal(sig, interrupted_outside_child)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        report['build'] = check(root, expected)
        report['host'] = host_info()
        for repetition in range(1, 4):
            # Check source and artifact drift before every destructive launch.
            check(root, expected)
            attempt = {'number': repetition, 'command': matrix_command(root), 'passed': False}
            report['attempts'].append(attempt)
            attempt['before'] = snapshot()
            save_report(output, report)
            started = time.monotonic()
            try:
                code, markers, interrupted = execute_matrix(attempt['command'], output / f'attempt-{repetition}.log')
            except Exception as error:
                # execute_matrix waits for cleanup before propagating output/launch errors.
                code, markers, interrupted = 1, set(), False
                attempt['execution_error'] = f'{type(error).__name__}: {error}'
            attempt.update(returncode=code, markers=sorted(markers),
                           elapsed_seconds=time.monotonic() - started,
                           missing_markers=sorted(REQUIRED_MARKERS - markers))
            # Always collect after cleanup, including failure/interruption.
            if interrupted:
                report['result'] = 'INTERRUPTED'
            attempt['after'] = snapshot()
            attempt['changed'] = [key for key in ('fstab', 'loops', 'mounts', 'swaps', 'lvm', 'fixtures')
                                  if attempt['before'][key] != attempt['after'][key]]
            check(root, expected)
            attempt['passed'] = not (code or attempt['missing_markers'] or attempt['changed'] or interrupted)
            save_report(output, report)
            if not attempt['passed']:
                report['result'] = 'INTERRUPTED' if interrupted else 'FAIL'
                break
        else:
            report['result'] = 'PASS'
    except (Exception, KeyboardInterrupt) as error:
        if report['result'] != 'INTERRUPTED':
            report['result'] = 'INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'FAIL'
        report['error'] = f'{type(error).__name__}: {error}'
    for sig, handler in previous.items():
        signal.signal(sig, handler)
    report['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_report(output, report)
    print(f"WAVE1_RESULT={report['result']} evidence={output}")
    return 0 if report['result'] == 'PASS' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', default='check', choices=('build', 'check', 'run'))
    parser.add_argument('--expected-source')
    parser.add_argument('--allow-disposable-vm-tests', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    # This refusal precedes all source, tool, and manifest inspection.
    if args.mode == 'run' and not args.allow_disposable_vm_tests:
        print('explicit --allow-disposable-vm-tests is required; disposable Linux VMs only', file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    try:
        if args.mode == 'build':
            build(root)
        elif args.mode == 'check':
            manifest = check(root, args.expected_source)
            print(f"CHECK_READY source={manifest['source_sha']} real-storage-integration=not-run")
        else:
            if sys.platform != 'linux' or os.geteuid() != 0:
                raise PreprodError('run requires root in a disposable Linux VM')
            output = args.output
            if output is None:
                output = root / 'target/preprod' / ('results-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + os.urandom(4).hex())
            return run(root, args.expected_source, output.absolute())
        return 0
    except (OSError, ValueError, PreprodError, subprocess.SubprocessError) as error:
        print(f'PREPROD_FAILED: {error}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Disposable Linux-only controller lifecycle contract; never run on a host cgroup.

Usage: sudo python3 test-controller-lifecycle.py MANAGER OBSERVER /sys/fs/cgroup/DISPOSABLE
MANAGER diagnostic mode must report one line:
  ACTIVE OBSERVER_PID WORKER_PID SETSID_DESCENDANT_PID LAUNCHER_PID CGROUP_PATH
only after authenticated pidfd registration and GO. The supplied parent must be
an empty, isolated delegated test cgroup. No block devices are touched.
"""
import os
import pathlib
import select
import signal
import subprocess
import sys
import tempfile
import time
import uuid

TIMEOUT = 10


def line(pipe):
    data = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if not select.select([pipe], [], [], deadline - time.monotonic())[0]:
            break
        byte = os.read(pipe.fileno(), 1)
        if not byte:
            raise AssertionError('controller exited before ACTIVE')
        if byte == b'\n':
            return data.decode('ascii')
        data.extend(byte)
        if len(data) > 4096:
            break
    raise AssertionError('controller did not report bounded ACTIVE')


def empty(group):
    values = dict(item.split() for item in (group / 'cgroup.events').read_text().splitlines())
    assert values.get('populated') in ('0', '1'), 'bad cgroup.events'
    return values['populated'] == '0'


def wait_empty(group):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if empty(group):
            return
        time.sleep(.01)
    raise AssertionError('worker cgroup remains populated')


def wait_dead(fd, label):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    assert poller.poll(TIMEOUT * 1000), label + ' remained alive'


def run_case(manager, observer, root, case):
    child = None
    group = None
    fds = []
    # The entire case is disposable, including any subgroup created before
    # the manager can report ACTIVE. Cleanup owns this known parent.
    case_root = root / ('lsm-controller-case-' + uuid.uuid4().hex)
    case_root.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='lsm-controller-test-') as temp:
        backup = pathlib.Path(temp) / 'backup'
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.write(fd, b'disposable backup evidence')
        os.close(fd)
        try:
            environment = os.environ.copy()
            if case in ('observer-before-go', 'observer-stopped-before-go'):
                environment['LSM_TEST_PAUSE_BEFORE_GO'] = '1'
            if case == 'launcher-poll-failure':
                environment['LSM_TEST_POST_GO_POLL_FAULT'] = '1'
            if case == 'launcher-failure-before-active':
                environment['LSM_TEST_FAIL_WITH_STOPPED_LAUNCHER'] = '1'
            if case == 'launcher-pidfd-failure':
                environment['LSM_TEST_LAUNCHER_PIDFD_FAIL'] = '1'
            if case == 'launcher-stopped-after-go':
                environment['LSM_TEST_PAUSE_AFTER_GO'] = '1'
            if case == 'launcher-no-numeric-manager-pidfd':
                environment['LSM_TEST_DENY_MANAGER_PIDFD_OPEN'] = '1'
            if case == 'manager-death-before-launcher-pin':
                environment['LSM_TEST_STOP_BEFORE_MANAGER_PIDFD'] = '1'
            if case == 'spoof-worker-same-cgroup':
                environment['LSM_TEST_SPOOF_SAME_GROUP_PIDFD'] = '1'
            def attach_case():
                # The diagnostic manager, observer and launcher inherit this
                # disposable parent even if setup fails before reporting PIDs.
                fd = os.open(case_root / 'cgroup.procs', os.O_WRONLY | os.O_CLOEXEC)
                os.write(fd, str(os.getpid()).encode('ascii'))
                os.close(fd)
                if case == 'manager-auto-reap':
                    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

            child = subprocess.Popen([manager, '--diagnostic-manager', str(case_root), observer, str(backup)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0, env=environment,
                                     preexec_fn=attach_case)
            if case == 'manager-auto-reap':
                assert child.wait(timeout=3) != 0, 'manager accepted auto-reaping SIGCHLD'
                assert b'unsafe SIGCHLD' in child.stderr.read(), 'SIGCHLD invariant was not explicitly rejected'
                assert not any(entry.is_dir() for entry in case_root.iterdir()), 'manager created a subgroup before rejecting SIGCHLD'
                print('PASS:', case, flush=True)
                return
            parts = line(child.stdout).split()
            if case == 'spoof-worker-same-cgroup':
                assert len(parts) == 3 and parts[0] == 'SPOOF-GATE', ('expected spoof pre-GO barrier', parts)
                alternate_pid = int(parts[1])
                group = pathlib.Path(parts[2])
                assert group.parent == case_root and group.name.startswith('lsm-backup-')
                fds.append(os.pidfd_open(alternate_pid))
                members = (group / 'cgroup.procs').read_text().split()
                assert str(alternate_pid) in members and len(members) >= 2, 'alternate and worker were not both in cgroup'
                assert not backup.with_suffix('.worker').exists(), 'payload ran before pre-GO barrier'
                child.stdin.write(b'C')
                child.stdin.flush()
                child.wait(timeout=TIMEOUT)
                wait_empty(group)
                poller = select.poll()
                poller.register(fds[0], select.POLLIN)
                assert not poller.poll(0), 'alternate process did not remain alive'
                assert not backup.with_suffix('.worker').exists(), 'spoofed worker pidfd allowed payload to run'
                print('PASS:', case, flush=True)
                return
            if case == 'manager-death-before-launcher-pin':
                assert len(parts) == 3 and parts[0] == 'PIN-BARRIER', ('expected manager pin barrier', parts)
                launcher_pid = int(parts[1])
                group = pathlib.Path(parts[2])
                assert group.parent == case_root and group.name.startswith('lsm-backup-')
                fds.append(os.pidfd_open(launcher_pid))
                child.kill()
                child.wait(timeout=TIMEOUT)
                signal.pidfd_send_signal(fds[0], signal.SIGCONT)
                wait_dead(fds[0], 'launcher after manager died before pin')
                wait_empty(group)
                assert not backup.with_suffix('.worker').exists(), 'payload ran after manager death'
                print('PASS:', case, flush=True)
                return
            if case == 'launcher-pidfd-failure':
                assert len(parts) == 3 and parts[0] == 'UNPINNED', ('expected pidfd fault barrier', parts)
                launcher_pid = int(parts[1])
                group = pathlib.Path(parts[2])
                assert group.parent == case_root and group.name.startswith('lsm-backup-')
                fds.append(os.pidfd_open(launcher_pid))
                signal.pidfd_send_signal(fds[0], signal.SIGSTOP)
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    if '\nState:\tT' in (pathlib.Path('/proc') / str(launcher_pid) / 'status').read_text():
                        break
                    time.sleep(.01)
                else:
                    raise AssertionError('launcher did not stop for injected pidfd failure')
                child.stdin.write(b'C')
                child.stdin.flush()
                assert child.wait(timeout=5) != 0, 'pidfd failure was reported as success'
                poller = select.poll()
                poller.register(fds[0], select.POLLIN)
                assert not poller.poll(300), 'unprotected numeric PID fallback killed launcher'
                print('PASS:', case, flush=True)
                return
            if case == 'launcher-stopped-after-go':
                assert len(parts) == 6 and parts[0] == 'POSTGO', ('expected post-GO barrier', parts)
                observer_pid, worker_pid, descendant_pid, launcher_pid = map(int, parts[1:5])
                group = pathlib.Path(parts[5])
                assert group.parent == case_root and group.name.startswith('lsm-backup-')
                fds.extend(os.pidfd_open(pid) for pid in (observer_pid, worker_pid, descendant_pid, launcher_pid))
                signal.pidfd_send_signal(fds[3], signal.SIGSTOP)
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    if '\nState:\tT' in (pathlib.Path('/proc') / str(launcher_pid) / 'status').read_text():
                        break
                    time.sleep(.01)
                else:
                    raise AssertionError('launcher did not stop at post-GO barrier')
                child.stdin.write(b'C')
                child.stdin.flush()
                child.wait(timeout=5)
                assert b'ACTIVE ' not in child.stdout.read(), 'manager reported ACTIVE after launcher stopped'
                wait_dead(fds[3], 'post-GO stopped launcher')
                wait_dead(fds[1], 'post-GO worker')
                wait_dead(fds[2], 'post-GO setsid descendant')
                wait_empty(group)
                print('PASS:', case, flush=True)
                return
            if case == 'launcher-failure-before-active':
                assert len(parts) == 3 and parts[0] == 'LAUNCHER', ('expected launcher barrier', parts)
                launcher_pid = int(parts[1])
                group = pathlib.Path(parts[2])
                assert group.is_absolute() and group.parent == case_root and group.name.startswith('lsm-backup-')
                fds.append(os.pidfd_open(launcher_pid))
                child.stdin.write(b'C')
                child.stdin.flush()
                child.wait(timeout=TIMEOUT)
                wait_dead(fds[0], 'stopped launcher before ACTIVE')
                wait_empty(case_root)
                print('PASS:', case, flush=True)
                return
            if case in ('observer-before-go', 'observer-stopped-before-go'):
                assert len(parts) == 5 and parts[0] == 'GATE', ('expected pre-GO barrier', parts)
                observer_pid, worker_pid, launcher_pid = map(int, parts[1:4])
                group = pathlib.Path(parts[4])
                assert group.is_absolute() and group.parent == case_root and group.name.startswith('lsm-backup-')
                fds.extend((os.pidfd_open(observer_pid), os.pidfd_open(worker_pid), os.pidfd_open(launcher_pid)))
                assert not empty(group), 'pre-GO worker not in cgroup'
                assert not backup.with_suffix('.worker').exists(), 'payload ran before GO'
                if case == 'observer-stopped-before-go':
                    signal.pidfd_send_signal(fds[0], signal.SIGSTOP)
                    deadline = time.monotonic() + 1
                    while time.monotonic() < deadline:
                        if '\nState:\tT' in (pathlib.Path('/proc') / str(observer_pid) / 'status').read_text():
                            break
                        time.sleep(.01)
                    else:
                        raise AssertionError('observer did not stop before GO')
                else:
                    signal.pidfd_send_signal(fds[0], signal.SIGKILL)
                    wait_dead(fds[0], 'observer')
                child.stdin.write(b'C')
                child.stdin.flush()
                wait_dead(fds[1], 'pre-GO worker')
                wait_empty(group)
                assert not backup.with_suffix('.worker').exists(), 'payload ran after observer death'
                print('PASS:', case, flush=True)
                return
            assert len(parts) == 6 and parts[0] == 'ACTIVE', ('unexpected controller status', parts)
            observer_pid, worker_pid, descendant_pid, launcher_pid = map(int, parts[1:5])
            group = pathlib.Path(parts[5])
            assert group.is_absolute() and group.parent == case_root and group.name.startswith('lsm-backup-'), 'unexpected cgroup'
            for pid in (observer_pid, worker_pid, descendant_pid, launcher_pid):
                assert pid > 1
                fds.append(os.pidfd_open(pid))
            assert not empty(group), 'no live worker in controller cgroup'
            assert os.getsid(descendant_pid) == descendant_pid, 'descendant did not create a session'
            members = set((group / 'cgroup.procs').read_text().split())
            assert {str(worker_pid), str(descendant_pid)} <= members, 'worker or descendant outside group'
            if case == 'launcher-stopped':
                signal.pidfd_send_signal(fds[3], signal.SIGSTOP)
                wait_dead(fds[3], 'stopped launcher')
            elif case == 'launcher-poll-failure':
                # Stop manager to distinguish launcher cleanup from the
                # manager's reaction; finish before observer's 2 s deadline.
                os.kill(child.pid, signal.SIGSTOP)
                backup.with_suffix('.fault').write_text('inject')
                poller = select.poll()
                poller.register(fds[1], select.POLLIN)
                assert poller.poll(900), 'launcher did not stop worker after injected poll failure'
                poller = select.poll()
                poller.register(fds[2], select.POLLIN)
                assert poller.poll(100), 'launcher did not stop setsid descendant'
                assert empty(group), 'launcher cleanup did not empty the group'
                os.kill(child.pid, signal.SIGCONT)
            elif case == 'manager-stopped':
                os.kill(child.pid, signal.SIGSTOP)
                # Manager pidfd stays live; launcher must detect missed pings.
                wait_dead(fds[3], 'launcher after manager stopped')
            elif case == 'launcher-no-numeric-manager-pidfd':
                child.kill()
                child.wait(timeout=TIMEOUT)
            elif case == 'normal-flow':
                marker = backup.with_suffix('.worker').read_text().split()
                assert marker == [str(worker_pid), str(descendant_pid)], 'normal worker marker mismatch'
                for process_fd in fds[1:]:
                    poller = select.poll()
                    poller.register(process_fd, select.POLLIN)
                    assert not poller.poll(0), 'normal process unexpectedly exited'
                child.kill()
                child.wait(timeout=TIMEOUT)
            elif case == 'manager-death':
                child.kill()
                child.wait(timeout=TIMEOUT)
            elif case == 'observer-stopped':
                signal.pidfd_send_signal(fds[0], signal.SIGSTOP)
            elif case == 'observer-death':
                signal.pidfd_send_signal(fds[0], signal.SIGKILL)
            elif case == 'lease-break':
                # A nonblocking open requests a lease break without waiting for
                # release; EWOULDBLOCK is expected while the observer owns it.
                try:
                    writer = os.open(backup, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                except BlockingIOError:
                    pass
                else:
                    os.close(writer)
                    raise AssertionError('write open succeeded while read lease should be held')
            else:
                raise AssertionError('unknown case')
            wait_dead(fds[1], 'worker')
            wait_dead(fds[2], 'setsid descendant')
            wait_empty(group)
            print('PASS:', case, flush=True)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=TIMEOUT)
            # The launcher lives outside the worker cgroup. Kill the exact
            # pidfd even when the controller failed before ACTIVE.
            launcher_index = 0 if case in ('launcher-failure-before-active', 'launcher-pidfd-failure', 'manager-death-before-launcher-pin') else (2 if case in ('observer-before-go', 'observer-stopped-before-go') else 3)
            if len(fds) > launcher_index:
                try:
                    signal.pidfd_send_signal(fds[launcher_index], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            # The known case parent is killed even if no group path was
            # reported. Never delete entries outside this unique namespace.
            if not empty(case_root):
                (case_root / 'cgroup.kill').write_text('1')
                wait_empty(case_root)
            for subgroup in case_root.iterdir():
                if subgroup.is_dir():
                    assert subgroup.name.startswith('lsm-backup-'), 'unexpected case subgroup'
                    subgroup.rmdir()
            case_root.rmdir()
            for fd in fds:
                os.close(fd)


def main():
    if len(sys.argv) not in (4, 5) or os.geteuid() != 0:
        raise SystemExit(__doc__)
    manager, observer = (str(pathlib.Path(item).resolve(strict=True)) for item in sys.argv[1:3])
    root = pathlib.Path(sys.argv[3]).resolve(strict=True)
    assert root != pathlib.Path('/sys/fs/cgroup') and root.is_relative_to('/sys/fs/cgroup')
    assert os.environ.get('LSM_TEST_DISPOSABLE_CGROUP') == str(root), 'explicit disposable cgroup required'
    cases = ('manager-death', 'observer-death', 'lease-break', 'observer-before-go', 'launcher-poll-failure', 'launcher-stopped', 'launcher-failure-before-active', 'manager-stopped', 'launcher-pidfd-failure', 'manager-auto-reap', 'launcher-stopped-after-go', 'launcher-no-numeric-manager-pidfd', 'manager-death-before-launcher-pin', 'observer-stopped', 'observer-stopped-before-go', 'spoof-worker-same-cgroup', 'normal-flow')
    if len(sys.argv) == 5:
        assert sys.argv[4] in cases
        cases = (sys.argv[4],)
    for case in cases:
        run_case(manager, observer, root, case)


if __name__ == '__main__':
    main()

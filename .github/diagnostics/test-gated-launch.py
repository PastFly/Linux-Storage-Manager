#!/usr/bin/env python3
"""Disposable-only Linux POC. Requires the built gated launcher and a delegated cgroup parent.

Usage: python3 test-gated-launch.py /path/to/launcher /sys/fs/cgroup/DISPOSABLE
Creates and removes randomly named child cgroups. No block devices are opened.
"""
import os
import pathlib
import select
import signal
import subprocess
import sys
import time
import uuid

TIMEOUT = 10


def read_line(fd):
    result = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
        if not readable:
            break
        char = os.read(fd, 1)
        if not char:
            raise AssertionError('launcher output closed before expected marker')
        if char == b'\n':
            return result.decode('ascii')
        result.extend(char)
        if len(result) > 256:
            raise AssertionError('oversized launcher marker')
    raise AssertionError('timed out waiting for launcher marker')


def wait_pidfd(fd, label):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    if not poller.poll(TIMEOUT * 1000):
        raise AssertionError(label + ' still alive')


def populated(group):
    data = (group / 'cgroup.events').read_text(encoding='ascii')
    values = dict(line.split() for line in data.splitlines())
    if values.get('populated') not in ('0', '1'):
        raise AssertionError('invalid cgroup.events')
    return values['populated'] == '1'


def wait_empty(group):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if not populated(group):
            return
        time.sleep(0.01)
    raise AssertionError('cgroup still populated')


def kill_group(group):
    # This is a freshly created random child, never the supplied parent.
    (group / 'cgroup.kill').write_text('1', encoding='ascii')
    wait_empty(group)


def run_case(executable, parent, case):
    group = parent / ('lsm-gated-proof-' + uuid.uuid4().hex)
    group.mkdir(mode=0o700)
    launcher = None
    worker_fd = None
    grandchild_fd = None
    try:
        launcher = subprocess.Popen([executable, str(group), case], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        tag, pid_text = read_line(launcher.stdout.fileno()).split()
        assert tag == 'FORKED', tag
        worker_pid = int(pid_text)
        worker_fd = os.pidfd_open(worker_pid)
        if case == 'before-pdeath':
            # Never stop an outside-cgroup child until cleanup owns its pidfd.
            launcher.stdin.write(b'S')
            launcher.stdin.flush()
        tag, confirmed_pid = read_line(launcher.stdout.fileno()).split()
        expected = 'STOPPED' if case == 'before-pdeath' else 'READY'
        assert tag == expected and int(confirmed_pid) == worker_pid, (tag, expected, confirmed_pid)
        fd_dir = pathlib.Path('/proc') / str(worker_pid) / 'fd'
        fd_targets = [os.readlink(fd) for fd in fd_dir.iterdir()]
        # stdout, stderr, sealed executable, GO, READY, launcher pidfd.
        assert len(fd_targets) == 6, ('unexpected pre-exec descriptors', fd_targets)
        assert 'anon_inode:[pidfd]' in fd_targets
        assert not any(str(group) in target for target in fd_targets), fd_targets
        if case == 'before-pdeath':
            assert not populated(group), 'pre-prctl child unexpectedly moved into cgroup'
            launcher.kill()
            launcher.wait(timeout=TIMEOUT)
            # The child is still stopped before prctl. Continue the exact pidfd,
            # then prove death via poll; EOF alone is not counted as termination.
            signal.pidfd_send_signal(worker_fd, signal.SIGCONT)
            wait_pidfd(worker_fd, 'child before prctl')
            kill_group(group)
        elif case == 'before-go':
            assert populated(group), 'child not in cgroup before GO'
            launcher.kill()
            launcher.wait(timeout=TIMEOUT)
            wait_pidfd(worker_fd, 'child before GO')
            kill_group(group)
        elif case == 'after-go':
            assert populated(group), 'child not in cgroup before GO'
            launcher.stdin.write(b'G')
            launcher.stdin.flush()
            tag, pid_text = read_line(launcher.stdout.fileno()).split()
            assert tag == 'RUNNING', tag
            grandchild_fd = os.pidfd_open(int(pid_text))
            launcher.kill()
            launcher.wait(timeout=TIMEOUT)
            # Parent-death signal kills the direct worker, not its setsid child.
            wait_pidfd(worker_fd, 'direct worker after launcher death')
            assert populated(group), 'expected independently surviving setsid descendant'
            kill_group(group)
            wait_pidfd(grandchild_fd, 'setsid descendant after cgroup.kill')
        else:
            raise AssertionError('unknown test case')
        print('PASS:', case)
    finally:
        if launcher is not None and launcher.poll() is None:
            launcher.kill()
            launcher.wait(timeout=TIMEOUT)
        # If a test failed, kill only our newly-created isolated group.
        if populated(group):
            kill_group(group)
        if worker_fd is not None:
            # The pre-placement child may be outside group. Always kill/continue
            # and verify that exact pidfd even if a test failed.
            try:
                signal.pidfd_send_signal(worker_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            wait_pidfd(worker_fd, 'worker during cleanup')
            os.close(worker_fd)
        if grandchild_fd is not None:
            try:
                signal.pidfd_send_signal(grandchild_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            wait_pidfd(grandchild_fd, 'grandchild during cleanup')
            os.close(grandchild_fd)
        group.rmdir()


def main():
    if sys.platform != 'linux' or len(sys.argv) != 3:
        raise SystemExit(__doc__)
    if os.geteuid() != 0:
        raise SystemExit('test requires root in a disposable Linux runner')
    exe = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
    parent = pathlib.Path(sys.argv[2]).resolve(strict=True)
    if not parent.is_dir() or not (parent / 'cgroup.controllers').exists():
        raise SystemExit('argument is not an existing cgroup v2 parent')
    for case in ('before-pdeath', 'before-go', 'after-go'):
        run_case(exe, parent, case)


if __name__ == '__main__':
    main()

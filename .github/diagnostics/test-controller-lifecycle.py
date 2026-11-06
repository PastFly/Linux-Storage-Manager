#!/usr/bin/env python3
"""Disposable Linux-only controller lifecycle contract; never run on a host cgroup.

Usage: sudo python3 test-controller-lifecycle.py MANAGER OBSERVER /sys/fs/cgroup/DISPOSABLE
MANAGER diagnostic mode must report one line:
  ACTIVE OBSERVER_PID WORKER_PID SETSID_DESCENDANT_PID CGROUP_PATH
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
    with tempfile.TemporaryDirectory(prefix='lsm-controller-test-') as temp:
        backup = pathlib.Path(temp) / 'backup'
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.write(fd, b'disposable backup evidence')
        os.close(fd)
        try:
            child = subprocess.Popen([manager, '--diagnostic-manager', str(root), observer, str(backup)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0)
            parts = line(child.stdout).split()
            assert len(parts) == 5 and parts[0] == 'ACTIVE', ('unexpected controller status', parts)
            observer_pid, worker_pid, descendant_pid = map(int, parts[1:4])
            group = pathlib.Path(parts[4])
            assert group.is_absolute() and group.parent == root and group.name.startswith('lsm-backup-'), 'unexpected cgroup'
            for pid in (observer_pid, worker_pid, descendant_pid):
                assert pid > 1
                fds.append(os.pidfd_open(pid))
            assert not empty(group), 'no live worker in controller cgroup'
            assert os.getsid(descendant_pid) == descendant_pid, 'descendant did not create a session'
            members = set((group / 'cgroup.procs').read_text().split())
            assert {str(worker_pid), str(descendant_pid)} <= members, 'worker or descendant outside group'
            if case == 'manager-death':
                child.kill()
                child.wait(timeout=TIMEOUT)
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
            if group is not None and group.parent == root and group.name.startswith('lsm-backup-'):
                if not empty(group):
                    (group / 'cgroup.kill').write_text('1')
                    wait_empty(group)
                group.rmdir()
            for fd in fds:
                os.close(fd)


def main():
    if len(sys.argv) not in (4, 5) or os.geteuid() != 0:
        raise SystemExit(__doc__)
    manager, observer = (str(pathlib.Path(item).resolve(strict=True)) for item in sys.argv[1:3])
    root = pathlib.Path(sys.argv[3]).resolve(strict=True)
    assert root != pathlib.Path('/sys/fs/cgroup') and root.is_relative_to('/sys/fs/cgroup')
    assert os.environ.get('LSM_TEST_DISPOSABLE_CGROUP') == str(root), 'explicit disposable cgroup required'
    cases = ('manager-death', 'observer-death', 'lease-break')
    if len(sys.argv) == 5:
        assert sys.argv[4] in cases
        cases = (sys.argv[4],)
    for case in cases:
        run_case(manager, observer, root, case)


if __name__ == '__main__':
    main()

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
            if case == 'observer-before-go':
                environment['LSM_TEST_PAUSE_BEFORE_GO'] = '1'
            if case == 'launcher-poll-failure':
                environment['LSM_TEST_POST_GO_POLL_FAULT'] = '1'
            child = subprocess.Popen([manager, '--diagnostic-manager', str(case_root), observer, str(backup)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0, env=environment)
            parts = line(child.stdout).split()
            if case == 'observer-before-go':
                assert len(parts) == 4 and parts[0] == 'GATE', ('expected pre-GO barrier', parts)
                observer_pid, worker_pid = map(int, parts[1:3])
                group = pathlib.Path(parts[3])
                assert group.is_absolute() and group.parent == case_root and group.name.startswith('lsm-backup-')
                fds.extend((os.pidfd_open(observer_pid), os.pidfd_open(worker_pid)))
                assert not empty(group), 'pre-GO worker not in cgroup'
                assert not backup.with_suffix('.worker').exists(), 'payload ran before GO'
                signal.pidfd_send_signal(fds[0], signal.SIGKILL)
                wait_dead(fds[0], 'observer')
                child.stdin.write(b'C')
                child.stdin.flush()
                wait_dead(fds[1], 'pre-GO worker')
                wait_empty(group)
                assert not backup.with_suffix('.worker').exists(), 'payload ran after observer death'
                print('PASS:', case, flush=True)
                return
            assert len(parts) == 5 and parts[0] == 'ACTIVE', ('unexpected controller status', parts)
            observer_pid, worker_pid, descendant_pid = map(int, parts[1:4])
            group = pathlib.Path(parts[4])
            assert group.is_absolute() and group.parent == case_root and group.name.startswith('lsm-backup-'), 'unexpected cgroup'
            for pid in (observer_pid, worker_pid, descendant_pid):
                assert pid > 1
                fds.append(os.pidfd_open(pid))
            assert not empty(group), 'no live worker in controller cgroup'
            assert os.getsid(descendant_pid) == descendant_pid, 'descendant did not create a session'
            members = set((group / 'cgroup.procs').read_text().split())
            assert {str(worker_pid), str(descendant_pid)} <= members, 'worker or descendant outside group'
            if case == 'launcher-poll-failure':
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
            elif case == 'manager-death':
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
    cases = ('manager-death', 'observer-death', 'lease-break', 'observer-before-go', 'launcher-poll-failure')
    if len(sys.argv) == 5:
        assert sys.argv[4] in cases
        cases = (sys.argv[4],)
    for case in cases:
        run_case(manager, observer, root, case)


if __name__ == '__main__':
    main()

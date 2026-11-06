#!/usr/bin/env python3
"""Disposable Linux-only lifecycle API tests; never point at a host cgroup.

Run as root: test-process-lifecycle.py RUNNER /sys/fs/cgroup/DISPOSABLE CASE
The manager reports PREPARED GUARD_PID WORKER_PID CGROUP then waits for G.
After GO, it reports RUNNING SETSID_DESCENDANT_PID. Each case owns a unique
parent cgroup containing the manager, guard, launcher, and worker subgroup.
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


def read_line(pipe):
    data = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        ready, _, _ = select.select([pipe], [], [], deadline - time.monotonic())
        if not ready:
            break
        value = os.read(pipe.fileno(), 1)
        if not value:
            raise AssertionError('lifecycle manager exited before expected state')
        if value == b'\n':
            return data.decode('ascii')
        data.extend(value)
        if len(data) > 4096:
            break
    raise AssertionError('lifecycle manager did not report bounded state')


def empty(group):
    data = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())
    assert data.get('populated') in ('0', '1'), 'invalid cgroup.events'
    return data['populated'] == '0'


def wait_empty(group):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if empty(group):
            return
        time.sleep(.01)
    raise AssertionError('lifecycle cgroup remains populated')


def wait_dead(fd, label):
    p = select.poll()
    p.register(fd, select.POLLIN)
    assert p.poll(TIMEOUT * 1000), label + ' remained alive'


def run_case(executable, parent, case):
    root = parent / ('lsm-lifecycle-case-' + uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    child = None
    fds = []
    try:
        def attach_case():
            fd = os.open(root / 'cgroup.procs', os.O_WRONLY | os.O_CLOEXEC)
            os.write(fd, str(os.getpid()).encode('ascii'))
            os.close(fd)

        child = subprocess.Popen([executable, '--manager', str(root)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                 preexec_fn=attach_case)
        parts = read_line(child.stdout).split()
        assert len(parts) == 4 and parts[0] == 'PREPARED', ('unexpected prepare state', parts)
        guard_pid, worker_pid = map(int, parts[1:3])
        group = pathlib.Path(parts[3])
        assert group.parent == root and group.name.startswith('lsm-lifecycle-')
        fds.extend((os.pidfd_open(guard_pid), os.pidfd_open(worker_pid)))
        assert str(worker_pid) in (group / 'cgroup.procs').read_text().split()
        assert not empty(group), 'worker not in dedicated cgroup before GO'
        if case == 'manager-before-go':
            child.kill()
            child.wait(timeout=TIMEOUT)
        else:
            child.stdin.write(b'G')
            child.stdin.flush()
            running = read_line(child.stdout).split()
            assert len(running) == 2 and running[0] == 'RUNNING'
            descendant = int(running[1])
            fds.append(os.pidfd_open(descendant))
            assert os.getsid(descendant) == descendant, 'descendant did not call setsid'
            assert {str(worker_pid), str(descendant)} <= set((group / 'cgroup.procs').read_text().split())
            if case == 'manager-after-go':
                child.kill()
                child.wait(timeout=TIMEOUT)
            elif case == 'guard-after-go':
                signal.pidfd_send_signal(fds[0], signal.SIGKILL)
            else:
                raise AssertionError('unknown lifecycle case')
        wait_dead(fds[1], 'worker')
        if len(fds) > 2:
            wait_dead(fds[2], 'setsid descendant')
        wait_empty(group)
        print('PASS:', case, flush=True)
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=TIMEOUT)
        if not empty(root):
            (root / 'cgroup.kill').write_text('1')
            wait_empty(root)
        for item in root.iterdir():
            if item.is_dir():
                assert item.name.startswith('lsm-lifecycle-'), 'unexpected subgroup'
                item.rmdir()
        root.rmdir()
        for fd in fds:
            os.close(fd)


def main():
    if len(sys.argv) != 4 or os.geteuid() != 0:
        raise SystemExit(__doc__)
    executable = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
    parent = pathlib.Path(sys.argv[2]).resolve(strict=True)
    assert parent != pathlib.Path('/sys/fs/cgroup') and parent.is_relative_to('/sys/fs/cgroup')
    assert os.environ.get('LSM_TEST_DISPOSABLE_CGROUP') == str(parent)
    assert sys.argv[3] in ('manager-before-go', 'manager-after-go', 'guard-after-go')
    run_case(executable, parent, sys.argv[3])


if __name__ == '__main__':
    main()

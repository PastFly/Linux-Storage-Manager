#!/usr/bin/env python3
"""Destructive only to a new temporary cgroup and temporary regular files.
Usage: python3 test_observer.py OBSERVER DELEGATED_CGROUP_PARENT
Requires Linux, cgroup v2 delegation, pidfd_open, and file leases.
"""
import array
import fcntl
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def wait_for(predicate, label, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError(f'timed out waiting for {label}')


def populated(group):
    with open(os.path.join(group, 'cgroup.events'), encoding='ascii') as f:
        return dict(line.split() for line in f)['populated']


def main():
    if sys.platform != 'linux' or len(sys.argv) != 3:
        raise SystemExit(__doc__)
    executable, parent_group = map(os.path.abspath, sys.argv[1:])
    if not os.path.isfile(executable):
        raise AssertionError('observer executable missing')
    group = os.path.join(parent_group, 'lsm-observer-test-' + str(os.getpid()))
    os.mkdir(group)
    manager_pid = None
    with tempfile.TemporaryDirectory(prefix='lsm-observer-test-') as tmp:
        marker = os.path.join(tmp, 'should-not-exist')
        backup = os.path.join(tmp, 'backup')
        with open(backup, 'wb') as f:
            f.write(b'disposable backup')
        pipe_read, pipe_write = os.pipe()
        try:
            manager_pid = os.fork()
            if manager_pid == 0:
                os.close(pipe_read)
                try:
                    manager_sock, observer_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    observer = subprocess.Popen([executable, str(observer_sock.fileno())],
                                                pass_fds=(observer_sock.fileno(),),
                                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
                    observer_sock.close()
                    pidfd = os.pidfd_open(os.getpid())
                    cgroup_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
                    backup_fd = os.open(backup, os.O_RDONLY)
                    fcntl.fcntl(backup_fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
                    fds = array.array('i', [pidfd, cgroup_fd, backup_fd])
                    manager_sock.sendmsg([struct.pack('=I', 1)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
                    if manager_sock.recv(1) != b'R':
                        raise RuntimeError('observer did not acknowledge readiness')
                    started_r, started_w = os.pipe()
                    worker = os.fork()
                    if worker == 0:
                        os.close(started_r)
                        with open(os.path.join(group, 'cgroup.procs'), 'w', encoding='ascii') as f:
                            f.write(str(os.getpid()))
                        grandchild = os.fork()
                        if grandchild == 0:
                            os.setsid()
                            os.write(started_w, b'X')
                            os.close(started_w)
                            time.sleep(3)
                            with open(marker, 'w', encoding='ascii') as f:
                                f.write('orphan survived')
                            os._exit(0)
                        os.close(started_w)
                        while True:
                            signal.pause()
                    os.close(started_w)
                    if os.read(started_r, 1) != b'X':
                        raise RuntimeError('worker failed to start')
                    os.close(started_r)
                    os.write(pipe_write, json.dumps({'observer': observer.pid, 'worker': worker}).encode() + b'\n')
                    while True:
                        signal.pause()
                except BaseException as e:
                    os.write(pipe_write, ('ERROR: ' + repr(e) + '\n').encode())
                    os._exit(1)
            os.close(pipe_write)
            with os.fdopen(pipe_read, 'rb', closefd=True) as report:
                line = report.readline().decode()
            if line.startswith('ERROR') or not line:
                raise AssertionError('manager failed: ' + line)
            info = json.loads(line)
            assert populated(group) == '1'
            fd_dir = '/proc/' + str(info['observer']) + '/fd'
            fd_targets = [os.readlink(os.path.join(fd_dir, fd)) for fd in os.listdir(fd_dir)]
            assert len(fd_targets) == 6, f'unexpected observer descriptors: {fd_targets!r}'
            assert 'anon_inode:[pidfd]' in fd_targets
            assert backup in fd_targets
            assert os.path.join(group, 'cgroup.kill') in fd_targets
            assert os.path.join(group, 'cgroup.events') in fd_targets
            os.kill(manager_pid, signal.SIGKILL)
            os.waitpid(manager_pid, 0)
            manager_pid = None
            wait_for(lambda: populated(group) == '0', 'empty cgroup')
            time.sleep(3.5)
            assert not os.path.exists(marker), 'setsid grandchild outlived manager'
            def observer_gone():
                try:
                    with open('/proc/' + str(info['observer']) + '/stat', encoding='ascii') as f:
                        return f.read().split()[2] == 'Z'
                except FileNotFoundError:
                    return True
            wait_for(observer_gone, 'observer exit')
            print('PASS: manager death killed worker and setsid descendant; cgroup empty')
        finally:
            if manager_pid is not None:
                try:
                    os.kill(manager_pid, signal.SIGKILL)
                    os.waitpid(manager_pid, 0)
                except ProcessLookupError:
                    pass
            if populated(group) == '1':
                with open(os.path.join(group, 'cgroup.kill'), 'w', encoding='ascii') as f:
                    f.write('1')
                wait_for(lambda: populated(group) == '0', 'cleanup')
            os.rmdir(group)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Disposable Linux test: python3 test_observer.py OBSERVER DELEGATED_CGROUP_PARENT.
Creates and destroys new cgroups and temporary regular files; no block devices.
Requires cgroup v2, pidfd_open, close_range, signalfd and filesystem leases.
"""
import array
import errno
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def wait_for(predicate, label, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError('timed out waiting for ' + label)


def populated(group):
    with open(os.path.join(group, 'cgroup.events'), encoding='ascii') as f:
        return dict(line.split() for line in f)['populated']


def observer_gone(pid):
    try:
        with open('/proc/' + str(pid) + '/stat', encoding='ascii') as f:
            return f.read().split()[2] == 'Z'
    except FileNotFoundError:
        return True


def manager_main(executable, group, backup, marker, report_fd, prior_writer_fd, expect_refusal):
    try:
        if prior_writer_fd is not None:
            os.close(prior_writer_fd)
        manager_sock, observer_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        observer = subprocess.Popen([executable, str(observer_sock.fileno())],
                                    pass_fds=(observer_sock.fileno(),),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        observer_sock.close()
        pidfd = os.pidfd_open(os.getpid())
        group_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
        source_fd = os.open(backup, os.O_RDONLY)
        fds = array.array('i', [pidfd, group_fd, source_fd])
        manager_sock.sendmsg([struct.pack('=I', 1)], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
        # Observer must own the last leased open-file description; workers never inherit it.
        os.close(source_fd)
        manager_sock.settimeout(8)
        try:
            reply = manager_sock.recv(1)
        except ConnectionResetError:
            reply = b''
        if expect_refusal:
            if reply == b'R':
                raise AssertionError('observer returned READY with an existing writer')
            code = observer.wait(timeout=8)
            if code != 4:
                raise AssertionError('unexpected refusal exit code ' + str(code))
            os.write(report_fd, b'{"refused":true}\n')
            os._exit(0)
        if reply != b'R':
            raise AssertionError('observer failed to return READY: ' + repr(reply))
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
                    f.write('setsid descendant survived')
                os._exit(0)
            os.close(started_w)
            while True:
                signal.pause()
        os.close(started_w)
        if os.read(started_r, 1) != b'X':
            raise AssertionError('worker failed to start')
        os.close(started_r)
        os.write(report_fd, json.dumps({'observer': observer.pid, 'worker': worker}).encode() + b'\n')
        while True:
            signal.pause()
    except BaseException as error:
        os.write(report_fd, ('ERROR: ' + repr(error) + '\n').encode())
        os._exit(1)


def run_case(executable, parent_group, name):
    group = os.path.join(parent_group, 'lsm-observer-' + name + '-' + str(os.getpid()))
    os.mkdir(group)
    manager_pid = None
    prior_writer_fd = None
    with tempfile.TemporaryDirectory(prefix='lsm-observer-test-') as tmp:
        marker = os.path.join(tmp, 'should-not-exist')
        backup = os.path.join(tmp, 'backup')
        with open(backup, 'wb') as f:
            f.write(b'disposable backup')
        if name == 'prior-writer':
            prior_writer_fd = os.open(backup, os.O_WRONLY)
        report_read, report_write = os.pipe()
        try:
            manager_pid = os.fork()
            if manager_pid == 0:
                os.close(report_read)
                manager_main(executable, group, backup, marker, report_write,
                             prior_writer_fd, name == 'prior-writer')
                os._exit(1)
            os.close(report_write)
            with os.fdopen(report_read, 'rb') as report:
                line = report.readline().decode()
            if line.startswith('ERROR') or not line:
                raise AssertionError('manager failed: ' + line)
            info = json.loads(line)
            if name == 'prior-writer':
                _, status = os.waitpid(manager_pid, 0)
                manager_pid = None
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and info['refused']
                assert populated(group) == '0'
                print('PASS: preexisting writer prevented READY')
                return
            assert populated(group) == '1'
            fd_dir = '/proc/' + str(info['observer']) + '/fd'
            targets = [os.readlink(os.path.join(fd_dir, fd)) for fd in os.listdir(fd_dir)]
            assert len(targets) == 7, 'unexpected observer descriptors: ' + repr(targets)
            assert 'anon_inode:[pidfd]' in targets and 'anon_inode:[signalfd]' in targets
            assert backup in targets and os.path.join(group, 'cgroup.kill') in targets
            assert os.path.join(group, 'cgroup.events') in targets
            if name == 'manager-death':
                os.kill(manager_pid, signal.SIGKILL)
                os.waitpid(manager_pid, 0)
                manager_pid = None
            elif name == 'lease-break':
                try:
                    unexpected = os.open(backup, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as error:
                    assert error.errno in (errno.EAGAIN, errno.EWOULDBLOCK), error
                else:
                    os.close(unexpected)
                    raise AssertionError('writer opened while cgroup still populated')
                def writer_can_open():
                    try:
                        fd = os.open(backup, os.O_WRONLY | os.O_NONBLOCK)
                    except OSError as error:
                        if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            return False
                        raise
                    try:
                        assert populated(group) == '0', 'lease released before cgroup emptied'
                    finally:
                        os.close(fd)
                    return True
                wait_for(writer_can_open, 'lease released after cgroup empty')
                assert os.waitpid(manager_pid, os.WNOHANG) == (0, 0), 'SIGIO killed manager'
            wait_for(lambda: populated(group) == '0', 'empty cgroup')
            wait_for(lambda: observer_gone(info['observer']), 'observer exit')
            time.sleep(3.5)
            assert not os.path.exists(marker), 'setsid descendant outlived stop'
            print('PASS:', name, 'killed worker and setsid descendant; cgroup empty')
        finally:
            if prior_writer_fd is not None:
                os.close(prior_writer_fd)
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


def main():
    if sys.platform != 'linux' or len(sys.argv) != 3:
        raise SystemExit(__doc__)
    executable, parent_group = map(os.path.abspath, sys.argv[1:])
    if not os.path.isfile(executable):
        raise AssertionError('observer executable missing')
    for name in ('prior-writer', 'manager-death', 'lease-break'):
        run_case(executable, parent_group, name)


if __name__ == '__main__':
    main()

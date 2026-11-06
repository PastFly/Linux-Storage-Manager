#!/usr/bin/env python3
"""Disposable Linux test: python3 test_observer.py OBSERVER DELEGATED_CGROUP_PARENT.
Creates and destroys new cgroups and temporary regular files; no block devices.
Requires cgroup v2, pidfd_open, close_range, signalfd and filesystem leases.
"""
import array
import errno
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


def manager_main(executable, group, backup, second_backup, marker, report_fd, prior_writer_fd, expect_refusal, malformed_quit, retained_duplicate, path_only, source_lease):
    try:
        if prior_writer_fd is not None:
            os.close(prior_writer_fd)
        manager_sock, observer_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        observer_args = [executable]
        if os.environ.get('LSM_TEST_OBSERVER_CLI') == '1':
            observer_args.append('__lsm_backup_observer')
        observer_args.append(str(observer_sock.fileno()))
        observer = subprocess.Popen(observer_args,
                                    pass_fds=(observer_sock.fileno(),),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        observer_sock.close()
        pidfd = os.pidfd_open(os.getpid())
        group_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
        source_fd = os.open(backup, os.O_PATH if path_only else os.O_RDONLY)
        if source_lease:
            fcntl.fcntl(source_fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        retained = os.dup(source_fd) if retained_duplicate or second_backup is not None else None
        sources = [source_fd]
        if second_backup is not None:
            sources.append(os.open(second_backup, os.O_RDONLY))
        fds = array.array('i', [pidfd, group_fd, *sources])
        manager_sock.sendmsg([struct.pack('=I', len(sources))], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
        # Observer must own the last leased open-file description; workers never inherit it.
        for fd in sources:
            os.close(fd)
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
            if retained is not None:
                try:
                    writable = os.open(backup, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as error:
                    raise AssertionError('partial setup left lease on retained descriptor') from error
                os.close(writable)
                os.close(retained)
            os.write(report_fd, b'{"refused":true}\n')
            os._exit(0)
        if reply != b'R':
            raise AssertionError('observer failed to return READY: ' + repr(reply))
        if retained_duplicate:
            manager_sock.sendall(b'Q')
            if manager_sock.recv(1) != b'Q' or observer.wait(timeout=8) != 0:
                raise AssertionError('observer did not disarm empty cgroup')
            try:
                writable = os.open(backup, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                raise AssertionError('retained descriptor kept observer lease alive') from error
            os.close(writable)
            os.close(retained)
            os.write(report_fd, b'{"duplicate_safe":true}\n')
            os._exit(0)
        if malformed_quit:
            manager_sock.sendall(b'Qunexpected-trailing-data')
            try:
                reply = manager_sock.recv(1)
            except ConnectionResetError:
                reply = b''
            if reply == b'Q':
                raise AssertionError('observer accepted a truncated quit packet')
            observer.wait(timeout=8)
            os.write(report_fd, b'{"malformed_refused":true}\n')
            os._exit(0)
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
        os.chmod(backup, 0o4600 if name == 'unsafe-mode' else 0o600)
        second_backup = None
        if name == 'partial-lease':
            second_backup = os.path.join(tmp, 'second-backup')
            with open(second_backup, 'wb') as f:
                f.write(b'second disposable backup')
            os.chmod(second_backup, 0o600)
        if name in ('prior-writer', 'partial-lease'):
            prior_writer_fd = os.open(second_backup or backup, os.O_WRONLY)
        report_read, report_write = os.pipe()
        try:
            manager_pid = os.fork()
            if manager_pid == 0:
                os.close(report_read)
                manager_main(executable, group, backup, second_backup, marker, report_write,
                             prior_writer_fd, name in ('prior-writer', 'partial-lease', 'unsafe-mode', 'opath', 'source-lease'), name == 'malformed-quit',
                             name == 'retained-duplicate', name == 'opath', name == 'source-lease')
                os._exit(1)
            os.close(report_write)
            with os.fdopen(report_read, 'rb') as report:
                line = report.readline().decode()
            if line.startswith('ERROR') or not line:
                raise AssertionError('manager failed: ' + line)
            info = json.loads(line)
            if name in ('prior-writer', 'partial-lease', 'unsafe-mode', 'opath', 'source-lease'):
                _, status = os.waitpid(manager_pid, 0)
                manager_pid = None
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and info['refused']
                assert populated(group) == '0'
                if name == 'partial-lease':
                    writable = os.open(backup, os.O_WRONLY | os.O_NONBLOCK)
                    os.close(writable)
                    print('PASS: failed second lease released first lease')
                else:
                    print('PASS: preexisting writer prevented READY')
                return
            if name == 'retained-duplicate':
                _, status = os.waitpid(manager_pid, 0)
                manager_pid = None
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and info['duplicate_safe']
                print('PASS: retained descriptor does not retain lease')
                return
            if name == 'malformed-quit':
                _, status = os.waitpid(manager_pid, 0)
                manager_pid = None
                assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and info['malformed_refused']
                assert populated(group) == '0'
                print('PASS: malformed quit packet rejected')
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
    cases = ['prior-writer', 'manager-death', 'lease-break']
    if os.environ.get('LSM_TEST_OBSERVER_CLI') == '1':
        cases.extend(('malformed-quit', 'partial-lease', 'retained-duplicate', 'source-lease', 'opath', 'unsafe-mode'))
    for name in cases:
        run_case(executable, parent_group, name)


if __name__ == '__main__':
    main()

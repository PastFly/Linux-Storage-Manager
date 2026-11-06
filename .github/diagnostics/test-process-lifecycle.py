#!/usr/bin/env python3
"""Disposable Linux-only lifecycle API tests; never point at a host cgroup.

Run as root: test-process-lifecycle.py RUNNER /sys/fs/cgroup/DISPOSABLE CASE
The manager reports PREPARED GUARD_PID WORKER_PID CGROUP then waits for G.
After GO, it reports RUNNING SETSID_DESCENDANT_PID. Exact pidfds are supplied
by the manager over an authenticated SOCK_SEQPACKET socket. Each case owns a
unique parent containing the manager, guard, launcher and worker subgroup.
"""
import array
import os
import pathlib
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
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


def receive_fds(control, expected_pid, expected_tag, count):
    if not select.select([control], [], [], TIMEOUT)[0]:
        raise AssertionError('timed out waiting for pinned pidfds')
    space = socket.CMSG_SPACE(64 * array.array('i').itemsize) + socket.CMSG_SPACE(12)
    data, ancillary, flags, _ = control.recvmsg(1, space, socket.MSG_CMSG_CLOEXEC)
    received = []
    credentials = []
    rights_messages = 0
    unexpected = False
    try:
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                rights_messages += 1
                parsed = array.array('i')
                if len(payload) % parsed.itemsize:
                    unexpected = True
                parsed.frombytes(payload[:len(payload) - len(payload) % parsed.itemsize])
                received.extend(parsed)
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(payload) == 12:
                credentials.append(struct.unpack('3i', payload))
            else:
                unexpected = True
        assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        assert data == expected_tag and rights_messages == (1 if count else 0) and len(received) == count
        assert not unexpected and len(credentials) == 1
        assert credentials[0][0] == expected_pid and credentials[0][1] == 0
        for fd in received:
            assert os.readlink('/proc/self/fd/' + str(fd)) == 'anon_inode:[pidfd]'
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            assert not poller.poll(0), 'received process already exited'
        result = received
        received = []
        return result
    finally:
        for fd in received:
            os.close(fd)


def pidfd_pid(fd):
    info = pathlib.Path('/proc/self/fdinfo/' + str(fd)).read_text().splitlines()
    values = [line.split(':', 1)[1].strip() for line in info if line.startswith('Pid:')]
    assert len(values) == 1 and int(values[0]) > 0
    return int(values[0])


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


def poll_dead(fd, timeout):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    events = poller.poll(timeout)
    if not events:
        return False
    assert len(events) == 1 and events[0][0] == fd
    assert not events[0][1] & (select.POLLERR | select.POLLNVAL), 'pidfd poll failed'
    assert events[0][1] & select.POLLIN, 'pidfd returned unexpected event'
    return True


def wait_dead(fd, label):
    assert poll_dead(fd, TIMEOUT * 1000), label + ' remained alive'


def run_case(executable, parent, case):
    assert signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'test parent must reap its child'
    root = parent / ('lsm-lifecycle-case-' + uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    child = None
    fds = []
    control = None
    peer = None
    temp = tempfile.TemporaryDirectory(prefix='lsm-lifecycle-marker-')
    try:
        control, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        control.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

        def attach_case():
            fd = os.open(root / 'cgroup.procs', os.O_WRONLY | os.O_CLOEXEC)
            os.write(fd, str(os.getpid()).encode('ascii'))
            os.close(fd)

        environment = os.environ.copy()
        environment['LSM_TEST_LIFECYCLE_MARKER'] = str(pathlib.Path(temp.name) / 'marker')
        environment['LSM_TEST_LIFECYCLE_TEST_FD'] = str(peer.fileno())
        if case == 'manager-before-clone':
            environment['LSM_TEST_LIFECYCLE_STOP_BEFORE_CLONE'] = '1'
        if case == 'manager-before-registration':
            environment['LSM_TEST_LIFECYCLE_STOP_BEFORE_REGISTRATION'] = '1'
        if case == 'manager-stopped-before-launcher':
            environment['LSM_TEST_LIFECYCLE_STOP_MANAGER_AFTER_GUARD'] = '1'
        child = subprocess.Popen([executable, '--manager', str(root)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                 pass_fds=(peer.fileno(),), preexec_fn=attach_case, env=environment)
        peer.close()
        peer = None
        parts = read_line(child.stdout).split()
        if case == 'manager-stopped-before-launcher':
            assert len(parts) == 3 and parts[0] == 'MANAGER-GATE', ('unexpected manager barrier', parts)
            guard_pid = int(parts[1])
            group = pathlib.Path(parts[2])
            assert group.name == 'worker' and group.parent.parent == root and group.parent.name.startswith('lsm-lifecycle-')
            fds.extend(receive_fds(control, child.pid, b'B', 2))
            assert [pidfd_pid(fd) for fd in fds] == [child.pid, guard_pid]
            assert empty(group.parent), 'scope unexpectedly populated before launcher'
            signal.pidfd_send_signal(fds[0], signal.SIGSTOP)
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                if '\nState:\tT' in (pathlib.Path('/proc') / str(child.pid) / 'status').read_text():
                    break
                time.sleep(.005)
            else:
                raise AssertionError('manager did not stop at barrier')
            if not poll_dead(fds[1], 3500):
                # A guard that keeps holding the scope is also fail-closed.
                signal.pidfd_send_signal(fds[0], signal.SIGKILL)
                child.wait(timeout=TIMEOUT)
                wait_dead(fds[1], 'retained guard after manager death')
                wait_empty(group.parent)
                print('PASS:', case, flush=True)
                return
            if not poll_dead(fds[0], 0):
                signal.pidfd_send_signal(fds[0], signal.SIGCONT)
                child.stdin.write(b'C')
                child.stdin.flush()
                # EOF/empty scope is inconclusive: a launcher may have
                # cloned and exited before the test observed its pidfd.
                try:
                    created = read_line(child.stdout).split()
                except AssertionError as error:
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        raise AssertionError('post-timeout creator stalled before clone state') from error
                    diagnostic = child.stderr.read().decode('utf-8', errors='replace')
                    raise AssertionError('post-timeout creator exited before clone state: ' + diagnostic) from error
                if created == ['NO-CLONE']:
                    # Defined protocol: this authenticated packet is sent only
                    # before clone, and the creator immediately exits.
                    receive_fds(control, child.pid, b'N', 0)
                    child.wait(timeout=TIMEOUT)
                    wait_empty(group.parent)
                    print('PASS:', case, flush=True)
                    return
                assert len(created) == 3 and created[0] == 'CLONED', ('unexpected post-timeout state', created)
                launcher_pid = int(created[1])
                assert pathlib.Path(created[2]) == group
                fds.extend(receive_fds(control, child.pid, b'C', 1))
                assert pidfd_pid(fds[2]) == launcher_pid
                assert str(launcher_pid) in (group.parent / 'cgroup.procs').read_text().split(), 'launcher not inside scope'
                raise AssertionError('guard exited while creator was alive; resumed manager cloned launcher')
            child.wait(timeout=TIMEOUT)
            wait_empty(group.parent)
            print('PASS:', case, flush=True)
            return
        if case == 'manager-before-registration':
            assert len(parts) == 4 and parts[0] == 'REGISTER-GATE', ('unexpected registration barrier', parts)
            guard_pid, launcher_pid = map(int, parts[1:3])
            group = pathlib.Path(parts[3])
            assert group.name == 'worker' and group.parent.parent == root and group.parent.name.startswith('lsm-lifecycle-')
            fds.extend(receive_fds(control, child.pid, b'U', 3))
            assert [pidfd_pid(fd) for fd in fds] == [child.pid, guard_pid, launcher_pid]
            assert str(launcher_pid) in (group.parent / 'cgroup.procs').read_text().split(), 'launcher outside guarded scope'
            assert empty(group), 'worker cgroup was populated before registration'
            signal.pidfd_send_signal(fds[0], signal.SIGKILL)
            child.wait(timeout=TIMEOUT)
            wait_dead(fds[2], 'launcher before registration after manager death')
            wait_empty(group.parent)
            print('PASS:', case, flush=True)
            return
        if case == 'manager-before-clone':
            assert len(parts) == 4 and parts[0] == 'CLONE-GATE', ('unexpected clone barrier', parts)
            guard_pid, launcher_pid = map(int, parts[1:3])
            group = pathlib.Path(parts[3])
            assert group.name == 'worker' and group.parent.parent == root and group.parent.name.startswith('lsm-lifecycle-')
            fds.extend(receive_fds(control, child.pid, b'T', 3))
            assert [pidfd_pid(fd) for fd in fds] == [child.pid, guard_pid, launcher_pid]
            assert empty(group), 'worker cgroup was populated before clone'
            signal.pidfd_send_signal(fds[0], signal.SIGKILL)
            child.wait(timeout=TIMEOUT)
            deadline = time.monotonic() + TIMEOUT
            while time.monotonic() < deadline:
                guard_dead = poll_dead(fds[1], 0)
                launcher_dead = poll_dead(fds[2], 0)
                assert not guard_dead or launcher_dead, 'guard exited while launcher remained stopped before clone'
                if launcher_dead:
                    wait_empty(group)
                    print('PASS:', case, flush=True)
                    return
                time.sleep(.01)
            raise AssertionError('launcher remained alive before clone after manager death')
        assert len(parts) == 4 and parts[0] == 'PREPARED', ('unexpected prepare state', parts)
        guard_pid, worker_pid = map(int, parts[1:3])
        group = pathlib.Path(parts[3])
        assert group.name == 'worker' and group.parent.parent == root and group.parent.name.startswith('lsm-lifecycle-')
        fds.extend(receive_fds(control, child.pid, b'P', 3))
        assert [pidfd_pid(fd) for fd in fds] == [child.pid, guard_pid, worker_pid]
        assert str(worker_pid) in (group / 'cgroup.procs').read_text().split()
        assert not empty(group), 'worker not in dedicated cgroup before GO'
        if case == 'manager-before-go':
            signal.pidfd_send_signal(fds[0], signal.SIGKILL)
            child.wait(timeout=TIMEOUT)
        elif case == 'guard-before-go':
            signal.pidfd_send_signal(fds[1], signal.SIGKILL)
        else:
            child.stdin.write(b'G')
            child.stdin.flush()
            running = read_line(child.stdout).split()
            assert len(running) == 2 and running[0] == 'RUNNING'
            descendant = int(running[1])
            fds.extend(receive_fds(control, child.pid, b'D', 1))
            assert pidfd_pid(fds[3]) == descendant
            assert os.getsid(descendant) == descendant, 'descendant did not call setsid'
            assert {str(worker_pid), str(descendant)} <= set((group / 'cgroup.procs').read_text().split())
            if case == 'manager-after-go':
                signal.pidfd_send_signal(fds[0], signal.SIGKILL)
                child.wait(timeout=TIMEOUT)
            elif case == 'guard-after-go':
                signal.pidfd_send_signal(fds[1], signal.SIGKILL)
            else:
                raise AssertionError('unknown lifecycle case')
        wait_dead(fds[2], 'worker')
        if len(fds) > 3:
            wait_dead(fds[3], 'setsid descendant')
        wait_empty(group)
        print('PASS:', case, flush=True)
    finally:
        try:
            # The manager, guard and launcher are in this known disposable
            # parent even if failure occurs before any pidfd handoff.
            if not empty(root):
                (root / 'cgroup.kill').write_text('1')
                wait_empty(root)
            if child is not None:
                child.wait(timeout=TIMEOUT)
            for item in root.iterdir():
                if item.is_dir():
                    assert item.name.startswith('lsm-lifecycle-'), 'unexpected scope'
                    for nested in item.iterdir():
                        if nested.is_dir():
                            assert nested.name == 'worker', 'unexpected worker subgroup'
                            nested.rmdir()
                    item.rmdir()
            root.rmdir()
        finally:
            # Never skip later closes or temporary-directory cleanup if an
            # earlier cleanup operation fails; preserve the original failure.
            active_error = sys.exc_info()[0] is not None
            cleanup_errors = []
            for fd in fds:
                try:
                    os.close(fd)
                except OSError as error:
                    cleanup_errors.append(str(error))
            for endpoint in (peer, control):
                if endpoint is not None:
                    try:
                        endpoint.close()
                    except OSError as error:
                        cleanup_errors.append(str(error))
            try:
                temp.cleanup()
            except OSError as error:
                cleanup_errors.append(str(error))
            if cleanup_errors:
                print('resource cleanup errors: ' + '; '.join(cleanup_errors), file=sys.stderr)
                if not active_error:
                    raise RuntimeError('resource cleanup failed')


def main():
    if len(sys.argv) != 4 or os.geteuid() != 0:
        raise SystemExit(__doc__)
    executable = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
    parent = pathlib.Path(sys.argv[2]).resolve(strict=True)
    assert parent != pathlib.Path('/sys/fs/cgroup') and parent.is_relative_to('/sys/fs/cgroup')
    assert os.environ.get('LSM_TEST_DISPOSABLE_CGROUP') == str(parent)
    assert sys.argv[3] in ('manager-stopped-before-launcher', 'manager-before-registration', 'manager-before-clone', 'manager-before-go', 'guard-before-go', 'manager-after-go', 'guard-after-go')
    run_case(executable, parent, sys.argv[3])


if __name__ == '__main__':
    main()

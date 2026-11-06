#!/usr/bin/env python3
"""Disposable Linux-only pre-PDEATHSIG regression.

Usage: LSM_DISPOSABLE_CGROUP=1 python3 -I test-atomic-pre-pdeath.py LAUNCHER CGROUP_PARENT
The parent must be a disposable writable cgroup v2 mount. Only a fresh random
child cgroup and its test worker are created or signalled. Never use on a host.
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


def line(stream):
    result = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        ready, _, _ = select.select([stream], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        byte = os.read(stream.fileno(), 1)
        if not byte:
            raise AssertionError('launcher closed before synchronization')
        if byte == b'\n':
            return result.decode('ascii')
        result.extend(byte)
        if len(result) > 256:
            raise AssertionError('oversized launcher response')
    raise AssertionError('launcher synchronization timed out')


def populated(group):
    values = dict(item.split() for item in (group / 'cgroup.events').read_text().splitlines())
    if values.get('populated') not in ('0', '1'):
        raise AssertionError('invalid cgroup.events')
    return values['populated'] == '1'


def wait_dead(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    if not poller.poll(TIMEOUT * 1000):
        raise AssertionError('worker pidfd did not become readable')


def main():
    if sys.platform != 'linux' or len(sys.argv) != 3 or os.geteuid() != 0:
        raise SystemExit(__doc__)
    if os.environ.get('LSM_DISPOSABLE_CGROUP') != '1':
        raise SystemExit('explicit LSM_DISPOSABLE_CGROUP=1 required')
    executable = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
    parent = pathlib.Path(sys.argv[2]).resolve(strict=True)
    if not parent.is_relative_to('/sys/fs/cgroup') or not (parent / 'cgroup.controllers').exists():
        raise SystemExit('not a cgroup v2 parent')
    group = parent / ('lsm-gated-proof-' + uuid.uuid4().hex)
    group.mkdir(mode=0o700)
    launcher = None
    worker_fd = None
    try:
        launcher = subprocess.Popen([executable, str(group), 'before-pdeath'], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        tag, pid_text = line(launcher.stdout).split()
        if tag != 'FORKED':
            raise AssertionError('missing early worker identity')
        worker_pid = int(pid_text)
        worker_fd = os.pidfd_open(worker_pid)
        launcher.stdin.write(b'S')
        launcher.stdin.flush()
        tag, pid_text = line(launcher.stdout).split()
        if tag != 'STOPPED' or int(pid_text) != worker_pid:
            raise AssertionError('worker did not stop before PDEATHSIG')
        if not populated(group):
            raise AssertionError('pre-PDEATHSIG stopped worker is outside the dedicated cgroup')
        print('PASS: stopped pre-PDEATHSIG worker is already in cgroup', flush=True)
    finally:
        if worker_fd is not None:
            try:
                signal.pidfd_send_signal(worker_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            wait_dead(worker_fd)
            os.close(worker_fd)
        if launcher is not None and launcher.poll() is None:
            launcher.kill()
            launcher.wait(timeout=TIMEOUT)
        if populated(group):
            (group / 'cgroup.kill').write_text('1')
            deadline = time.monotonic() + TIMEOUT
            while populated(group) and time.monotonic() < deadline:
                time.sleep(0.01)
            if populated(group):
                raise AssertionError('disposable cgroup did not empty')
        group.rmdir()


if __name__ == '__main__':
    main()

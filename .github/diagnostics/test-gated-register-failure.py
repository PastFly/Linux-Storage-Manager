#!/usr/bin/env python3
"""Disposable Linux-only regression for an early pidfd registration failure.

LSM_DISPOSABLE_CGROUP=1 python3 -I test-gated-register-failure.py HARNESS CGROUP_PARENT
Creates one random child cgroup and a temporary marker; no block devices.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid


def populated(group):
    values = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())
    if values.get('populated') not in ('0', '1'):
        raise AssertionError('invalid cgroup.events')
    return values['populated'] == '1'


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 3:
        raise SystemExit(__doc__)
    if os.environ.get('LSM_DISPOSABLE_CGROUP') != '1':
        raise SystemExit('explicit LSM_DISPOSABLE_CGROUP=1 required')
    executable = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
    parent = pathlib.Path(sys.argv[2]).resolve(strict=True)
    if not parent.is_relative_to('/sys/fs/cgroup') or not (parent / 'cgroup.controllers').exists():
        raise SystemExit('not a cgroup v2 parent')
    group = parent / ('lsm-register-test-' + uuid.uuid4().hex)
    group.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix='lsm-register-test-') as tmp:
            marker = pathlib.Path(tmp) / 'started'
            env = os.environ.copy()
            env['LSM_TEST_REGISTER_FAIL'] = '1'
            result = subprocess.run([executable, str(group), 'success', str(marker)], env=env,
                                    timeout=25, check=False)
            if result.returncode == 0 or marker.exists():
                raise AssertionError('registration failure did not prevent GO and payload')
            if populated(group):
                raise AssertionError('registration failure left worker cgroup populated')
            print('PASS: rejected early pidfd registration prevented GO', flush=True)
    finally:
        if populated(group):
            (group / 'cgroup.kill').write_text('1')
            deadline = time.monotonic() + 10
            while populated(group) and time.monotonic() < deadline:
                time.sleep(0.01)
            if populated(group):
                raise AssertionError('disposable cgroup did not empty')
        group.rmdir()


if __name__ == '__main__':
    main()

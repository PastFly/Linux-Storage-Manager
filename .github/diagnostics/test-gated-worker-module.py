#!/usr/bin/env python3
"""Linux disposable-only module test: HARNESS DELEGATED_CGROUP_PARENT.
Creates fresh child cgroups and temporary regular markers; no block devices.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid


def populated(group):
    return dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())['populated'] == '1'


def clean_group(group):
    if populated(group):
        (group / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 10
        while populated(group) and time.monotonic() < deadline:
            time.sleep(0.01)
        if populated(group):
            raise AssertionError('test cgroup still populated')
    group.rmdir()


def main():
    if sys.platform != 'linux' or len(sys.argv) != 3 or os.geteuid() != 0:
        raise SystemExit(__doc__)
    binary = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
    parent = pathlib.Path(sys.argv[2]).resolve(strict=True)
    if not (parent / 'cgroup.controllers').exists():
        raise SystemExit('not a cgroup v2 parent')
    for mode in ('before', 'after-spawn', 'before-go', 'success'):
        group = parent / ('lsm-module-test-' + uuid.uuid4().hex)
        group.mkdir(mode=0o700)
        try:
            with tempfile.TemporaryDirectory(prefix='lsm-gated-module-') as tmp:
                marker = pathlib.Path(tmp) / 'marker'
                result = subprocess.run([binary, str(group), mode, str(marker)], timeout=25, check=False)
                if result.returncode:
                    raise AssertionError(f'{mode} failed with exit {result.returncode}')
                if marker.exists() != (mode == 'success'):
                    raise AssertionError(f'{mode} produced unexpected payload marker')
                if populated(group):
                    raise AssertionError(f'{mode} left test cgroup populated')
                print('PASS:', mode, flush=True)
        finally:
            clean_group(group)


if __name__ == '__main__':
    main()

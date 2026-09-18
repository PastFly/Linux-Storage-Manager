#!/usr/bin/env python3
"""Temporary observation-only entry point for the existing disposable-VM harness.

Preserve every harness check, argument, exit code and cleanup operation. Print
only the owned fixture facts returned by storage_facts, never the host snapshot.
"""
import json
from pathlib import Path
import runpy


def main():
    harness = Path(__file__).resolve().parents[1] / 'tests/integration/loop_matrix.py'
    namespace = runpy.run_path(str(harness), run_name='lsm_integration_trace')
    original = namespace['storage_facts']
    count = 0

    def trace(snapshot, loop, vg):
        nonlocal count
        facts = original(snapshot, loop, vg)
        count += 1
        print('OWNED_FIXTURE_FACTS ' + json.dumps(
            {'sample': count, 'loop': loop, 'vg': vg, 'facts': facts},
            sort_keys=True), flush=True)
        return facts

    namespace['exercise'].__globals__['storage_facts'] = trace
    return namespace['main']()


if __name__ == '__main__':
    raise SystemExit(main())

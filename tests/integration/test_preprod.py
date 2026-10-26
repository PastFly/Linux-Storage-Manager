#!/usr/bin/env python3
"""Rootless behavioral checks for Wave 1 orchestration."""
import importlib.util
import json
import os
import signal
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[2] / 'tools/preprod.py'
spec = importlib.util.spec_from_file_location('preprod', PATH)
p = importlib.util.module_from_spec(spec)
if PATH.exists():
    spec.loader.exec_module(p)

class PreprodTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.output = self.root / 'evidence'
        self.snapshot = {'fstab': {'sha256': 'a', 'mode': 420, 'uid': 0, 'gid': 0},
                         'loops': [], 'mounts': [], 'swaps': [], 'lvm': [], 'fixtures': []}

    def invoke(self, outcomes=None, snapshots=None):
        outcomes = outcomes or [(0, set(p.REQUIRED_MARKERS), False)] * 3
        with patch.object(p, 'check', return_value={'source_sha': 'a' * 40}), \
             patch.object(p, 'host_info', return_value={'arch': 'test'}), \
             patch.object(p, 'snapshot', side_effect=snapshots or [self.snapshot] * 6), \
             patch.object(p, 'execute_matrix', side_effect=outcomes) as execute:
            status = p.run(self.root, 'a' * 40, self.output)
        return status, json.loads((self.output / 'report.json').read_text()), execute.call_count

    def test_three_complete_runs_pass(self):
        status, report, count = self.invoke()
        self.assertEqual((status, report['result'], count), (0, 'PASS', 3))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def test_omitted_profile_fails_and_stops(self):
        status, report, count = self.invoke([(0, set(p.REQUIRED_MARKERS) - {'PRODUCTION_CREATE_PERSISTENT_E2E_OK=gpt-xfs:create-format-mount-fstab-restart-restore-unmount'}, False)])
        self.assertEqual((status, report['result'], count), (1, 'FAIL', 1))

    def test_nonzero_exit_fails_despite_all_markers(self):
        self.assertEqual(self.invoke([(1, set(p.REQUIRED_MARKERS), False)])[0], 1)

    def test_interruption_is_retained(self):
        status, report, count = self.invoke([(0, set(p.REQUIRED_MARKERS), True)])
        self.assertEqual((status, report['result'], count), (1, 'INTERRUPTED', 1))

    def test_changed_fstab_or_resources_fails(self):
        for key in ('fstab', 'loops', 'mounts', 'swaps', 'lvm', 'fixtures'):
            with self.subTest(key=key):
                self.output = self.root / key
                changed = dict(self.snapshot, **{key: ['changed']})
                self.assertEqual(self.invoke(snapshots=[self.snapshot, changed])[0], 1)

    def test_final_capture_failure_is_retained(self):
        status, report, count = self.invoke(snapshots=[self.snapshot, RuntimeError('capture failed')])
        self.assertEqual((status, report['result'], count), (1, 'FAIL', 1))
        self.assertIn('capture failed', report['error'])

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            p.run(self.root, 'a' * 40, self.output)

    def test_run_without_optin_refuses_before_check(self):
        with patch.object(p, 'check', side_effect=AssertionError('must not inspect')):
            self.assertNotEqual(p.main(['run', '--expected-source', 'a' * 40]), 0)

    def test_inventory_order_is_irrelevant(self):
        self.assertEqual(p.stable_rows([{'a': '1'}, {'a': '2'}]),
                         p.stable_rows([{'a': '2'}, {'a': '1'}]))

    def test_manifest_detects_binary_and_runner_drift(self):
        files = {}
        for name in p.BINARIES:
            path = self.root / 'target/preprod/release' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'binary')
            path.chmod(0o755)
            files[str(path.relative_to(self.root))] = p.digest(path)
        for name in p.SOURCE_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'source')
            files[name] = p.digest(path)
        manifest = {'source_sha': 'a' * 40, 'rustc': 'rustc 1.88.0 (test)', 'files': files}
        target = self.root / 'target/preprod/build.json'
        target.write_text(json.dumps(manifest))
        with patch.object(p, 'source_sha', return_value='a' * 40), \
             patch.object(p, 'tool_inventory', return_value={}):
            p.check(self.root, 'a' * 40)
            for name in (next(iter(files)), p.SOURCE_FILES[0]):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(b'drift')
                with self.assertRaises(p.PreprodError):
                    p.check(self.root, 'a' * 40)
                path.write_bytes(original)

    def test_dirty_tree_refuses(self):
        with patch.object(p, 'command', side_effect=['a' * 40, ' M tools/preprod.py']):
            with self.assertRaises(p.PreprodError):
                p.source_sha(self.root)

    def test_child_finishes_cleanup_when_console_output_fails(self):
        completed = self.root / 'cleanup-completed'
        script = ("import pathlib,time; print('ready',flush=True); time.sleep(.05); "
                  f"pathlib.Path({str(completed)!r}).write_text('done')")
        with patch('builtins.print', side_effect=BrokenPipeError('closed terminal')):
            with self.assertRaises(BrokenPipeError):
                p.execute_matrix([sys.executable, '-c', script], self.root / 'log')
        self.assertTrue(completed.exists(), 'wrapper abandoned the running matrix')

    def test_signal_is_forwarded_only_once_and_cleanup_finishes(self):
        completed = self.root / 'cleanup-completed'
        script = ("import signal,time,pathlib; "
                  "signal.signal(signal.SIGTERM,lambda s,f:None); "
                  "print('ready',flush=True); time.sleep(.05); "
                  f"pathlib.Path({str(completed)!r}).write_text('done')")
        def interrupt(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGTERM)
        with patch('builtins.print', side_effect=interrupt):
            code, markers, interrupted = p.execute_matrix([sys.executable, '-c', script], self.root / 'log')
        self.assertTrue(interrupted)
        self.assertEqual(code, 0)
        self.assertTrue(completed.exists())

    def fake_cargo(self, argv, **kwargs):
        binary = argv[argv.index('--bin') + 1]
        destination = self.root / 'target/preprod/x86_64-unknown-linux-gnu/release' / binary
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b'new binary')
        destination.chmod(0o755)

    def build_patches(self, launch):
        return (patch.object(p, 'source_sha', return_value='a' * 40),
                patch.object(p, 'command', side_effect=['rustc 1.88.0 (test)',
                             'rustc 1.88.0 (test)\nhost: x86_64-unknown-linux-gnu']),
                patch.object(p, 'digest', return_value='hash'),
                patch.object(p.subprocess, 'run', side_effect=launch))

    def test_build_uses_native_host_and_separate_features(self):
        a, b, c, d = self.build_patches(self.fake_cargo)
        with a, b, c, d as launch:
            p.build(self.root)
        commands = [call.args[0] for call in launch.call_args_list]
        self.assertEqual(len(commands), 6)
        self.assertIn('linux-storage-manager-cli', commands[0])
        for argv in commands:
            self.assertEqual(argv[argv.index('--target') + 1], 'x86_64-unknown-linux-gnu')
        for argv in commands[1:]:
            self.assertEqual(argv.count('--features'), 1)
        self.assertTrue((self.root / 'target/preprod/build.json').exists())

    def test_successful_wrong_target_build_cannot_relabel_stale_binaries(self):
        for name in p.BINARIES:
            old = self.root / 'target/preprod/release' / name
            old.parent.mkdir(parents=True, exist_ok=True)
            old.write_bytes(b'old candidate')
        a, b, c, d = self.build_patches(lambda *args, **kwargs: None)
        with a, b, c, d:
            with self.assertRaises((p.PreprodError, FileNotFoundError)):
                p.build(self.root)
        self.assertFalse((self.root / 'target/preprod/build.json').exists())

    def test_failed_summary_has_actionable_reason(self):
        self.invoke([(0, set(), False)])
        self.assertIn('missing markers', (self.output / 'SUMMARY.txt').read_text())

    def test_proc_swap_inventory_excludes_usage(self):
        first = 'Filename Type Size Used Priority\n/swapfile file 1024 0 -2\n'
        second = first.replace('1024 0', '1024 900')
        self.assertEqual(p.parse_swaps(first), p.parse_swaps(second))
        with self.assertRaises(p.PreprodError):
            p.parse_swaps('not an inventory')

    def test_source_mismatch_refuses_before_tools(self):
        with patch.object(p, 'source_sha', return_value='b' * 40), \
             patch.object(p, 'tool_inventory', side_effect=AssertionError('must not probe')):
            with self.assertRaises(p.PreprodError):
                p.check(self.root, 'a' * 40)

    def test_matrix_command_includes_every_profile_executor(self):
        argv = p.matrix_command(self.root)
        self.assertIn('--allow-disposable-loop-tests', argv)
        for flag, name in (
            ('--swap-executor-binary', 'lsm-disposable-swap-loop-harness'),
            ('--production-executor-binary', 'lsm-production-loop-harness'),
            ('--production-swap-executor-binary', 'lsm-production-swap-loop-harness'),
            ('--production-create-executor-binary', 'lsm-production-create-loop-harness')):
            self.assertEqual(argv[argv.index(flag) + 1], str(self.root / 'target/preprod/release' / name))
        self.assertIn(str(self.root / 'target/preprod/release/storagemgr'), argv)
        self.assertIn(str(self.root / 'target/preprod/release/lsm-disposable-loop-harness'), argv)

    def test_summary_is_replaced_atomically(self):
        self.output.mkdir()
        with patch.object(p.os, 'replace', wraps=os.replace) as replace:
            p.save_report(self.output, {'result': 'FAIL', 'expected_source': 'a' * 40, 'attempts': []})
        self.assertEqual({Path(call.args[1]).name for call in replace.call_args_list},
                         {'report.json', 'SUMMARY.txt'})

    def test_swap_identity_size_and_priority_drift_is_visible(self):
        baseline = 'Filename Type Size Used Priority\n/swapfile file 1024 0 -2\n'
        for changed in (baseline.replace('/swapfile', '/other'),
                        baseline.replace('1024', '2048'), baseline.replace('-2', '-3')):
            self.assertNotEqual(p.parse_swaps(baseline), p.parse_swaps(changed))

    def test_symlink_output_is_not_followed(self):
        destination = self.root / 'destination'
        destination.mkdir()
        self.output.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            p.run(self.root, 'a' * 40, self.output)
        self.assertEqual(list(destination.iterdir()), [])

    def test_missing_tool_is_prerequisite_failure(self):
        with patch.object(p.shutil, 'which', return_value=None):
            with self.assertRaises(p.PreprodError):
                p.tool_inventory()

if __name__ == '__main__':
    unittest.main()

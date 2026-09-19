#!/usr/bin/env python3
"""Unprivileged harness unit tests. NO block devices or storage tools are used."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("loop_matrix", Path(__file__).with_name("loop_matrix.py"))
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.loops = []
        self.mounts = []
        self.groups = []
        self.pvs = []
        self.fail = None
        self.lazy = False
        self.invalid_loop_report = False

    def run(self, name, *args, input=None, allowed=(0,)):
        self.calls.append((name, args))
        if name == self.fail:
            raise M.SafetyError("injected " + name + " failure")
        data, code = None, 0
        if name == "losetup" and "--detach" in args:
            if not self.lazy:
                self.loops = [row for row in self.loops if row["name"] != args[-1]]
        elif name == "losetup":
            data = {} if self.invalid_loop_report else {"loopdevices": self.loops}
        elif name == "findmnt":
            entries = self.mounts
            if "--mountpoint" in args:
                target = args[args.index("--mountpoint") + 1]
                entries = [row for row in entries if row["target"] == target]
                if not entries:
                    code = 1
            if code == 0:
                data = {"filesystems": entries}
        elif name == "umount":
            self.mounts = [row for row in self.mounts if row["target"] != args[-1]]
        elif name == "vgs":
            data = {"report": [{"vg": self.groups}]}
        elif name == "pvs":
            data = {"report": [{"pv": self.pvs}]}
        elif name == "vgremove":
            self.groups.clear()
        else:
            raise AssertionError("unexpected mock command: " + name)
        if code not in allowed:
            raise M.SafetyError("unexpected mock exit code")
        return subprocess.CompletedProcess((name, *args), code, json.dumps(data) if data is not None else "", "")

    def json(self, name, *args):
        return json.loads(self.run(name, *args).stdout)


class RunnerDiagnosticsTests(unittest.TestCase):
    def test_unexpected_exit_includes_stdout_and_stderr(self):
        fake = object.__new__(M.Runner)
        fake.tools = {"storagemgr": "/tmp/storagemgr"}
        completed = subprocess.CompletedProcess(
            ("/tmp/storagemgr", "plan"),
            2,
            '{"status":"blocked","blockers":[{"code":"example"}]}',
            "diagnostic stderr",
        )
        with patch.object(M.subprocess, "run", return_value=completed):
            with self.assertRaises(M.SafetyError) as error:
                fake.run("storagemgr", "plan")
        message = str(error.exception)
        self.assertIn('"status":"blocked"', message)
        self.assertIn("diagnostic stderr", message)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lsm-unit-")
        self.root = Path(self.temp.name) / "owned"
        self.root.mkdir()
        self.image = self.root / "test.img"
        self.image.write_bytes(b"fixture, not a real disk")
        self.runner = FakeRunner()
        self.resources = M.Resources(self.root, self.runner)
        info = self.image.stat()
        self.loop = M.Loop("/dev/loop987654", self.image, (info.st_dev, info.st_ino))
        self.resources.images.append(self.image)
        self.resources.loops.append(self.loop)
        self.runner.loops = [{"name": self.loop.device, "back-file": str(self.image)}]
        self.target = self.root / "mount"
        self.target.mkdir()
        self.resources.directories.append(self.target)
        self.resources.mounts.append(M.Mount("/dev/loop987654p1", self.target))
        self.runner.mounts = [{"source": "/dev/loop987654p1", "target": str(self.target)}]
        self.resources.groups.append(M.VolumeGroup("lsmtestabc", "/dev/loop987654p1", "vg-uuid"))
        self.runner.groups = [{"vg_name": "lsmtestabc", "vg_uuid": "vg-uuid"}]
        self.runner.pvs = [{"vg_name": "lsmtestabc", "pv_name": "/dev/loop987654p1"}]

    def tearDown(self):
        self.temp.cleanup()  # Only regular files made by this unprivileged unit test.

    def assert_retained(self, forbidden):
        self.assertTrue(self.image.exists())
        names = [name for name, _ in self.runner.calls]
        for name in forbidden:
            self.assertNotIn(name, names)
        self.assertFalse(any(name == "losetup" and "--detach" in args for name, args in self.runner.calls))

    def test_cleanup_orders_unmount_vg_remove_detach_then_unlink(self):
        self.resources.cleanup()
        calls = self.runner.calls
        unmount = next(i for i, (n, _) in enumerate(calls) if n == "umount")
        remove = next(i for i, (n, _) in enumerate(calls) if n == "vgremove")
        detach = next(i for i, (n, a) in enumerate(calls) if n == "losetup" and "--detach" in a)
        self.assertLess(unmount, remove)
        self.assertLess(remove, detach)
        self.assertFalse(self.root.exists())

    def test_unmount_failure_prevents_vg_remove_and_detach(self):
        self.runner.fail = "umount"
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["vgremove"])

    def test_foreign_mount_source_is_not_unmounted(self):
        self.runner.mounts[0]["source"] = "/dev/foreign"
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["umount", "vgremove"])

    def test_changed_backing_file_is_not_touched(self):
        self.runner.loops[0]["back-file"] = "/unowned/disk.img"
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["umount", "vgremove"])

    def test_replaced_image_inode_is_not_touched(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(b"new identity")
        replacement.replace(self.image)
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["umount", "vgremove"])

    def test_non_loop_device_is_rejected(self):
        self.loop.device = "/dev/sda"
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assertEqual(self.runner.calls, [])

    def test_duplicate_loop_identity_is_rejected(self):
        self.runner.loops *= 2
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["umount", "vgremove"])

    def test_missing_loop_report_does_not_mean_no_loops(self):
        self.runner.invalid_loop_report = True
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["umount", "vgremove"])

    def test_untracked_nested_mount_blocks_removal(self):
        self.runner.mounts.append({"source": "/dev/other", "target": str(self.root / "extra")})
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["vgremove"])

    def test_changed_vg_uuid_is_not_removed(self):
        self.runner.groups[0]["vg_uuid"] = "foreign-vg"
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["vgremove"])

    def test_unrecorded_vg_uuid_is_not_removed(self):
        self.resources.groups[0].uuid = None
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["vgremove"])

    def test_extra_pv_prevents_removal(self):
        self.runner.pvs.append({"vg_name": "lsmtestabc", "pv_name": "/dev/foreign"})
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained(["vgremove"])

    def test_vg_remove_failure_preserves_images(self):
        self.runner.fail = "vgremove"
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assert_retained([])

    def test_lazy_detach_preserves_image_until_confirmed(self):
        self.runner.lazy = True
        with patch.object(M.time, "sleep"), self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assertTrue(self.image.exists())

    def test_unexpected_files_are_never_recursively_deleted(self):
        extra = self.target / "unexpected.txt"
        extra.write_text("keep me")
        with self.assertRaises(OSError):
            self.resources.cleanup()
        self.assertEqual(extra.read_text(), "keep me")
        self.assertTrue(self.image.exists())

    def test_uncertain_creation_preserves_everything(self):
        self.resources.uncertain = True
        with self.assertRaises(M.SafetyError):
            self.resources.cleanup()
        self.assertEqual(self.runner.calls, [])
        self.assertTrue(self.image.exists())


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.preview = {"dry_run": True, "executable": False, "status": "preview", "blockers": [],
                        "steps": [{"operation": "revalidate_snapshot"}], "size_change": {
                            "extent_size_bytes": 4096, "rounded_growth_bytes": 4096,
                            "requested_growth_bytes": 1, "current_lv_size_bytes": 8192,
                            "expected_lv_size_bytes": 12288}}
        self.blocked = {"dry_run": True, "executable": False, "status": "blocked",
                        "steps": [], "blockers": [{"code": "no-capacity"}], "size_change": None}

    def test_valid_preview_and_blocked_shapes(self):
        M.check_preview(self.preview, "preview")
        M.check_preview(self.blocked, "blocked")

    def test_never_accepts_executable_or_missing_readonly_flags(self):
        for key, value in (("dry_run", False), ("executable", True), ("executable", None)):
            with self.subTest(key=key, value=value):
                plan = copy.deepcopy(self.preview)
                plan[key] = value
                with self.assertRaises(M.SafetyError):
                    M.check_preview(plan, "preview")

    def test_blocked_plan_cannot_contain_steps(self):
        self.blocked["steps"] = [{"operation": "extend_logical_volume"}]
        with self.assertRaises(M.SafetyError):
            M.check_preview(self.blocked, "blocked")

    def test_blocked_plan_requires_reason(self):
        self.blocked["blockers"] = []
        with self.assertRaises(M.SafetyError):
            M.check_preview(self.blocked, "blocked")

    def test_preview_rejects_bad_extent_arithmetic(self):
        for key, value in (("extent_size_bytes", 0), ("rounded_growth_bytes", 4095),
                           ("expected_lv_size_bytes", 12289), ("requested_growth_bytes", 8192)):
            with self.subTest(key=key):
                plan = copy.deepcopy(self.preview)
                plan["size_change"][key] = value
                with self.assertRaises(M.SafetyError):
                    M.check_preview(plan, "preview")

    def test_missing_ack_refuses_before_runner_is_constructed(self):
        with patch.object(M, "Runner") as runner, patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:
                M.main(["/does/not/matter"])
        self.assertEqual(error.exception.code, 2)
        runner.assert_not_called()


class ExerciseTests(unittest.TestCase):
    def test_exercises_size_modes_and_expected_exit_codes_without_mutation(self):
        self._exercise(False)

    def test_detects_geometry_drift_after_readonly_commands(self):
        self._exercise(True)

    def test_waits_for_fixture_metadata_before_starting_readonly_commands(self):
        with patch.object(M.time, "sleep"):
            self._exercise(False, readiness_drift=True)

    def _exercise(self, drift, readiness_drift=False):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "readonly-sentinel").write_bytes(b"original")
            before = {"partition_tables": [{"device": "/dev/loop987654", "partitions": []}],
                      "storage": {"block_devices": [{
                          "path": "/dev/loop987654", "kind": "loop", "size_bytes": 100,
                          "children": [{
                              "path": "/dev/loop987654p1", "kind": "partition",
                              "uuid": "pv-uuid", "children": [{
                                  "path": "/dev/mapper/lsmtestabc-data", "kind": "lvm",
                                  "uuid": "fs-uuid", "children": []
                              }]
                          }]
                      }]},
                      "lvm": {
                          "physical_volumes": [{
                              "name": "/dev/loop987654p1", "uuid": "pv-uuid",
                              "vg_name": "lsmtestabc"
                          }],
                          "volume_groups": [{"name": "lsmtestabc", "uuid": "vg-uuid"}],
                          "logical_volumes": [{
                              "name": "data", "path": "/dev/lsmtestabc/data",
                              "uuid": "lv-uuid", "vg_name": "lsmtestabc"
                          }]
                      },
                      "diagnostics": []}
            after = copy.deepcopy(before)
            if drift:
                after["storage"]["block_devices"][0]["size_bytes"] = 101
            preview = {"dry_run": True, "executable": False, "status": "preview", "blockers": [],
                       "steps": [{"operation": "revalidate_snapshot"}], "size_change": {
                           "extent_size_bytes": 4096, "rounded_growth_bytes": 4096,
                           "requested_growth_bytes": 4096, "current_lv_size_bytes": 8192,
                           "expected_lv_size_bytes": 12288}}
            blocked = {"dry_run": True, "executable": False, "status": "blocked", "steps": [],
                       "blockers": [{"code": "insufficient-capacity"}], "size_change": None}
            calls = []
            class FakeApplication:
                def __init__(self):
                    self.sample_count = 0
                def json(self, name, *args):
                    assert args == ("snapshot",)
                    self.sample_count += 1
                    if calls:
                        return after
                    if readiness_drift and self.sample_count == 1:
                        early = copy.deepcopy(before)
                        early["storage"]["block_devices"][0]["children"][0]["children"][0]["uuid"] = None
                        return early
                    return before
                def run(self, name, *args, allowed=(0,)):
                    if name == "udevadm":
                        assert args == ("settle", "--timeout=30")
                        return subprocess.CompletedProcess(args, 0, "", "")
                    calls.append((args, allowed))
                    refusal = "1TiB" in args or "--apply" in args
                    assert allowed == ((2,) if refusal else (0,))
                    return subprocess.CompletedProcess(args, 2 if refusal else 0,
                                                       json.dumps(blocked if refusal else preview), "")
            application = FakeApplication()
            loop = M.Loop("/dev/loop987654", target / "unused.img", (0, 0))
            if drift:
                with self.assertRaises(M.SafetyError):
                    M.exercise(None, application, loop, target, "lsmtestabc")
            else:
                M.exercise(None, application, loop, target, "lsmtestabc")
            self.assertEqual(len(calls), 4)
            self.assertEqual((target / "readonly-sentinel").read_bytes(), b"original")


class IdentityReadinessTests(unittest.TestCase):
    def test_lvm_fixture_requires_all_runtime_identities(self):
        snapshot = {
            "storage": {"block_devices": [{
                "path": "/dev/loop987654", "kind": "loop", "uuid": None,
                "children": [{
                    "path": "/dev/loop987654p1", "kind": "partition",
                    "uuid": "pv-uuid", "children": [{
                        "path": "/dev/mapper/lsmtestabc-data", "kind": "lvm",
                        "uuid": "fs-uuid", "children": []
                    }]
                }]
            }]},
            "lvm": {
                "physical_volumes": [{
                    "name": "/dev/loop987654p1", "uuid": "pv-uuid",
                    "vg_name": "lsmtestabc"
                }],
                "volume_groups": [{
                    "name": "lsmtestabc", "uuid": "vg-uuid"
                }],
                "logical_volumes": [{
                    "name": "data", "path": "/dev/lsmtestabc/data",
                    "uuid": "lv-uuid", "vg_name": "lsmtestabc"
                }],
            },
        }
        self.assertTrue(M.fixture_identity_ready(snapshot, "/dev/loop987654", "lsmtestabc"))

        broken = copy.deepcopy(snapshot)
        broken["storage"]["block_devices"][0]["children"][0]["children"][0]["uuid"] = None
        self.assertFalse(M.fixture_identity_ready(broken, "/dev/loop987654", "lsmtestabc"))

        broken = copy.deepcopy(snapshot)
        broken["lvm"]["logical_volumes"][0]["uuid"] = None
        self.assertFalse(M.fixture_identity_ready(broken, "/dev/loop987654", "lsmtestabc"))

    def test_plain_fixture_does_not_require_lvm_identity(self):
        snapshot = {"storage": {"block_devices": []}, "lvm": None}
        self.assertTrue(M.fixture_identity_ready(snapshot, "/dev/loop987654", None))


class PartitionRecoveryHelperTests(unittest.TestCase):
    def facts(self, label="gpt"):
        return {
            "partitiontable": {
                "label": label,
                "id": "disk-id",
                "device": "/dev/loop987654",
                "unit": "sectors",
                "firstlba": 34 if label == "gpt" else None,
                "lastlba": 524254 if label == "gpt" else None,
                "sectorsize": 512,
                "partitions": [{
                    "node": "/dev/loop987654p1",
                    "start": 2048,
                    "size": 262144,
                    "type": (
                        "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
                        if label == "gpt" else "83"
                    ),
                    "uuid": "part-id" if label == "gpt" else None,
                }],
            }
        }

    def test_machine_readable_facts_preserve_exact_geometry(self):
        for label in ("gpt", "dos"):
            with self.subTest(label=label):
                facts = M.partition_table_facts(
                    self.facts(label), "/dev/loop987654", "/dev/loop987654p1"
                )
                self.assertEqual(facts["label"], label)
                self.assertEqual(facts["sectorsize"], 512)
                self.assertEqual(facts["partitions"][0]["start"], 2048)
                self.assertEqual(facts["partitions"][0]["size"], 262144)

    def test_recovery_facts_reject_foreign_device_or_multiple_partitions(self):
        with self.assertRaises(M.SafetyError):
            M.partition_table_facts(
                self.facts(), "/dev/loop987655", "/dev/loop987655p1"
            )
        duplicate = self.facts()
        duplicate["partitiontable"]["partitions"].append(
            copy.deepcopy(duplicate["partitiontable"]["partitions"][0])
        )
        duplicate["partitiontable"]["partitions"][1]["node"] = "/dev/loop987654p2"
        with self.assertRaises(M.SafetyError):
            M.partition_table_facts(
                duplicate, "/dev/loop987654", "/dev/loop987654p1"
            )

    def test_controlled_mutation_only_grows_partition_end(self):
        facts = M.partition_table_facts(
            self.facts(), "/dev/loop987654", "/dev/loop987654p1"
        )
        script, new_size = M.growth_only_partition_script(
            facts, disk_sectors=524288, growth_sectors=8192
        )

        self.assertEqual(new_size, 270336)
        self.assertIn("label: gpt", script)
        self.assertIn("unit: sectors", script)
        self.assertIn("2048,270336,", script)
        self.assertNotIn("203", script.splitlines()[-1].split(",")[0])

    def test_controlled_mutation_refuses_insufficient_guarded_tail(self):
        facts = M.partition_table_facts(
            self.facts(), "/dev/loop987654", "/dev/loop987654p1"
        )
        with self.assertRaisesRegex(M.SafetyError, "insufficient guarded tail"):
            M.growth_only_partition_script(
                facts, disk_sectors=272000, growth_sectors=8192
            )


class UdevRefreshTests(unittest.TestCase):
    def test_refresh_targets_only_created_block_sysname_and_settles(self):
        runner = Mock()
        M.refresh_fixture_udev(runner, "dm-7")
        self.assertEqual(
            runner.run.call_args_list,
            [
                unittest.mock.call(
                    "udevadm",
                    "trigger",
                    "--action=change",
                    "--sysname-match=dm-7",
                ),
                unittest.mock.call("udevadm", "settle", "--timeout=30"),
            ],
        )

    def test_refresh_rejects_non_sysname_input(self):
        runner = Mock()
        with self.assertRaises(M.SafetyError):
            M.refresh_fixture_udev(runner, "../sda")
        runner.run.assert_not_called()


class ReadinessTests(unittest.TestCase):
    def test_settle_failure_prevents_baseline_collection(self):
        runner = Mock()
        runner.run.side_effect = M.SafetyError("udev queue timeout")
        with self.assertRaisesRegex(M.SafetyError, "udev queue timeout"):
            M.ready_snapshot(runner, "/dev/loop987654", None)
        runner.json.assert_not_called()

    def test_unstable_baseline_is_bounded_and_refused(self):
        runner = Mock()
        runner.json.side_effect = list(range(20))
        with patch.object(M, "storage_facts", side_effect=lambda sample, *_: sample), \
                patch.object(M.time, "sleep"):
            with self.assertRaisesRegex(M.SafetyError, "did not stabilize"):
                M.ready_snapshot(runner, "/dev/loop987654", None)
        self.assertEqual(runner.json.call_count, 20)
        runner.run.assert_called_once_with("udevadm", "settle", "--timeout=30")

    def test_baseline_requires_two_identical_owned_samples(self):
        runner = Mock()
        runner.json.side_effect = [1, 2, 2]
        with patch.object(M, "storage_facts", side_effect=lambda sample, *_: sample), \
                patch.object(M.time, "sleep"):
            self.assertEqual(M.ready_snapshot(runner, "/dev/loop987654", None), 2)
        self.assertEqual(runner.json.call_count, 3)


if __name__ == "__main__":
    unittest.main()

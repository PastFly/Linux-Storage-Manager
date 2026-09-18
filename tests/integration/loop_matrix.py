#!/usr/bin/env python3
"""Opt-in storage integration tests. Run only in a disposable Linux VM.

The harness creates storage; storagemgr must not. Unit tests mock every command.
Cleanup never uses recursive deletion and retains resources on uncertain ownership.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any


class SafetyError(RuntimeError):
    pass


class Runner:
    def __init__(self, binary: Path):
        names = ("losetup", "sfdisk", "partx", "mkfs.ext4", "mkfs.xfs", "pvcreate",
                 "vgcreate", "lvcreate", "vgremove", "vgs", "pvs", "mount", "umount",
                 "findmnt", "vgcfgbackup", "lvextend", "resize2fs", "xfs_growfs", "udevadm")
        self.tools = {}
        for name in names:
            path = shutil.which(name)
            if path is None:
                raise SafetyError(f"required test tool is missing: {name}")
            self.tools[name] = path
        self.tools["storagemgr"] = str(binary.resolve(strict=True))

    def run(self, name: str, *args: str, input: str | None = None,
            allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [self.tools[name], *args], input=input, text=True, capture_output=True,
            timeout=120, env={**os.environ, "LC_ALL": "C", "LANG": "C"}, check=False,
        )
        if result.returncode not in allowed:
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            raise SafetyError(
                f"{name} {args!r} exited {result.returncode}: "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        return result

    def json(self, name: str, *args: str) -> Any:
        return json.loads(self.run(name, *args).stdout)


def rows(data: Any, envelope: str, key: str) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get(envelope), list):
        raise SafetyError(f"missing {envelope} report")
    result = []
    for report in data[envelope]:
        if not isinstance(report, dict) or not isinstance(report.get(key), list):
            raise SafetyError(f"missing {key} rows")
        result.extend(report[key])
    if not all(isinstance(row, dict) for row in result):
        raise SafetyError("invalid report row")
    return result


def mount_rows(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("filesystems"), list):
        raise SafetyError("missing findmnt filesystems report")
    result = []
    def visit(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get("target"), str):
                raise SafetyError("invalid findmnt entry")
            result.append(node)
            visit(node.get("children", []))
    visit(data["filesystems"])
    return result


@dataclass
class Loop:
    device: str
    image: Path
    inode: tuple[int, int]


@dataclass
class VolumeGroup:
    name: str
    pv: str
    uuid: str | None = None


@dataclass
class Mount:
    source: str
    target: Path


class Resources:
    def __init__(self, root: Path, runner: Runner):
        self.root = root.resolve(strict=True)
        self.runner = runner
        self.loops: list[Loop] = []
        self.groups: list[VolumeGroup] = []
        self.mounts: list[Mount] = []
        self.images: list[Path] = []
        self.directories: list[Path] = []
        self.uncertain = False

    def loop_report(self) -> list[dict[str, Any]]:
        data = self.runner.json("losetup", "--list", "--json", "--output", "NAME,BACK-FILE")
        if not isinstance(data, dict) or not isinstance(data.get("loopdevices"), list):
            raise SafetyError("cannot establish loop ownership")
        if not all(isinstance(row, dict) and isinstance(row.get("name"), str)
                   and isinstance(row.get("back-file"), str) for row in data["loopdevices"]):
            raise SafetyError("invalid loop ownership report")
        return data["loopdevices"]

    def check_loop(self, loop: Loop) -> None:
        if re.fullmatch(r"/dev/loop[0-9]+", loop.device) is None:
            raise SafetyError("refusing non-loop device")
        matches = [row for row in self.loop_report() if row["name"] == loop.device]
        if len(matches) != 1 or matches[0]["back-file"] != str(loop.image):
            raise SafetyError(f"loop backing file changed: {loop.device}")
        info = loop.image.lstat()
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != loop.inode:
            raise SafetyError(f"image identity changed: {loop.image}")
        if loop.image.parent != self.root:
            raise SafetyError("image is outside the owned directory")

    def create_loop(self, label: str, size: int) -> Loop:
        image = self.root / f"{label}.img"
        with image.open("xb") as stream:
            stream.truncate(size)
        self.images.append(image)
        info = image.stat()
        # Any ambiguous create failure leaves resources for manual inspection.
        self.uncertain = True
        device = self.runner.run("losetup", "--find", "--show", "--partscan",
                                 "--nooverlap", str(image)).stdout.strip()
        loop = Loop(device, image, (info.st_dev, info.st_ino))
        self.loops.append(loop)
        self.check_loop(loop)
        self.uncertain = False
        return loop

    def create_partition(self, loop: Loop, size_mib: int, lvm: bool) -> str:
        self.check_loop(loop)
        device_info = Path(loop.device).stat()
        if not stat.S_ISBLK(device_info.st_mode) or os.major(device_info.st_rdev) != 7:
            raise SafetyError("expected an actual Linux loop block device")
        partition_type = ",E6D6D379-F507-44C2-A23C-238F2A3DF928" if lvm else ""
        self.runner.run("sfdisk", loop.device,
                        input=f"label: gpt\n,{size_mib}MiB{partition_type}\n")
        self.runner.run("partx", "--update", loop.device)
        partition = loop.device + "p1"
        wait_block(partition)
        sys_path = Path("/sys/class/block") / Path(partition).name
        if not (sys_path / "partition").is_file() or sys_path.resolve().parent.name != Path(loop.device).name:
            raise SafetyError("partition parent identity could not be verified")
        self.check_loop(loop)
        return partition

    def create_vg(self, loop: Loop, partition: str, name: str) -> str:
        self.check_loop(loop)
        if partition != loop.device + "p1" or re.fullmatch(r"lsmtest[a-f0-9]+", name) is None:
            raise SafetyError("invalid disposable PV or VG")
        if self.vg_rows(name):
            raise SafetyError(f"refusing existing VG: {name}")
        self.runner.run("pvcreate", "--yes", partition)
        group = VolumeGroup(name, partition)
        self.groups.append(group)  # Also track partial vgcreate failures.
        self.runner.run("vgcreate", name, partition)
        reports = self.vg_rows(name)
        if len(reports) != 1 or not reports[0].get("vg_uuid"):
            raise SafetyError("new VG identity is unavailable")
        group.uuid = reports[0]["vg_uuid"].strip()
        self.runner.run("lvcreate", "--size", "384MiB", "--name", "data", name)
        lv = f"/dev/{name}/data"
        wait_block(lv)
        return lv

    def vg_rows(self, name: str) -> list[dict[str, Any]]:
        return rows(self.runner.json("vgs", "--reportformat", "json", "--options",
                                    "vg_name,vg_uuid", "--select", f"vg_name={name}"), "report", "vg")

    def mount(self, source: str, label: str) -> Path:
        target = self.root / label
        target.mkdir()
        self.directories.append(target)
        self.mounts.append(Mount(source, target))
        self.runner.run("mount", source, str(target))
        (target / "readonly-sentinel").write_bytes(b"Linux Storage Manager read-only sentinel\n")
        return target

    def cleanup(self) -> None:
        # Never detach/remove resources after an ownership or unmount failure.
        if self.uncertain:
            raise SafetyError("creation state is uncertain; retaining all test resources")
        for loop in self.loops:
            self.check_loop(loop)
        for mount in reversed(self.mounts):
            current = self.runner.run("findmnt", "--json", "--mountpoint", str(mount.target),
                                      "--output", "SOURCE,TARGET", allowed=(0, 1))
            if current.returncode == 1 and not current.stdout.strip() and not current.stderr.strip():
                continue
            if current.returncode != 0:
                raise SafetyError("unable to establish mount state")
            entries = mount_rows(json.loads(current.stdout))
            if (len(entries) != 1 or entries[0]["target"] != str(mount.target)
                    or not isinstance(entries[0].get("source"), str)
                    or os.path.realpath(entries[0]["source"]) != os.path.realpath(mount.source)):
                raise SafetyError(f"mount ownership changed: {mount.target}")
            self.runner.run("umount", str(mount.target))
        remaining = mount_rows(self.runner.json("findmnt", "--json", "--output", "TARGET"))
        if any(row["target"] == str(self.root) or row["target"].startswith(str(self.root) + "/")
               for row in remaining):
            raise SafetyError("mounts remain under the test directory")
        for group in reversed(self.groups):
            entries = self.vg_rows(group.name)
            if not entries:
                continue
            if (len(entries) != 1 or group.uuid is None or entries[0].get("vg_name") != group.name
                    or entries[0].get("vg_uuid", "").strip() != group.uuid):
                raise SafetyError(f"VG ownership changed or unknown: {group.name}")
            pvs = rows(self.runner.json("pvs", "--reportformat", "json", "--options",
                                       "pv_name,vg_name", "--select", f"vg_name={group.name}"), "report", "pv")
            if (len(pvs) != 1 or pvs[0].get("vg_name") != group.name
                    or os.path.realpath(pvs[0].get("pv_name", "")) != os.path.realpath(group.pv)):
                raise SafetyError(f"VG has unexpected PV membership: {group.name}")
            self.runner.run("vgremove", "--yes", group.name)
        for loop in reversed(self.loops):
            self.check_loop(loop)
            self.runner.run("losetup", "--detach", loop.device)
        # Detach can be lazy. Never unlink images that remain associated with a loop.
        for _ in range(50):
            associated = {row["back-file"] for row in self.loop_report()}
            if not any(str(image) in associated for image in self.images):
                break
            time.sleep(0.1)
        else:
            raise SafetyError("loop detach has not completed; retaining image files")
        # rmdir fails on unexpected contents; no recursive deletion, even on error.
        for directory in reversed(self.directories):
            directory.rmdir()
        for image in self.images:
            image.unlink()
        self.root.rmdir()


def wait_block(path: str) -> None:
    for _ in range(100):
        try:
            if stat.S_ISBLK(Path(path).stat().st_mode):
                return
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    raise SafetyError(f"block device did not appear: {path}")


def check_preview(plan: Any, expected_status: str) -> None:
    if not isinstance(plan, dict):
        raise SafetyError("plan is not a JSON object")
    if plan.get("dry_run") is not True or plan.get("executable") is not False:
        raise SafetyError("plan does not explicitly prohibit execution")
    if plan.get("status") != expected_status:
        raise SafetyError(f"unexpected plan status: {plan.get('status')!r}; blockers={plan.get('blockers')!r}")
    if expected_status == "blocked":
        if (plan.get("steps") != [] or not plan.get("blockers")
                or plan.get("size_change") is not None
                or plan.get("partition_size_change") is not None):
            raise SafetyError("blocked plan contains operations or lacks a reason")
    else:
        lvm_change = plan.get("size_change")
        partition_change = plan.get("partition_size_change")
        if ((isinstance(lvm_change, dict) + isinstance(partition_change, dict)) != 1
                or not plan.get("steps") or plan.get("blockers") != []):
            raise SafetyError("preview must contain exactly one size change and no blockers")
        if isinstance(lvm_change, dict):
            extent = lvm_change.get("extent_size_bytes")
            growth = lvm_change.get("rounded_growth_bytes")
            if (type(extent) is not int or extent <= 0 or type(growth) is not int or growth <= 0
                    or growth % extent or growth < lvm_change["requested_growth_bytes"]
                    or lvm_change["current_lv_size_bytes"] + growth
                    != lvm_change["expected_lv_size_bytes"]):
                raise SafetyError("inconsistent LVM preview size arithmetic")
        else:
            sector = partition_change.get("sector_size_bytes")
            growth = partition_change.get("rounded_growth_bytes")
            if (type(sector) is not int or sector <= 0 or type(growth) is not int or growth <= 0
                    or growth % sector or growth < partition_change["requested_growth_bytes"]
                    or partition_change["current_partition_size_bytes"] + growth
                    != partition_change["expected_partition_size_bytes"]):
                raise SafetyError("inconsistent partition preview size arithmetic")


def storage_facts(snapshot: dict[str, Any], loop: str, vg: str | None) -> Any:
    """Compare only the owned fixture's geometry/identity, not volatile host usage."""
    tables = [table for table in snapshot["partition_tables"] if table["device"] == loop]
    if len(tables) != 1:
        raise SafetyError("owned partition table missing or duplicated")
    lvm = snapshot.get("lvm")
    if vg is not None and not isinstance(lvm, dict):
        raise SafetyError("LVM collector is unavailable")
    inventory = {} if vg is None else {
        key: sorted((row for row in lvm[key] if row.get("vg_name", row.get("name")) == vg),
                    key=lambda row: row["name"])
        for key in ("physical_volumes", "volume_groups", "logical_volumes")
    }
    devices = [node for node in snapshot["storage"]["block_devices"] if node.get("path") == loop]
    if len(devices) != 1:
        raise SafetyError("owned lsblk tree missing or duplicated")
    return tables, inventory, devices


def fixture_identity_gaps(snapshot: dict[str, Any], loop: str, vg: str | None) -> list[str]:
    if vg is None:
        return []

    gaps: list[str] = []
    lvm = snapshot.get("lvm")
    storage = snapshot.get("storage")
    if not isinstance(lvm, dict):
        return ["lvm-inventory-missing"]
    if not isinstance(storage, dict):
        return ["storage-graph-missing"]

    pvs = [row for row in lvm.get("physical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg]
    vgs = [row for row in lvm.get("volume_groups", [])
           if isinstance(row, dict) and row.get("name") == vg]
    lvs = [row for row in lvm.get("logical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg]
    if len(pvs) != 1:
        gaps.append(f"pv-count={len(pvs)}")
    if len(vgs) != 1:
        gaps.append(f"vg-count={len(vgs)}")
    if len(lvs) != 1:
        gaps.append(f"lv-count={len(lvs)}")
    if gaps:
        return gaps

    for label, row in (("pv", pvs[0]), ("vg", vgs[0]), ("lv", lvs[0])):
        if not isinstance(row.get("uuid"), str) or not row["uuid"]:
            gaps.append(f"{label}-uuid-missing")

    roots = [node for node in storage.get("block_devices", [])
             if isinstance(node, dict) and node.get("path") == loop]
    if len(roots) != 1:
        gaps.append(f"loop-root-count={len(roots)}")
        return gaps

    nodes: list[dict[str, Any]] = []
    def visit(node: dict[str, Any]) -> None:
        nodes.append(node)
        for child in node.get("children", []):
            if isinstance(child, dict):
                visit(child)
    visit(roots[0])

    pv_nodes = [node for node in nodes if node.get("path") == pvs[0].get("name")]
    if len(pv_nodes) != 1:
        gaps.append(f"pv-node-count={len(pv_nodes)}")
    elif pv_nodes[0].get("uuid") != pvs[0].get("uuid"):
        gaps.append(
            f"pv-node-uuid={pv_nodes[0].get('uuid')!r} expected={pvs[0].get('uuid')!r}"
        )

    lvm_nodes = [node for node in nodes if node.get("kind") == "lvm"]
    if len(lvm_nodes) != 1:
        gaps.append(f"lvm-node-count={len(lvm_nodes)}")
    elif not isinstance(lvm_nodes[0].get("uuid"), str) or not lvm_nodes[0]["uuid"]:
        gaps.append("filesystem-uuid-missing")

    return gaps


def fixture_identity_ready(snapshot: dict[str, Any], loop: str, vg: str | None) -> bool:
    return not fixture_identity_gaps(snapshot, loop, vg)


def ready_snapshot(binary: Runner, loop: str, vg: str | None) -> dict[str, Any]:
    """Require settled, repeatable fixture facts BEFORE testing nonmutation.

    This is fixture setup, not an acceptance retry. Changes after any planning
    command still fail immediately; no mismatching post-test sample is retried.
    """
    binary.run("udevadm", "settle", "--timeout=30")
    previous = None
    for attempt in range(20):
        snapshot = binary.json("storagemgr", "snapshot")
        facts = storage_facts(snapshot, loop, vg)
        if previous is not None and facts == previous and fixture_identity_ready(snapshot, loop, vg):
            return snapshot
        previous = facts
        if attempt < 19:
            time.sleep(0.1)
    gaps = fixture_identity_gaps(snapshot, loop, vg) if 'snapshot' in locals() else ["no-snapshot"]
    raise SafetyError(
        "fixture metadata did not stabilize before read-only tests; identity gaps="
        + ",".join(gaps)
    )


def exercise(resources: Resources, binary: Runner, loop: Loop, target: Path, vg: str | None) -> None:
    before = ready_snapshot(binary, loop.device, vg)
    facts = storage_facts(before, loop.device, vg)
    sentinel = (target / "readonly-sentinel").read_bytes()
    for flag, value in (("--by", "8MiB"), ("--max", None), ("--by", "1TiB")):
        arguments = ["plan", "extend", str(target), flag]
        if value is not None:
            arguments.append(value)
        expected = "blocked" if value == "1TiB" else "preview"
        output = binary.run("storagemgr", *arguments, "--json", allowed=(2,) if expected == "blocked" else (0,))
        check_preview(json.loads(output.stdout), expected)
    result = binary.run("storagemgr", "plan", "extend", str(target), "--max", "--apply", allowed=(2,))
    if result.returncode != 2:
        raise SafetyError("--apply must be rejected by the CLI")
    after = binary.json("storagemgr", "snapshot")
    after_facts = storage_facts(after, loop.device, vg)
    if facts != after_facts:
        evidence = json.dumps({"before": facts, "after": after_facts}, sort_keys=True)
        raise SafetyError("owned storage facts changed during read-only planning: " + evidence)
    if sentinel != (target / "readonly-sentinel").read_bytes():
        raise SafetyError("sentinel changed during read-only planning")
    for snapshot in (before, after):
        for item in snapshot["diagnostics"]:
            device = item.get("device") or ""
            if item["severity"] == "error" and (device == loop.device or device.startswith(loop.device + "p")):
                raise SafetyError(f"fixture geometry diagnostic: {item!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-disposable-loop-tests", action="store_true",
                        help="acknowledge that this dedicated VM can be discarded")
    parser.add_argument("binary", type=Path)
    args = parser.parse_args(argv)
    if not args.allow_disposable_loop_tests:
        parser.error("explicit --allow-disposable-loop-tests is required; never use on a production host")
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires root in a disposable Linux VM")
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error("binary is absent or not executable")
    def interrupted(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt(f"received signal {signum}")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    os.umask(0o077)
    runner = Runner(args.binary)
    root = Path(tempfile.mkdtemp(prefix="lsm-loop-matrix-"))
    resources = Resources(root, runner)
    failed = False
    try:
        for label, filesystem, lvm in (("plain", "ext4", False), ("lvm-ext4", "ext4", True), ("lvm-xfs", "xfs", True)):
            print(f"==> {label}", flush=True)
            loop = resources.create_loop(label, 1024 * 1024 * 1024 if lvm else 256 * 1024 * 1024)
            partition = resources.create_partition(loop, 896 if lvm else 128, lvm)
            vg = "lsmtest" + os.urandom(12).hex() if lvm else None
            source = resources.create_vg(loop, partition, vg) if vg else partition
            runner.run("mkfs." + filesystem, "-f" if filesystem == "xfs" else "-F", source)
            target = resources.mount(source, label + "-mount")
            exercise(resources, runner, loop, target, vg)
    except (OSError, ValueError, KeyError, TypeError, SafetyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(f"INTEGRATION_FAILED: {error}", file=sys.stderr)
        failed = True
    finally:
        try:
            resources.cleanup()
        except (OSError, ValueError, KeyError, TypeError, SafetyError, subprocess.SubprocessError) as error:
            print(f"CLEANUP_INCOMPLETE: {error}; retained directory: {root}", file=sys.stderr)
            failed = True
    if not failed:
        print("LOOP_MATRIX_OK cases=plain-ext4,lvm-ext4,lvm-xfs cleanup=complete")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

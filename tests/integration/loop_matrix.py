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
    def __init__(self, binary: Path, executor_binary: Path):
        names = ("losetup", "sfdisk", "partx", "mkfs.ext4", "mkfs.xfs", "pvcreate",
                 "vgcreate", "vgchange", "lvcreate", "lvrename", "vgremove", "vgs", "pvs", "lvs",
                 "mount", "umount", "findmnt", "vgcfgbackup", "vgcfgrestore", "pvresize", "lvextend",
                 "resize2fs", "xfs_growfs", "xfs_scrub", "udevadm")
        self.tools = {}
        for name in names:
            path = shutil.which(name)
            if path is None:
                raise SafetyError(f"required test tool is missing: {name}")
            self.tools[name] = path
        self.tools["storagemgr"] = str(binary.resolve(strict=True))
        self.tools["disposable-executor"] = str(executor_binary.resolve(strict=True))

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
        self.artifacts: list[tuple[Path, tuple[int, int]]] = []
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

    def create_partition(self, loop: Loop, size_mib: int, lvm: bool,
                         table_label: str = "gpt") -> str:
        self.check_loop(loop)
        device_info = Path(loop.device).stat()
        if not stat.S_ISBLK(device_info.st_mode) or os.major(device_info.st_rdev) != 7:
            raise SafetyError("expected an actual Linux loop block device")
        if table_label not in ("gpt", "dos"):
            raise SafetyError("fixture partition table must be GPT or DOS/MBR")
        partition_type = ""
        if lvm:
            partition_type = ",E6D6D379-F507-44C2-A23C-238F2A3DF928" if table_label == "gpt" else ",8e"
        self.runner.run("sfdisk", loop.device,
                        input=f"label: {table_label}\n,{size_mib}MiB{partition_type}\n")
        self.runner.run("partx", "--update", loop.device)
        partition = loop.device + "p1"
        wait_block(partition)
        sys_path = Path("/sys/class/block") / Path(partition).name
        if not (sys_path / "partition").is_file() or sys_path.resolve().parent.name != Path(loop.device).name:
            raise SafetyError("partition parent identity could not be verified")
        self.check_loop(loop)
        return partition

    def create_vg(self, loop: Loop, partition: str, name: str,
                  pv_size_mib: int | None = None) -> str:
        self.check_loop(loop)
        if partition != loop.device + "p1" or re.fullmatch(r"lsmtest[a-f0-9]+", name) is None:
            raise SafetyError("invalid disposable PV or VG")
        if self.vg_rows(name):
            raise SafetyError(f"refusing existing VG: {name}")
        if pv_size_mib is None:
            self.runner.run("pvcreate", "--yes", partition)
        else:
            if pv_size_mib <= 0:
                raise SafetyError("limited disposable PV size must be positive")
            self.runner.run(
                "pvcreate", "--yes", "--setphysicalvolumesize",
                f"{pv_size_mib}MiB", partition
            )
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

    def track_artifact(self, path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.parent.resolve(strict=True) != self.root:
            raise SafetyError("recovery artifact is not a regular file owned by the harness")
        self.artifacts.append((path, (info.st_dev, info.st_ino)))

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
        for artifact, inode in self.artifacts:
            if not artifact.exists():
                continue
            info = artifact.lstat()
            if (not stat.S_ISREG(info.st_mode)
                    or artifact.parent.resolve(strict=True) != self.root
                    or (info.st_dev, info.st_ino) != inode):
                raise SafetyError(f"recovery artifact identity changed: {artifact}")
            artifact.unlink()
        # rmdir fails on unexpected contents; no recursive deletion, even on error.
        for directory in reversed(self.directories):
            directory.rmdir()
        for image in self.images:
            image.unlink()
        self.root.rmdir()


def partition_table_facts(data: Any, loop_device: str, partition: str) -> dict[str, Any]:
    if re.fullmatch(r"/dev/loop[0-9]+", loop_device) is None or partition != loop_device + "p1":
        raise SafetyError("partition recovery fixture identity is not an owned loop p1")
    if not isinstance(data, dict) or not isinstance(data.get("partitiontable"), dict):
        raise SafetyError("sfdisk JSON lacks one partitiontable object")
    table = data["partitiontable"]
    if table.get("device") != loop_device or table.get("label") not in ("gpt", "dos"):
        raise SafetyError("sfdisk JSON does not identify the expected GPT/DOS loop table")
    if table.get("unit") != "sectors" or not isinstance(table.get("sectorsize"), int):
        raise SafetyError("sfdisk JSON does not expose sector geometry")
    if table["sectorsize"] < 512 or table["sectorsize"] & (table["sectorsize"] - 1):
        raise SafetyError("invalid sector size in recovery fixture")
    partitions = table.get("partitions")
    if not isinstance(partitions, list) or len(partitions) != 1 or not isinstance(partitions[0], dict):
        raise SafetyError("partition recovery drill requires exactly one partition")
    record = partitions[0]
    if record.get("node") != partition:
        raise SafetyError("partition recovery fixture node identity changed")
    if not isinstance(record.get("start"), int) or not isinstance(record.get("size"), int):
        raise SafetyError("partition recovery fixture lacks numeric geometry")
    if record["start"] <= 0 or record["size"] <= 0 or not isinstance(record.get("type"), str):
        raise SafetyError("partition recovery fixture geometry/type is invalid")
    return {
        "label": table["label"],
        "id": table.get("id"),
        "device": table["device"],
        "unit": table["unit"],
        "firstlba": table.get("firstlba"),
        "lastlba": table.get("lastlba"),
        "sectorsize": table["sectorsize"],
        "partitions": [{
            "node": record["node"],
            "start": record["start"],
            "size": record["size"],
            "type": record["type"],
            "uuid": record.get("uuid"),
            "name": record.get("name"),
            "attrs": record.get("attrs"),
            "bootable": record.get("bootable"),
        }],
    }


def growth_only_partition_script(facts: dict[str, Any], disk_sectors: int,
                                 growth_sectors: int = 8192) -> tuple[str, int]:
    partitions = facts.get("partitions")
    if not isinstance(partitions, list) or len(partitions) != 1:
        raise SafetyError("cannot build recovery mutation from ambiguous partition facts")
    record = partitions[0]
    start, size = record.get("start"), record.get("size")
    partition_type = record.get("type")
    if (facts.get("label") not in ("gpt", "dos") or not isinstance(start, int)
            or not isinstance(size, int) or not isinstance(partition_type, str)
            or growth_sectors <= 0 or disk_sectors <= 0):
        raise SafetyError("cannot build recovery mutation from invalid geometry")
    new_size = size + growth_sectors
    # Keep a guard region at the end of the disposable loop. The recovery drill
    # changes only the partition end; moving the start is never exercised.
    if start + new_size + 2048 >= disk_sectors:
        raise SafetyError("disposable recovery fixture has insufficient guarded tail capacity")
    script = (
        f"label: {facts['label']}\n"
        "unit: sectors\n"
        f"{start},{new_size},{partition_type}\n"
    )
    return script, new_size


def assert_owned_mount(binary: Runner, mount: Mount) -> None:
    current = binary.run("findmnt", "--json", "--mountpoint", str(mount.target),
                         "--output", "SOURCE,TARGET", allowed=(0, 1))
    if current.returncode != 0:
        raise SafetyError("expected disposable recovery mount is absent")
    entries = mount_rows(json.loads(current.stdout))
    if (len(entries) != 1 or entries[0]["target"] != str(mount.target)
            or not isinstance(entries[0].get("source"), str)
            or os.path.realpath(entries[0]["source"]) != os.path.realpath(mount.source)):
        raise SafetyError("disposable recovery mount ownership changed")


def exercise_partition_table_recovery(resources: Resources, binary: Runner,
                                      table_label: str) -> None:
    if table_label not in ("gpt", "dos"):
        raise SafetyError("recovery drill table label must be GPT or DOS/MBR")
    label = f"recovery-{table_label}"
    loop = resources.create_loop(label, 256 * 1024 * 1024)
    partition = resources.create_partition(loop, 128, False, table_label=table_label)
    binary.run("mkfs.ext4", "-F", partition)
    refresh_fixture_udev(binary, Path(partition).name)
    target = resources.mount(partition, label + "-mount")
    tracked_mount = resources.mounts[-1]
    assert_owned_mount(binary, tracked_mount)
    sentinel = (target / "readonly-sentinel").read_bytes()

    resources.check_loop(loop)
    baseline = partition_table_facts(
        binary.json("sfdisk", "--json", loop.device), loop.device, partition
    )
    backup = binary.run("sfdisk", "--dump", loop.device).stdout
    if not backup.strip() or loop.device not in backup:
        raise SafetyError("partition-table backup artifact is empty or lacks target identity")
    backup_path = resources.root / f"{label}-partition-table.sfdisk"
    backup_path.write_text(backup)
    resources.track_artifact(backup_path)
    if backup_path.read_text() != backup:
        raise SafetyError("partition-table backup artifact is not readable byte-for-byte")

    binary.run("umount", str(target))
    absent = binary.run("findmnt", "--json", "--mountpoint", str(target),
                        "--output", "SOURCE,TARGET", allowed=(0, 1))
    if absent.returncode != 1 or absent.stdout.strip() or absent.stderr.strip():
        raise SafetyError("disposable recovery filesystem did not unmount cleanly")

    resources.check_loop(loop)
    disk_sectors = loop.image.stat().st_size // baseline["sectorsize"]
    mutation_script, expected_size = growth_only_partition_script(baseline, disk_sectors)

    # From here until exact restoration + sentinel verification, ambiguity retains
    # the owned fixture instead of attempting automatic cleanup.
    resources.uncertain = True
    binary.run("sfdisk", loop.device, input=mutation_script)
    binary.run("partx", "--update", loop.device)
    binary.run("udevadm", "settle", "--timeout=30")
    wait_block(partition)
    resources.check_loop(loop)
    mutated = partition_table_facts(
        binary.json("sfdisk", "--json", loop.device), loop.device, partition
    )
    before_record, mutated_record = baseline["partitions"][0], mutated["partitions"][0]
    if mutated_record["start"] != before_record["start"] or mutated_record["size"] != expected_size:
        raise SafetyError("controlled recovery mutation moved the start or has unexpected size")
    if mutated == baseline:
        raise SafetyError("partition-table recovery mutation did not change authoritative facts")

    restore_input = backup_path.read_text()
    binary.run("sfdisk", loop.device, input=restore_input)
    binary.run("partx", "--update", loop.device)
    binary.run("udevadm", "settle", "--timeout=30")
    wait_block(partition)
    resources.check_loop(loop)
    restored = partition_table_facts(
        binary.json("sfdisk", "--json", loop.device), loop.device, partition
    )
    if restored != baseline:
        evidence = json.dumps({"before": baseline, "restored": restored}, sort_keys=True)
        raise SafetyError("partition-table recovery did not restore exact geometry: " + evidence)

    binary.run("mount", partition, str(target))
    assert_owned_mount(binary, tracked_mount)
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("filesystem sentinel changed across partition-table recovery drill")

    backup_path.unlink()
    resources.uncertain = False


def _normalized_report_row(row: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    normalized = {}
    for key in keys:
        value = row.get(key)
        normalized[key] = value.strip() if isinstance(value, str) else value
    return normalized


def lvm_metadata_facts(binary: Runner, vg_name: str, pv_path: str) -> dict[str, Any]:
    if re.fullmatch(r"lsmtest[a-f0-9]+", vg_name) is None:
        raise SafetyError("LVM recovery drill requires a harness-owned VG name")
    reports = {
        "vg": rows(
            binary.json(
                "vgs", "--reportformat", "json", "--units", "b", "--nosuffix",
                "--options", "vg_name,vg_uuid,vg_size,vg_free,pv_count,lv_count",
                "--select", f"vg_name={vg_name}",
            ),
            "report", "vg",
        ),
        "pv": rows(
            binary.json(
                "pvs", "--reportformat", "json", "--units", "b", "--nosuffix",
                "--options", "pv_name,pv_uuid,vg_name,vg_uuid,pv_size,pv_free",
                "--select", f"vg_name={vg_name}",
            ),
            "report", "pv",
        ),
        "lv": rows(
            binary.json(
                "lvs", "--reportformat", "json", "--units", "b", "--nosuffix",
                "--options", "lv_name,lv_uuid,vg_name,vg_uuid,lv_size,segtype",
                "--select", f"vg_name={vg_name}",
            ),
            "report", "lv",
        ),
    }
    if any(len(reports[key]) != 1 for key in ("vg", "pv", "lv")):
        raise SafetyError("LVM recovery drill requires exactly one VG, PV and LV")
    vg = _normalized_report_row(
        reports["vg"][0],
        ("vg_name", "vg_uuid", "vg_size", "vg_free", "pv_count", "lv_count"),
    )
    pv = _normalized_report_row(
        reports["pv"][0],
        ("pv_name", "pv_uuid", "vg_name", "vg_uuid", "pv_size", "pv_free"),
    )
    lv = _normalized_report_row(
        reports["lv"][0],
        ("lv_name", "lv_uuid", "vg_name", "vg_uuid", "lv_size", "segtype"),
    )
    if vg["vg_name"] != vg_name or pv["vg_name"] != vg_name or lv["vg_name"] != vg_name:
        raise SafetyError("LVM recovery report escaped the owned VG")
    if not isinstance(vg["vg_uuid"], str) or not vg["vg_uuid"]:
        raise SafetyError("LVM recovery VG UUID is unavailable")
    if pv["vg_uuid"] != vg["vg_uuid"] or lv["vg_uuid"] != vg["vg_uuid"]:
        raise SafetyError("LVM recovery report disagrees on VG UUID")
    if os.path.realpath(str(pv["pv_name"])) != os.path.realpath(pv_path):
        raise SafetyError("LVM recovery PV identity changed")
    if not isinstance(pv["pv_uuid"], str) or not pv["pv_uuid"]:
        raise SafetyError("LVM recovery PV UUID is unavailable")
    if not isinstance(lv["lv_uuid"], str) or not lv["lv_uuid"]:
        raise SafetyError("LVM recovery LV UUID is unavailable")
    return {"vg": vg, "pv": pv, "lv": lv}


def assert_only_lv_name_changed(baseline: dict[str, Any], mutated: dict[str, Any],
                                expected_name: str) -> None:
    if mutated["vg"] != baseline["vg"] or mutated["pv"] != baseline["pv"]:
        raise SafetyError("controlled LVM recovery mutation changed VG/PV identity or capacity")
    expected_lv = dict(baseline["lv"])
    expected_lv["lv_name"] = expected_name
    if mutated["lv"] != expected_lv:
        raise SafetyError("controlled LVM recovery mutation changed more than the LV name")


def exercise_lvm_metadata_recovery(resources: Resources, binary: Runner) -> None:
    label = "recovery-lvm"
    loop = resources.create_loop(label, 768 * 1024 * 1024)
    partition = resources.create_partition(loop, 640, True)
    vg_name = "lsmtest" + os.urandom(12).hex()
    source = resources.create_vg(loop, partition, vg_name)
    group = resources.groups[-1]
    if group.uuid is None:
        raise SafetyError("LVM recovery fixture lacks the tracked VG UUID")

    binary.run("mkfs.ext4", "-F", source)
    refresh_fixture_udev(binary, Path(source).resolve(strict=True).name)
    target = resources.mount(source, label + "-mount")
    tracked_mount = resources.mounts[-1]
    assert_owned_mount(binary, tracked_mount)
    sentinel = (target / "readonly-sentinel").read_bytes()

    resources.check_loop(loop)
    baseline = lvm_metadata_facts(binary, vg_name, partition)
    if baseline["vg"]["vg_uuid"] != group.uuid:
        raise SafetyError("tracked VG UUID disagrees with recovery baseline")

    backup_path = resources.root / f"{label}-vgcfgbackup.conf"
    binary.run("vgcfgbackup", "--file", str(backup_path), vg_name)
    if not backup_path.is_file() or backup_path.stat().st_size == 0:
        raise SafetyError("LVM metadata backup artifact is absent or empty")
    resources.track_artifact(backup_path)
    backup_text = backup_path.read_text()
    if vg_name not in backup_text or group.uuid not in backup_text:
        raise SafetyError("LVM metadata backup artifact lacks frozen VG identity")

    binary.run("umount", str(target))
    absent = binary.run("findmnt", "--json", "--mountpoint", str(target),
                        "--output", "SOURCE,TARGET", allowed=(0, 1))
    if absent.returncode != 1 or absent.stdout.strip() or absent.stderr.strip():
        raise SafetyError("disposable LVM recovery filesystem did not unmount cleanly")

    resources.check_loop(loop)
    binary.run("vgchange", "-an", vg_name)
    binary.run("vgcfgrestore", "--test", "--file", str(backup_path), vg_name)
    binary.run("vgchange", "-ay", vg_name)
    binary.run("udevadm", "settle", "--timeout=30")
    wait_block(source)

    resources.uncertain = True
    binary.run("lvrename", vg_name, "data", "data_mutated")
    binary.run("udevadm", "settle", "--timeout=30")
    mutated = lvm_metadata_facts(binary, vg_name, partition)
    assert_only_lv_name_changed(baseline, mutated, "data_mutated")

    binary.run("vgchange", "-an", vg_name)
    binary.run("vgcfgrestore", "--file", str(backup_path), vg_name)
    binary.run("vgchange", "-ay", vg_name)
    binary.run("udevadm", "settle", "--timeout=30")
    wait_block(source)
    resources.check_loop(loop)

    restored = lvm_metadata_facts(binary, vg_name, partition)
    if restored != baseline:
        evidence = json.dumps({"before": baseline, "restored": restored}, sort_keys=True)
        raise SafetyError("LVM metadata recovery did not restore exact identity: " + evidence)

    binary.run("mount", source, str(target))
    assert_owned_mount(binary, tracked_mount)
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("filesystem sentinel changed across LVM metadata recovery drill")

    backup_path.unlink()
    resources.uncertain = False


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
        has_lvm_change = isinstance(lvm_change, dict)
        has_partition_change = isinstance(partition_change, dict)
        if (not (has_lvm_change or has_partition_change)
                or not plan.get("steps") or plan.get("blockers") != []):
            raise SafetyError("preview must contain a size change and no blockers")
        if has_lvm_change and has_partition_change:
            operations = [
                operation.get("operation")
                for step in plan["steps"]
                if isinstance(step, dict)
                for operation in [step.get("operation")]
                if isinstance(operation, dict)
            ]
            required = [
                "extend_partition",
                "resize_physical_volume",
                "extend_logical_volume",
                "grow_filesystem",
                "rediscover_and_verify",
            ]
            if any(operation not in operations for operation in required):
                raise SafetyError(
                    "combined partition/LVM preview lacks the exact chained growth operations"
                )
        if has_lvm_change:
            extent = lvm_change.get("extent_size_bytes")
            growth = lvm_change.get("rounded_growth_bytes")
            if (type(extent) is not int or extent <= 0 or type(growth) is not int or growth <= 0
                    or growth % extent or growth < lvm_change["requested_growth_bytes"]
                    or lvm_change["current_lv_size_bytes"] + growth
                    != lvm_change["expected_lv_size_bytes"]):
                raise SafetyError("inconsistent LVM preview size arithmetic")
        if has_partition_change:
            sector = partition_change.get("sector_size_bytes")
            growth = partition_change.get("rounded_growth_bytes")
            if (type(sector) is not int or sector <= 0 or type(growth) is not int or growth <= 0
                    or growth % sector or growth < partition_change["requested_growth_bytes"]
                    or partition_change["current_partition_size_bytes"] + growth
                    != partition_change["expected_partition_size_bytes"]):
                raise SafetyError("inconsistent partition preview size arithmetic")


def remove_owned_evidence_directory(resources: Resources, path: Path) -> None:
    if path.parent.resolve(strict=True) != resources.root or path.is_symlink() or not path.is_dir():
        raise SafetyError(f"refusing cleanup of unowned evidence directory: {path}")
    for entry in path.iterdir():
        info = entry.lstat()
        if entry.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise SafetyError(f"unexpected non-file in evidence directory: {entry}")
        entry.unlink()
    path.rmdir()


def exercise_disposable_pre_spawn_failure(resources: Resources, binary: Runner, loop: Loop,
                                          source: str, target: Path, vg: str) -> None:
    resources.check_loop(loop)
    before = ready_snapshot(binary, loop.device, vg)
    lvs = [row for row in before["lvm"]["logical_volumes"]
           if row.get("vg_name") == vg and row.get("path") == source]
    vgs = [row for row in before["lvm"]["volume_groups"]
           if row.get("name") == vg]
    if len(lvs) != 1 or len(vgs) != 1:
        raise SafetyError("fault-injection LV/VG identity is ambiguous")
    current_lv_size = lvs[0].get("size_bytes")
    extent = vgs[0].get("extent_size_bytes")
    if type(current_lv_size) is not int or type(extent) is not int or extent <= 0:
        raise SafetyError("fault-injection LVM size evidence is incomplete")

    sentinel = (target / "readonly-sentinel").read_bytes()
    before_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    association_row = binary.run(
        "losetup", "--list", "--noheadings", "--output", "NAME,BACK-FILE", loop.device
    ).stdout.strip()
    journal_root = resources.root / f"{vg}-fault-journal"
    backup_root = resources.root / f"{vg}-fault-backup"
    args = (
        "--allow-disposable-loop-execution",
        "--target", str(target),
        "--loop-device", loop.device,
        "--backing-file", str(loop.image),
        "--owned-root", str(resources.root),
        "--association-row", association_row,
        "--journal-root", str(journal_root),
        "--backup-root", str(backup_root),
        "--growth-bytes", str(8 * extent),
        "--sfdisk", binary.tools["sfdisk"],
        "--partx", binary.tools["partx"],
        "--pvresize", binary.tools["pvresize"],
        "--lvextend", "/usr/bin/false",
        "--resize2fs", binary.tools["resize2fs"],
        "--xfs-growfs", binary.tools["xfs_growfs"],
        "--xfs-scrub", binary.tools["xfs_scrub"],
        "--udevadm", binary.tools["udevadm"],
    )

    resources.uncertain = True
    failed = binary.run("disposable-executor", *args, allowed=(1,))
    if "selected disposable tool path is unsafe for Lvextend" not in failed.stderr:
        raise SafetyError(f"unexpected pre-spawn fault result: {failed.stderr!r}")

    journals = list(journal_root.glob("*.json"))
    if len(journals) != 1:
        raise SafetyError("fault injection did not retain exactly one durable journal")
    journal_bytes = journals[0].read_bytes()
    journal = json.loads(journal_bytes)
    events = journal.get("events")
    if (journal.get("phase") != "recovery_required"
            or journal.get("mutation_may_have_started") is not True
            or not isinstance(journal.get("execution"), dict)
            or not isinstance(events, list) or not events
            or events[-1].get("code") != "interrupted-after-mutation-boundary"):
        raise SafetyError(f"fault journal did not enter RecoveryRequired: {journal!r}")

    unchanged = ready_snapshot(binary, loop.device, vg)
    unchanged_lvs = [row for row in unchanged["lvm"]["logical_volumes"]
                     if row.get("vg_name") == vg and row.get("path") == source]
    if len(unchanged_lvs) != 1 or unchanged_lvs[0].get("size_bytes") != current_lv_size:
        raise SafetyError("pre-spawn failure changed LV size")
    if os.statvfs(target).f_blocks * os.statvfs(target).f_frsize != before_fs_bytes:
        raise SafetyError("pre-spawn failure changed filesystem capacity")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("pre-spawn failure changed filesystem sentinel")

    replay_args = list(args)
    replay_args[replay_args.index("/usr/bin/false")] = binary.tools["lvextend"]
    replay = binary.run("disposable-executor", *replay_args, allowed=(1,))
    if "journal root already exists" not in replay.stderr:
        raise SafetyError(f"replay was not blocked by retained durable evidence: {replay.stderr!r}")
    if journals[0].read_bytes() != journal_bytes:
        raise SafetyError("blocked replay changed the retained recovery journal")

    remove_owned_evidence_directory(resources, backup_root)
    remove_owned_evidence_directory(resources, journal_root)
    resources.uncertain = False
    print("DISPOSABLE_RECOVERY_REQUIRED_OK=pre-spawn-failure-no-storage-change", flush=True)


def exercise_partition_post_write_recovery(
    resources: Resources, binary: Runner, loop: Loop, partition: str,
    source: str, target: Path, vg: str, table_label: str,
) -> None:
    resources.check_loop(loop)
    if partition != loop.device + "p1" or source != f"/dev/{vg}/data":
        raise SafetyError("unexpected partition recovery-boundary identity")
    if table_label not in ("gpt", "dos"):
        raise SafetyError("unsupported partition recovery-boundary table")

    before = ready_snapshot(binary, loop.device, vg)
    tables = [table for table in before["partition_tables"] if table.get("device") == loop.device]
    if len(tables) != 1 or tables[0].get("label") != table_label:
        raise SafetyError("partition recovery-boundary table identity is ambiguous")
    table = tables[0]
    records = [row for row in table.get("partitions", []) if row.get("node") == partition]
    if len(records) != 1:
        raise SafetyError("partition recovery-boundary record is ambiguous")
    record = records[0]
    sector = table.get("sector_size_bytes")
    start_sector = record.get("start_sector")
    current_size_sectors = record.get("size_sectors")
    if (type(sector) is not int or type(start_sector) is not int
            or type(current_size_sectors) is not int or sector <= 0
            or current_size_sectors <= 0):
        raise SafetyError("partition recovery-boundary geometry is incomplete")

    lvm = before.get("lvm")
    if not isinstance(lvm, dict):
        raise SafetyError("LVM inventory missing before partition recovery-boundary drill")
    pvs = [row for row in lvm.get("physical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("name") == partition]
    vgs = [row for row in lvm.get("volume_groups", [])
           if isinstance(row, dict) and row.get("name") == vg]
    if len(pvs) != 1 or len(vgs) != 1:
        raise SafetyError("PV/VG identity is ambiguous before partition recovery-boundary drill")
    current_pv_size = pvs[0].get("size_bytes")
    pe_start_bytes = pvs[0].get("pe_start_bytes")
    extent = vgs[0].get("extent_size_bytes")
    free_extents = vgs[0].get("free_extent_count")
    if (type(current_pv_size) is not int or type(pe_start_bytes) is not int
            or type(extent) is not int or type(free_extents) is not int
            or pe_start_bytes < 0 or extent <= 0 or free_extents < 0):
        raise SafetyError("partition recovery-boundary LVM geometry is incomplete")

    growth_bytes = 320 * 1024 * 1024
    if growth_bytes % extent:
        raise SafetyError("partition recovery-boundary growth is not extent aligned")
    growth_extents = growth_bytes // extent
    if growth_extents <= free_extents:
        raise SafetyError("partition recovery-boundary drill would not require partition growth")

    required_pv_growth_bytes = (growth_extents - free_extents) * extent
    current_partition_size_bytes = current_size_sectors * sector
    if current_partition_size_bytes < pe_start_bytes:
        raise SafetyError("PV PE start exceeds partition before recovery-boundary drill")
    usable_backing_bytes = current_partition_size_bytes - pe_start_bytes
    if usable_backing_bytes < current_pv_size:
        raise SafetyError("PV exceeds usable partition backing before recovery-boundary drill")
    pv_device_slack_bytes = usable_backing_bytes - current_pv_size
    raw_partition_growth_bytes = max(0, required_pv_growth_bytes - pv_device_slack_bytes)
    required_partition_growth_bytes = (
        (raw_partition_growth_bytes + sector - 1) // sector
    ) * sector
    if required_partition_growth_bytes <= 0:
        raise SafetyError("recovery-boundary drill unexpectedly fits current partition")

    expected_size_sectors = (
        current_partition_size_bytes + required_partition_growth_bytes
    ) // sector
    baseline_disk_facts = partition_table_facts(
        binary.json("sfdisk", "--json", loop.device), loop.device, partition
    )
    baseline_lvm = lvm_metadata_facts(binary, vg, partition)
    sentinel = (target / "readonly-sentinel").read_bytes()
    before_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    association_row = binary.run(
        "losetup", "--list", "--noheadings", "--output", "NAME,BACK-FILE", loop.device
    ).stdout.strip()
    if not association_row:
        raise SafetyError("loop association missing before partition recovery-boundary drill")

    journal_root = resources.root / f"{vg}-{table_label}-post-write-fault-journal"
    backup_root = resources.root / f"{vg}-{table_label}-post-write-fault-backup"
    args = (
        "--allow-disposable-loop-execution",
        "--target", str(target),
        "--loop-device", loop.device,
        "--backing-file", str(loop.image),
        "--owned-root", str(resources.root),
        "--association-row", association_row,
        "--journal-root", str(journal_root),
        "--backup-root", str(backup_root),
        "--growth-bytes", str(growth_bytes),
        "--sfdisk", binary.tools["sfdisk"],
        "--partx", "/usr/bin/false",
        "--pvresize", binary.tools["pvresize"],
        "--lvextend", binary.tools["lvextend"],
        "--resize2fs", binary.tools["resize2fs"],
        "--xfs-growfs", binary.tools["xfs_growfs"],
        "--xfs-scrub", binary.tools["xfs_scrub"],
        "--udevadm", binary.tools["udevadm"],
    )

    resources.uncertain = True
    failed = binary.run("disposable-executor", *args, allowed=(1,))
    if "selected disposable tool path is unsafe for Partx" not in failed.stderr:
        raise SafetyError(f"unexpected post-write fault result: {failed.stderr!r}")

    journals = list(journal_root.glob("*.json"))
    if len(journals) != 1:
        raise SafetyError("post-write fault did not retain exactly one durable journal")
    journal_bytes = journals[0].read_bytes()
    journal = json.loads(journal_bytes)
    events = journal.get("events")
    if (journal.get("phase") != "recovery_required"
            or journal.get("mutation_may_have_started") is not True
            or not isinstance(journal.get("execution"), dict)
            or not isinstance(events, list) or not events
            or events[-1].get("code") != "interrupted-after-mutation-boundary"):
        raise SafetyError(f"post-write fault journal did not require recovery: {journal!r}")

    disk_facts = partition_table_facts(
        binary.json("sfdisk", "--json", loop.device), loop.device, partition
    )
    before_record = baseline_disk_facts["partitions"][0]
    changed_record = disk_facts["partitions"][0]
    if (disk_facts.get("label") != baseline_disk_facts.get("label")
            or disk_facts.get("id") != baseline_disk_facts.get("id")
            or changed_record.get("start") != before_record.get("start")
            or changed_record.get("size") != expected_size_sectors):
        raise SafetyError("post-write fault did not leave the exact approved on-disk geometry")
    for key in ("type", "uuid", "name", "attrs", "bootable"):
        if changed_record.get(key) != before_record.get(key):
            raise SafetyError(f"post-write fault changed partition metadata field: {key}")

    if lvm_metadata_facts(binary, vg, partition) != baseline_lvm:
        raise SafetyError("post-write fault changed PV/VG/LV metadata before pvresize")
    if os.statvfs(target).f_blocks * os.statvfs(target).f_frsize != before_fs_bytes:
        raise SafetyError("post-write fault changed filesystem capacity")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("post-write fault changed filesystem sentinel")

    replay_args = list(args)
    replay_args[replay_args.index("/usr/bin/false")] = binary.tools["partx"]
    replay = binary.run("disposable-executor", *replay_args, allowed=(1,))
    if "journal root already exists" not in replay.stderr:
        raise SafetyError(f"post-write replay was not blocked: {replay.stderr!r}")
    if journals[0].read_bytes() != journal_bytes:
        raise SafetyError("blocked post-write replay changed retained recovery evidence")

    binary.run("partx", "--update", "--nr", "1", loop.device)
    binary.run("udevadm", "settle", "--timeout=30")
    wait_block(partition)
    reconciled = ready_snapshot(binary, loop.device, vg)
    reconciled_tables = [
        item for item in reconciled["partition_tables"] if item.get("device") == loop.device
    ]
    if len(reconciled_tables) != 1:
        raise SafetyError("post-write reconciliation lost partition-table identity")
    reconciled_records = [
        row for row in reconciled_tables[0].get("partitions", []) if row.get("node") == partition
    ]
    if (len(reconciled_records) != 1
            or reconciled_records[0].get("start_sector") != start_sector
            or reconciled_records[0].get("size_sectors") != expected_size_sectors):
        raise SafetyError("post-write reconciliation did not converge on exact geometry")
    if lvm_metadata_facts(binary, vg, partition) != baseline_lvm:
        raise SafetyError("post-write reconciliation changed PV/VG/LV metadata")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("post-write reconciliation changed filesystem sentinel")

    remove_owned_evidence_directory(resources, backup_root)
    remove_owned_evidence_directory(resources, journal_root)
    resources.uncertain = False
    print(
        f"PARTITION_RECOVERY_REQUIRED_OK={table_label}-post-write-pre-kernel-refresh",
        flush=True,
    )


def exercise_partition_pv_lvm_growth_mutation(
    resources: Resources, binary: Runner, loop: Loop, partition: str,
    source: str, target: Path, vg: str, table_label: str,
) -> None:
    resources.check_loop(loop)
    if partition != loop.device + "p1" or source != f"/dev/{vg}/data":
        raise SafetyError("unexpected disposable partition/PV/LV identity")
    if table_label not in ("gpt", "dos"):
        raise SafetyError("unsupported disposable partition table")

    before = ready_snapshot(binary, loop.device, vg)
    tables = [table for table in before["partition_tables"] if table.get("device") == loop.device]
    if len(tables) != 1 or tables[0].get("label") != table_label:
        raise SafetyError("partition table identity is ambiguous before partition growth")
    table = tables[0]
    records = [row for row in table.get("partitions", []) if row.get("node") == partition]
    if len(records) != 1:
        raise SafetyError("target partition record is ambiguous before growth")
    record = records[0]
    sector = table.get("sector_size_bytes")
    start_sector = record.get("start_sector")
    current_size_sectors = record.get("size_sectors")
    if (type(sector) is not int or type(start_sector) is not int
            or type(current_size_sectors) is not int or sector <= 0
            or current_size_sectors <= 0):
        raise SafetyError("partition geometry is incomplete before growth")

    preserved_table_id = table.get("id")
    preserved_record = {
        key: record.get(key)
        for key in ("partition_type", "uuid", "name", "attrs", "bootable")
    }

    lvm = before.get("lvm")
    if not isinstance(lvm, dict):
        raise SafetyError("LVM inventory missing before partition mutation drill")
    pvs = [row for row in lvm.get("physical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("name") == partition]
    vgs = [row for row in lvm.get("volume_groups", [])
           if isinstance(row, dict) and row.get("name") == vg]
    lvs = [row for row in lvm.get("logical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("path") == source]
    if len(pvs) != 1 or len(vgs) != 1 or len(lvs) != 1:
        raise SafetyError("partition/PV/VG/LV identity is ambiguous before growth")

    current_pv_size = pvs[0].get("size_bytes")
    pe_start_bytes = pvs[0].get("pe_start_bytes")
    current_lv_size = lvs[0].get("size_bytes")
    extent = vgs[0].get("extent_size_bytes")
    free_extents = vgs[0].get("free_extent_count")
    if (type(current_pv_size) is not int or type(pe_start_bytes) is not int
            or type(current_lv_size) is not int or type(extent) is not int
            or type(free_extents) is not int or pe_start_bytes < 0
            or extent <= 0 or free_extents < 0):
        raise SafetyError("exact partition/PV/VG/LV size evidence is incomplete")

    growth_bytes = 320 * 1024 * 1024
    if growth_bytes % extent:
        raise SafetyError("partition growth drill size is not extent aligned")
    growth_extents = growth_bytes // extent
    if growth_extents <= free_extents:
        raise SafetyError("partition growth drill would not require underlying capacity")

    additional_pv_extents = growth_extents - free_extents
    required_pv_growth_bytes = additional_pv_extents * extent
    current_partition_size_bytes = current_size_sectors * sector
    if current_partition_size_bytes < pe_start_bytes:
        raise SafetyError("PV PE start exceeds the partition before growth")
    usable_backing_bytes = current_partition_size_bytes - pe_start_bytes
    if usable_backing_bytes < current_pv_size:
        raise SafetyError("PV is larger than its usable partition backing before growth")
    pv_device_slack_bytes = usable_backing_bytes - current_pv_size
    raw_partition_growth_bytes = max(0, required_pv_growth_bytes - pv_device_slack_bytes)
    required_partition_growth_bytes = (
        (raw_partition_growth_bytes + sector - 1) // sector
    ) * sector
    if required_partition_growth_bytes <= 0:
        raise SafetyError("partition growth drill unexpectedly fits inside current partition")

    expected_partition_size_bytes = current_partition_size_bytes + required_partition_growth_bytes
    expected_partition_size_sectors = expected_partition_size_bytes // sector
    expected_pv_size = current_pv_size + required_pv_growth_bytes
    expected_lv_size = current_lv_size + growth_extents * extent

    sentinel = (target / "readonly-sentinel").read_bytes()
    before_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    association_row = binary.run(
        "losetup", "--list", "--noheadings", "--output", "NAME,BACK-FILE", loop.device
    ).stdout.strip()
    if not association_row:
        raise SafetyError("exact loop association row is unavailable before partition execution")

    journal_root = resources.root / f"{vg}-{table_label}-partition-executor-journal"
    backup_root = resources.root / f"{vg}-{table_label}-partition-executor-backup"
    resources.uncertain = True
    result = binary.run(
        "disposable-executor",
        "--allow-disposable-loop-execution",
        "--target", str(target),
        "--loop-device", loop.device,
        "--backing-file", str(loop.image),
        "--owned-root", str(resources.root),
        "--association-row", association_row,
        "--journal-root", str(journal_root),
        "--backup-root", str(backup_root),
        "--growth-bytes", str(growth_bytes),
        "--sfdisk", binary.tools["sfdisk"],
        "--partx", binary.tools["partx"],
        "--pvresize", binary.tools["pvresize"],
        "--lvextend", binary.tools["lvextend"],
        "--resize2fs", binary.tools["resize2fs"],
        "--xfs-growfs", binary.tools["xfs_growfs"],
        "--xfs-scrub", binary.tools["xfs_scrub"],
        "--udevadm", binary.tools["udevadm"],
    )
    outcome = json.loads(result.stdout)
    if (not isinstance(outcome, dict) or outcome.get("status") != "completed"
            or outcome.get("mutation_enabled") is not False
            or not isinstance(outcome.get("execution_id"), str)
            or not isinstance(outcome.get("final_identity_digest"), str)):
        raise SafetyError(f"invalid partition executor completion evidence: {outcome!r}")

    final = ready_snapshot(binary, loop.device, vg)
    final_tables = [table for table in final["partition_tables"] if table.get("device") == loop.device]
    if len(final_tables) != 1:
        raise SafetyError("partition table identity is ambiguous after execution")
    final_table = final_tables[0]
    final_records = [
        row for row in final_table.get("partitions", []) if row.get("node") == partition
    ]
    if len(final_records) != 1:
        raise SafetyError("target partition record is ambiguous after execution")
    final_record = final_records[0]
    if (final_table.get("label") != table_label
            or final_table.get("id") != preserved_table_id
            or final_table.get("sector_size_bytes") != sector
            or final_record.get("start_sector") != start_sector
            or final_record.get("size_sectors") != expected_partition_size_sectors):
        raise SafetyError("partition geometry does not match the exact approved resize")
    for key, expected in preserved_record.items():
        if final_record.get(key) != expected:
            raise SafetyError(f"partition field changed unexpectedly: {key}")

    final_lvm = final.get("lvm")
    if not isinstance(final_lvm, dict):
        raise SafetyError("LVM inventory missing after partition executor drill")
    final_pvs = [row for row in final_lvm.get("physical_volumes", [])
                 if isinstance(row, dict) and row.get("vg_name") == vg
                 and row.get("name") == partition]
    final_lvs = [row for row in final_lvm.get("logical_volumes", [])
                 if isinstance(row, dict) and row.get("vg_name") == vg
                 and row.get("path") == source]
    if len(final_pvs) != 1 or final_pvs[0].get("size_bytes") != expected_pv_size:
        raise SafetyError("PV size mismatch after partition -> PV Rust execution")
    if len(final_lvs) != 1 or final_lvs[0].get("size_bytes") != expected_lv_size:
        raise SafetyError("LV size mismatch after partition -> PV -> LV Rust execution")

    after_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    if after_fs_bytes <= before_fs_bytes:
        raise SafetyError("filesystem capacity did not increase after full chained growth")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("filesystem sentinel changed during full chained growth")
    if journal_root.exists() or backup_root.exists():
        raise SafetyError("partition executor did not clean its owned journal/backup artifacts")

    resources.uncertain = False
    print(
        f"PARTITION_PV_LV_FILESYSTEM_EXECUTOR_OK={table_label}-size-only-boundaries",
        flush=True,
    )


def exercise_pv_post_write_recovery(
    resources: Resources, binary: Runner, loop: Loop, partition: str,
    source: str, target: Path, vg: str,
) -> None:
    resources.check_loop(loop)
    if partition != loop.device + "p1" or source != f"/dev/{vg}/data":
        raise SafetyError("unexpected PV recovery-boundary identity")

    before = ready_snapshot(binary, loop.device, vg)
    lvm = before.get("lvm")
    if not isinstance(lvm, dict):
        raise SafetyError("LVM inventory missing before PV recovery-boundary drill")
    pvs = [row for row in lvm.get("physical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("name") == partition]
    vgs = [row for row in lvm.get("volume_groups", [])
           if isinstance(row, dict) and row.get("name") == vg]
    lvs = [row for row in lvm.get("logical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("path") == source]
    if len(pvs) != 1 or len(vgs) != 1 or len(lvs) != 1:
        raise SafetyError("PV/VG/LV identity is ambiguous before PV recovery-boundary drill")

    current_pv_size = pvs[0].get("size_bytes")
    current_pv_uuid = pvs[0].get("uuid")
    current_lv_size = lvs[0].get("size_bytes")
    current_lv_uuid = lvs[0].get("uuid")
    extent = vgs[0].get("extent_size_bytes")
    free_extents = vgs[0].get("free_extent_count")
    vg_uuid = vgs[0].get("uuid")
    if (type(current_pv_size) is not int or type(current_lv_size) is not int
            or type(extent) is not int or type(free_extents) is not int
            or extent <= 0 or free_extents < 0
            or not isinstance(current_pv_uuid, str) or not current_pv_uuid
            or not isinstance(current_lv_uuid, str) or not current_lv_uuid
            or not isinstance(vg_uuid, str) or not vg_uuid):
        raise SafetyError("PV recovery-boundary identity/size evidence is incomplete")

    growth_bytes = 384 * 1024 * 1024
    if growth_bytes % extent:
        raise SafetyError("PV recovery-boundary growth is not extent aligned")
    growth_extents = growth_bytes // extent
    if growth_extents <= free_extents:
        raise SafetyError("PV recovery-boundary drill would not require pvresize")
    additional_pv_extents = growth_extents - free_extents
    expected_pv_size = current_pv_size + additional_pv_extents * extent

    sentinel = (target / "readonly-sentinel").read_bytes()
    before_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    association_row = binary.run(
        "losetup", "--list", "--noheadings", "--output", "NAME,BACK-FILE", loop.device
    ).stdout.strip()
    if not association_row:
        raise SafetyError("loop association missing before PV recovery-boundary drill")

    journal_root = resources.root / f"{vg}-pv-post-write-fault-journal"
    backup_root = resources.root / f"{vg}-pv-post-write-fault-backup"
    args = (
        "--allow-disposable-loop-execution",
        "--target", str(target),
        "--loop-device", loop.device,
        "--backing-file", str(loop.image),
        "--owned-root", str(resources.root),
        "--association-row", association_row,
        "--journal-root", str(journal_root),
        "--backup-root", str(backup_root),
        "--growth-bytes", str(growth_bytes),
        "--sfdisk", binary.tools["sfdisk"],
        "--partx", binary.tools["partx"],
        "--pvresize", binary.tools["pvresize"],
        "--lvextend", "/usr/bin/false",
        "--resize2fs", binary.tools["resize2fs"],
        "--xfs-growfs", binary.tools["xfs_growfs"],
        "--xfs-scrub", binary.tools["xfs_scrub"],
        "--udevadm", binary.tools["udevadm"],
    )

    resources.uncertain = True
    failed = binary.run("disposable-executor", *args, allowed=(1,))
    if "selected disposable tool path is unsafe for Lvextend" not in failed.stderr:
        raise SafetyError(f"unexpected PV post-write fault result: {failed.stderr!r}")

    journals = list(journal_root.glob("*.json"))
    if len(journals) != 1:
        raise SafetyError("PV post-write fault did not retain exactly one durable journal")
    journal_bytes = journals[0].read_bytes()
    journal = json.loads(journal_bytes)
    events = journal.get("events")
    if (journal.get("phase") != "recovery_required"
            or journal.get("mutation_may_have_started") is not True
            or not isinstance(journal.get("execution"), dict)
            or not isinstance(events, list) or not events
            or events[-1].get("code") != "interrupted-after-mutation-boundary"):
        raise SafetyError(f"PV post-write fault journal did not require recovery: {journal!r}")

    reconciled = ready_snapshot(binary, loop.device, vg)
    reconciled_lvm = reconciled.get("lvm")
    if not isinstance(reconciled_lvm, dict):
        raise SafetyError("LVM inventory missing during PV recovery reconciliation")
    new_pvs = [row for row in reconciled_lvm.get("physical_volumes", [])
               if isinstance(row, dict) and row.get("vg_name") == vg and row.get("name") == partition]
    new_vgs = [row for row in reconciled_lvm.get("volume_groups", [])
               if isinstance(row, dict) and row.get("name") == vg]
    new_lvs = [row for row in reconciled_lvm.get("logical_volumes", [])
               if isinstance(row, dict) and row.get("vg_name") == vg and row.get("path") == source]
    if len(new_pvs) != 1 or len(new_vgs) != 1 or len(new_lvs) != 1:
        raise SafetyError("PV recovery reconciliation lost exact LVM identity")
    if (new_pvs[0].get("uuid") != current_pv_uuid
            or new_pvs[0].get("size_bytes") != expected_pv_size):
        raise SafetyError("PV recovery reconciliation did not prove exact resized PV state")
    if new_vgs[0].get("uuid") != vg_uuid:
        raise SafetyError("PV recovery reconciliation changed VG identity")
    if (new_lvs[0].get("uuid") != current_lv_uuid
            or new_lvs[0].get("size_bytes") != current_lv_size):
        raise SafetyError("PV recovery-boundary fault changed LV identity or size")
    if os.statvfs(target).f_blocks * os.statvfs(target).f_frsize != before_fs_bytes:
        raise SafetyError("PV recovery-boundary fault changed filesystem capacity")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("PV recovery-boundary fault changed filesystem sentinel")

    replay_args = list(args)
    replay_args[replay_args.index("/usr/bin/false")] = binary.tools["lvextend"]
    replay = binary.run("disposable-executor", *replay_args, allowed=(1,))
    if "journal root already exists" not in replay.stderr:
        raise SafetyError(f"PV post-write replay was not blocked: {replay.stderr!r}")
    if journals[0].read_bytes() != journal_bytes:
        raise SafetyError("blocked PV post-write replay changed retained recovery evidence")

    remove_owned_evidence_directory(resources, backup_root)
    remove_owned_evidence_directory(resources, journal_root)
    resources.uncertain = False
    print("PV_RECOVERY_REQUIRED_OK=post-pvresize-pre-lvextend", flush=True)


def exercise_pv_lvm_growth_mutation(resources: Resources, binary: Runner, loop: Loop,
                                    partition: str, source: str, target: Path,
                                    vg: str) -> None:
    resources.check_loop(loop)
    if partition != loop.device + "p1" or source != f"/dev/{vg}/data":
        raise SafetyError("unexpected disposable PV/LV identity")

    before = ready_snapshot(binary, loop.device, vg)
    lvm = before.get("lvm")
    if not isinstance(lvm, dict):
        raise SafetyError("LVM inventory missing before PV mutation drill")
    pvs = [row for row in lvm.get("physical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("name") == partition]
    vgs = [row for row in lvm.get("volume_groups", [])
           if isinstance(row, dict) and row.get("name") == vg]
    lvs = [row for row in lvm.get("logical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("path") == source]
    if len(pvs) != 1 or len(vgs) != 1 or len(lvs) != 1:
        raise SafetyError("disposable PV/VG/LV identity is ambiguous before PV growth")

    current_pv_size = pvs[0].get("size_bytes")
    current_lv_size = lvs[0].get("size_bytes")
    extent = vgs[0].get("extent_size_bytes")
    free_extents = vgs[0].get("free_extent_count")
    if (type(current_pv_size) is not int or type(current_lv_size) is not int
            or type(extent) is not int or type(free_extents) is not int
            or extent <= 0 or free_extents < 0):
        raise SafetyError("exact PV/VG/LV size evidence is incomplete")

    growth_bytes = 384 * 1024 * 1024
    if growth_bytes % extent:
        raise SafetyError("PV growth drill size is not extent aligned")
    growth_extents = growth_bytes // extent
    if growth_extents <= free_extents:
        raise SafetyError("PV growth drill would not require pvresize")
    additional_pv_extents = growth_extents - free_extents
    expected_pv_size = current_pv_size + additional_pv_extents * extent
    expected_lv_size = current_lv_size + growth_extents * extent

    sentinel = (target / "readonly-sentinel").read_bytes()
    before_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    association_row = binary.run(
        "losetup", "--list", "--noheadings", "--output", "NAME,BACK-FILE", loop.device
    ).stdout.strip()
    if not association_row:
        raise SafetyError("exact loop association row is unavailable before PV execution")

    journal_root = resources.root / f"{vg}-pv-executor-journal"
    backup_root = resources.root / f"{vg}-pv-executor-backup"
    resources.uncertain = True
    result = binary.run(
        "disposable-executor",
        "--allow-disposable-loop-execution",
        "--target", str(target),
        "--loop-device", loop.device,
        "--backing-file", str(loop.image),
        "--owned-root", str(resources.root),
        "--association-row", association_row,
        "--journal-root", str(journal_root),
        "--backup-root", str(backup_root),
        "--growth-bytes", str(growth_bytes),
        "--sfdisk", binary.tools["sfdisk"],
        "--partx", binary.tools["partx"],
        "--pvresize", binary.tools["pvresize"],
        "--lvextend", binary.tools["lvextend"],
        "--resize2fs", binary.tools["resize2fs"],
        "--xfs-growfs", binary.tools["xfs_growfs"],
        "--xfs-scrub", binary.tools["xfs_scrub"],
        "--udevadm", binary.tools["udevadm"],
    )
    outcome = json.loads(result.stdout)
    if (not isinstance(outcome, dict) or outcome.get("status") != "completed"
            or outcome.get("mutation_enabled") is not False
            or not isinstance(outcome.get("execution_id"), str)
            or not isinstance(outcome.get("final_identity_digest"), str)):
        raise SafetyError(f"invalid PV executor completion evidence: {outcome!r}")

    final = ready_snapshot(binary, loop.device, vg)
    final_lvm = final.get("lvm")
    if not isinstance(final_lvm, dict):
        raise SafetyError("LVM inventory missing after PV executor drill")
    final_pvs = [row for row in final_lvm.get("physical_volumes", [])
                 if isinstance(row, dict) and row.get("vg_name") == vg
                 and row.get("name") == partition]
    final_lvs = [row for row in final_lvm.get("logical_volumes", [])
                 if isinstance(row, dict) and row.get("vg_name") == vg
                 and row.get("path") == source]
    if len(final_pvs) != 1 or final_pvs[0].get("size_bytes") != expected_pv_size:
        raise SafetyError(
            f"PV size mismatch after Rust pvresize: expected={expected_pv_size} "
            f"actual={final_pvs[0].get('size_bytes') if final_pvs else None}"
        )
    if len(final_lvs) != 1 or final_lvs[0].get("size_bytes") != expected_lv_size:
        raise SafetyError("LV size mismatch after PV -> LV Rust execution")

    after_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    if after_fs_bytes <= before_fs_bytes:
        raise SafetyError("filesystem capacity did not increase after PV -> LV executor growth")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("filesystem sentinel changed during PV -> LV executor growth")
    if journal_root.exists() or backup_root.exists():
        raise SafetyError("PV executor did not clean its owned journal/backup artifacts")

    resources.uncertain = False
    print("PV_LV_FILESYSTEM_EXECUTOR_OK=exact-pv-lv-fs-boundaries", flush=True)


def exercise_lv_post_write_recovery(
    resources: Resources, binary: Runner, loop: Loop,
    source: str, target: Path, vg: str,
) -> None:
    resources.check_loop(loop)
    if source != f"/dev/{vg}/data":
        raise SafetyError("unexpected LV recovery-boundary identity")

    before = ready_snapshot(binary, loop.device, vg)
    lvm = before.get("lvm")
    if not isinstance(lvm, dict):
        raise SafetyError("LVM inventory missing before LV recovery-boundary drill")
    lvs = [row for row in lvm.get("logical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("path") == source]
    vgs = [row for row in lvm.get("volume_groups", [])
           if isinstance(row, dict) and row.get("name") == vg]
    if len(lvs) != 1 or len(vgs) != 1:
        raise SafetyError("LV/VG identity is ambiguous before LV recovery-boundary drill")

    current_lv_size = lvs[0].get("size_bytes")
    current_lv_uuid = lvs[0].get("uuid")
    vg_uuid = vgs[0].get("uuid")
    extent = vgs[0].get("extent_size_bytes")
    free_extents = vgs[0].get("free_extent_count")
    if (type(current_lv_size) is not int or type(extent) is not int
            or type(free_extents) is not int or extent <= 0 or free_extents < 8
            or not isinstance(current_lv_uuid, str) or not current_lv_uuid
            or not isinstance(vg_uuid, str) or not vg_uuid):
        raise SafetyError("LV recovery-boundary identity/extent evidence is incomplete")

    growth_extents = 8
    growth_bytes = growth_extents * extent
    expected_lv_size = current_lv_size + growth_bytes
    sentinel = (target / "readonly-sentinel").read_bytes()
    before_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    association_row = binary.run(
        "losetup", "--list", "--noheadings", "--output", "NAME,BACK-FILE", loop.device
    ).stdout.strip()
    if not association_row:
        raise SafetyError("loop association missing before LV recovery-boundary drill")

    journal_root = resources.root / f"{vg}-lv-post-write-fault-journal"
    backup_root = resources.root / f"{vg}-lv-post-write-fault-backup"
    args = (
        "--allow-disposable-loop-execution",
        "--target", str(target),
        "--loop-device", loop.device,
        "--backing-file", str(loop.image),
        "--owned-root", str(resources.root),
        "--association-row", association_row,
        "--journal-root", str(journal_root),
        "--backup-root", str(backup_root),
        "--growth-bytes", str(growth_bytes),
        "--sfdisk", binary.tools["sfdisk"],
        "--partx", binary.tools["partx"],
        "--pvresize", binary.tools["pvresize"],
        "--lvextend", binary.tools["lvextend"],
        "--resize2fs", "/usr/bin/false",
        "--xfs-growfs", binary.tools["xfs_growfs"],
        "--xfs-scrub", binary.tools["xfs_scrub"],
        "--udevadm", binary.tools["udevadm"],
    )

    resources.uncertain = True
    failed = binary.run("disposable-executor", *args, allowed=(1,))
    if "selected disposable tool path is unsafe for Resize2fs" not in failed.stderr:
        raise SafetyError(f"unexpected LV post-write fault result: {failed.stderr!r}")

    journals = list(journal_root.glob("*.json"))
    if len(journals) != 1:
        raise SafetyError("LV post-write fault did not retain exactly one durable journal")
    journal_bytes = journals[0].read_bytes()
    journal = json.loads(journal_bytes)
    events = journal.get("events")
    boundary = journal.get("verified_boundary")
    if (journal.get("phase") != "recovery_required"
            or journal.get("mutation_may_have_started") is not True
            or not isinstance(journal.get("execution"), dict)
            or not isinstance(boundary, dict)
            or not isinstance(boundary.get("completed_step_id"), int)
            or not isinstance(boundary.get("next_step_id"), int)
            or not isinstance(boundary.get("fresh_identity_digest"), str)
            or not boundary["fresh_identity_digest"]
            or not isinstance(events, list) or not events
            or events[-1].get("code") != "interrupted-after-mutation-boundary"):
        raise SafetyError(f"LV post-write fault journal lost verified boundary evidence: {journal!r}")

    reconciled = ready_snapshot(binary, loop.device, vg)
    reconciled_lvm = reconciled.get("lvm")
    if not isinstance(reconciled_lvm, dict):
        raise SafetyError("LVM inventory missing during LV recovery reconciliation")
    new_vgs = [row for row in reconciled_lvm.get("volume_groups", [])
               if isinstance(row, dict) and row.get("name") == vg]
    new_lvs = [row for row in reconciled_lvm.get("logical_volumes", [])
               if isinstance(row, dict) and row.get("vg_name") == vg and row.get("path") == source]
    if len(new_vgs) != 1 or len(new_lvs) != 1:
        raise SafetyError("LV recovery reconciliation lost exact LVM identity")
    if new_vgs[0].get("uuid") != vg_uuid:
        raise SafetyError("LV recovery reconciliation changed VG identity")
    if (new_lvs[0].get("uuid") != current_lv_uuid
            or new_lvs[0].get("size_bytes") != expected_lv_size):
        raise SafetyError("LV recovery reconciliation did not prove exact resized LV state")

    after_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    if after_fs_bytes != before_fs_bytes:
        raise SafetyError("LV recovery-boundary fault changed filesystem capacity before resize2fs")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("LV recovery-boundary fault changed filesystem sentinel")

    filesystem = reconciled.get("storage", {}).get("block_devices")
    if not isinstance(filesystem, list):
        raise SafetyError("storage graph missing during LV recovery reconciliation")

    replay_args = list(args)
    replay_args[replay_args.index("/usr/bin/false")] = binary.tools["resize2fs"]
    replay = binary.run("disposable-executor", *replay_args, allowed=(1,))
    if "journal root already exists" not in replay.stderr:
        raise SafetyError(f"LV post-write replay was not blocked: {replay.stderr!r}")
    if journals[0].read_bytes() != journal_bytes:
        raise SafetyError("blocked LV post-write replay changed retained recovery evidence")

    remove_owned_evidence_directory(resources, backup_root)
    remove_owned_evidence_directory(resources, journal_root)
    resources.uncertain = False
    print("LV_RECOVERY_REQUIRED_OK=post-lvextend-pre-filesystem-grow", flush=True)


def exercise_lvm_growth_mutation(resources: Resources, binary: Runner, loop: Loop,
                                 source: str, target: Path, vg: str,
                                 filesystem: str) -> None:
    resources.check_loop(loop)
    if source != f"/dev/{vg}/data":
        raise SafetyError("unexpected disposable LV path")
    if filesystem not in ("ext4", "xfs"):
        raise SafetyError("unsupported disposable filesystem growth drill")

    before = ready_snapshot(binary, loop.device, vg)
    lvm = before.get("lvm")
    if not isinstance(lvm, dict):
        raise SafetyError("LVM inventory missing before mutation drill")
    lvs = [row for row in lvm.get("logical_volumes", [])
           if isinstance(row, dict) and row.get("vg_name") == vg and row.get("path") == source]
    vgs = [row for row in lvm.get("volume_groups", [])
           if isinstance(row, dict) and row.get("name") == vg]
    if len(lvs) != 1 or len(vgs) != 1:
        raise SafetyError("disposable LV/VG identity is ambiguous before mutation")

    current_lv_size = lvs[0].get("size_bytes")
    extent = vgs[0].get("extent_size_bytes")
    free_extents = vgs[0].get("free_extent_count")
    if (type(current_lv_size) is not int or type(extent) is not int
            or type(free_extents) is not int or extent <= 0 or free_extents < 8):
        raise SafetyError("insufficient exact LVM extent evidence for mutation drill")

    growth_extents = 8
    expected_lv_size = current_lv_size + growth_extents * extent
    sentinel = (target / "readonly-sentinel").read_bytes()
    before_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize

    if filesystem == "xfs":
        scrub = binary.run(
            "xfs_scrub", "-n", "-k", str(target), allowed=(0, 4)
        )
        if scrub.returncode == 4:
            expected = "Kernel metadata scrubbing facility is not available."
            if expected not in scrub.stderr:
                raise SafetyError(
                    "XFS health preflight failed for an unexpected reason: "
                    f"{scrub.stderr.strip()!r}"
                )
            unchanged = ready_snapshot(binary, loop.device, vg)
            unchanged_lvs = [
                row for row in unchanged["lvm"]["logical_volumes"]
                if row.get("vg_name") == vg and row.get("path") == source
            ]
            if len(unchanged_lvs) != 1 or unchanged_lvs[0].get("size_bytes") != current_lv_size:
                raise SafetyError("XFS scrub capability probe changed the disposable LV")
            if os.statvfs(target).f_blocks * os.statvfs(target).f_frsize != before_fs_bytes:
                raise SafetyError("XFS scrub capability probe changed filesystem capacity")
            if (target / "readonly-sentinel").read_bytes() != sentinel:
                raise SafetyError("XFS scrub capability probe changed the filesystem sentinel")
            print("XFS_EXECUTOR_BLOCKED_EXPECTED=kernel-online-scrub-unavailable")
            return

    association_row = binary.run(
        "losetup", "--list", "--noheadings", "--output", "NAME,BACK-FILE", loop.device
    ).stdout.strip()
    if not association_row:
        raise SafetyError("exact loop association row is unavailable before Rust execution")

    journal_root = resources.root / f"{vg}-executor-journal"
    backup_root = resources.root / f"{vg}-executor-backup"

    # From this point the Rust executor may change storage. Any failure retains all fixture evidence.
    resources.uncertain = True
    result = binary.run(
        "disposable-executor",
        "--allow-disposable-loop-execution",
        "--target", str(target),
        "--loop-device", loop.device,
        "--backing-file", str(loop.image),
        "--owned-root", str(resources.root),
        "--association-row", association_row,
        "--journal-root", str(journal_root),
        "--backup-root", str(backup_root),
        "--growth-bytes", str(growth_extents * extent),
        "--sfdisk", binary.tools["sfdisk"],
        "--partx", binary.tools["partx"],
        "--pvresize", binary.tools["pvresize"],
        "--lvextend", binary.tools["lvextend"],
        "--resize2fs", binary.tools["resize2fs"],
        "--xfs-growfs", binary.tools["xfs_growfs"],
        "--xfs-scrub", binary.tools["xfs_scrub"],
        "--udevadm", binary.tools["udevadm"],
    )
    outcome = json.loads(result.stdout)
    if (not isinstance(outcome, dict) or outcome.get("status") != "completed"
            or outcome.get("mutation_enabled") is not False
            or not isinstance(outcome.get("execution_id"), str)
            or not isinstance(outcome.get("final_identity_digest"), str)):
        raise SafetyError(f"invalid Rust executor completion evidence: {outcome!r}")

    refresh_fixture_udev(binary, Path(source).resolve(strict=True).name)
    final = ready_snapshot(binary, loop.device, vg)
    final_lvs = [row for row in final["lvm"]["logical_volumes"]
                 if row.get("vg_name") == vg and row.get("path") == source]
    if len(final_lvs) != 1 or final_lvs[0].get("size_bytes") != expected_lv_size:
        raise SafetyError("final rediscovery lost the exact Rust-executed LV size")

    after_fs_bytes = os.statvfs(target).f_blocks * os.statvfs(target).f_frsize
    if after_fs_bytes <= before_fs_bytes:
        raise SafetyError("filesystem capacity did not increase after Rust executor growth")
    if (target / "readonly-sentinel").read_bytes() != sentinel:
        raise SafetyError("filesystem sentinel changed during Rust executor growth")

    if journal_root.exists() or backup_root.exists():
        raise SafetyError("Rust harness did not clean its owned journal/backup artifacts")

    resources.uncertain = False


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


def refresh_fixture_udev(binary: Runner, sysname: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9._+!-]+", sysname) is None:
        raise SafetyError("invalid block sysname for targeted udev refresh")
    binary.run(
        "udevadm",
        "trigger",
        "--action=change",
        f"--sysname-match={sysname}",
    )
    binary.run("udevadm", "settle", "--timeout=30")


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
    parser.add_argument("executor_binary", type=Path)
    args = parser.parse_args(argv)
    if not args.allow_disposable_loop_tests:
        parser.error("explicit --allow-disposable-loop-tests is required; never use on a production host")
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires root in a disposable Linux VM")
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error("binary is absent or not executable")
    if not args.executor_binary.is_file() or not os.access(args.executor_binary, os.X_OK):
        parser.error("disposable executor binary is absent or not executable")
    def interrupted(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt(f"received signal {signum}")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    os.umask(0o077)
    runner = Runner(args.binary, args.executor_binary)
    root = Path(tempfile.mkdtemp(prefix="lsm-loop-matrix-"))
    resources = Resources(root, runner)
    failed = False
    try:
        for label, filesystem, lvm in (
            ("plain", "ext4", False),
            ("plain-xfs", "xfs", False),
            ("lvm-ext4", "ext4", True),
            ("lvm-xfs", "xfs", True),
        ):
            print(f"==> {label}", flush=True)
            if lvm:
                loop_mib, partition_mib = 1024, 896
            elif filesystem == "xfs":
                loop_mib, partition_mib = 512, 384
            else:
                loop_mib, partition_mib = 256, 128
            loop = resources.create_loop(label, loop_mib * 1024 * 1024)
            partition = resources.create_partition(loop, partition_mib, lvm)
            vg = "lsmtest" + os.urandom(12).hex() if lvm else None
            source = resources.create_vg(loop, partition, vg) if vg else partition
            runner.run("mkfs." + filesystem, "-f" if filesystem == "xfs" else "-F", source)
            canonical_source = Path(source).resolve(strict=True)
            refresh_fixture_udev(runner, canonical_source.name)
            target = resources.mount(source, label + "-mount")
            exercise(resources, runner, loop, target, vg)
            if vg is not None:
                if filesystem == "ext4":
                    print(f"==> {label}-pre-spawn-failure", flush=True)
                    exercise_disposable_pre_spawn_failure(
                        resources, runner, loop, source, target, vg
                    )
                print(f"==> {label}-growth-mutation", flush=True)
                exercise_lvm_growth_mutation(
                    resources, runner, loop, source, target, vg, filesystem
                )
        print("==> lvm-ext4-lv-post-write-recovery", flush=True)
        lv_fault_loop = resources.create_loop(
            "lvm-ext4-lv-post-write-recovery", 1024 * 1024 * 1024
        )
        lv_fault_partition = resources.create_partition(
            lv_fault_loop, 896, True
        )
        lv_fault_vg = "lsmtest" + os.urandom(12).hex()
        lv_fault_source = resources.create_vg(
            lv_fault_loop, lv_fault_partition, lv_fault_vg
        )
        runner.run("mkfs.ext4", "-F", lv_fault_source)
        refresh_fixture_udev(runner, Path(lv_fault_source).resolve(strict=True).name)
        lv_fault_target = resources.mount(
            lv_fault_source, "lvm-ext4-lv-post-write-recovery-mount"
        )
        exercise_lv_post_write_recovery(
            resources,
            runner,
            lv_fault_loop,
            lv_fault_source,
            lv_fault_target,
            lv_fault_vg,
        )

        print("==> lvm-ext4-pv-post-write-recovery", flush=True)
        pv_fault_loop = resources.create_loop(
            "lvm-ext4-pv-post-write-recovery", 1024 * 1024 * 1024
        )
        pv_fault_partition = resources.create_partition(
            pv_fault_loop, 896, True
        )
        pv_fault_vg = "lsmtest" + os.urandom(12).hex()
        pv_fault_source = resources.create_vg(
            pv_fault_loop, pv_fault_partition, pv_fault_vg, pv_size_mib=640
        )
        runner.run("mkfs.ext4", "-F", pv_fault_source)
        refresh_fixture_udev(runner, Path(pv_fault_source).resolve(strict=True).name)
        pv_fault_target = resources.mount(
            pv_fault_source, "lvm-ext4-pv-post-write-recovery-mount"
        )
        exercise_pv_post_write_recovery(
            resources,
            runner,
            pv_fault_loop,
            pv_fault_partition,
            pv_fault_source,
            pv_fault_target,
            pv_fault_vg,
        )

        print("==> lvm-ext4-pv-lv-filesystem-growth", flush=True)
        pv_loop = resources.create_loop("lvm-ext4-pv-growth", 1024 * 1024 * 1024)
        pv_partition = resources.create_partition(pv_loop, 896, True)
        pv_vg = "lsmtest" + os.urandom(12).hex()
        pv_source = resources.create_vg(pv_loop, pv_partition, pv_vg, pv_size_mib=640)
        runner.run("mkfs.ext4", "-F", pv_source)
        refresh_fixture_udev(runner, Path(pv_source).resolve(strict=True).name)
        pv_target = resources.mount(pv_source, "lvm-ext4-pv-growth-mount")
        exercise_pv_lvm_growth_mutation(
            resources, runner, pv_loop, pv_partition, pv_source, pv_target, pv_vg
        )

        for table_label in ("gpt", "dos"):
            print(f"==> lvm-ext4-{table_label}-partition-post-write-recovery", flush=True)
            fault_loop = resources.create_loop(
                f"lvm-ext4-{table_label}-partition-post-write-recovery",
                1024 * 1024 * 1024,
            )
            fault_partition = resources.create_partition(
                fault_loop, 640, True, table_label=table_label
            )
            fault_vg = "lsmtest" + os.urandom(12).hex()
            fault_source = resources.create_vg(
                fault_loop, fault_partition, fault_vg
            )
            runner.run("mkfs.ext4", "-F", fault_source)
            refresh_fixture_udev(runner, Path(fault_source).resolve(strict=True).name)
            fault_target = resources.mount(
                fault_source,
                f"lvm-ext4-{table_label}-partition-post-write-recovery-mount",
            )
            exercise_partition_post_write_recovery(
                resources,
                runner,
                fault_loop,
                fault_partition,
                fault_source,
                fault_target,
                fault_vg,
                table_label,
            )

        for table_label in ("gpt", "dos"):
            print(f"==> lvm-ext4-{table_label}-partition-pv-lv-filesystem-growth", flush=True)
            chain_loop = resources.create_loop(
                f"lvm-ext4-{table_label}-partition-growth", 1024 * 1024 * 1024
            )
            chain_partition = resources.create_partition(
                chain_loop, 640, True, table_label=table_label
            )
            chain_vg = "lsmtest" + os.urandom(12).hex()
            chain_source = resources.create_vg(
                chain_loop, chain_partition, chain_vg
            )
            runner.run("mkfs.ext4", "-F", chain_source)
            refresh_fixture_udev(runner, Path(chain_source).resolve(strict=True).name)
            chain_target = resources.mount(
                chain_source, f"lvm-ext4-{table_label}-partition-growth-mount"
            )
            exercise_partition_pv_lvm_growth_mutation(
                resources,
                runner,
                chain_loop,
                chain_partition,
                chain_source,
                chain_target,
                chain_vg,
                table_label,
            )

        for table_label in ("gpt", "dos"):
            print(f"==> partition-recovery-{table_label}", flush=True)
            exercise_partition_table_recovery(resources, runner, table_label)
        print("==> lvm-metadata-recovery", flush=True)
        exercise_lvm_metadata_recovery(resources, runner)
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
        print("LOOP_MATRIX_OK cases=plain-ext4,plain-xfs,lvm-ext4,lvm-xfs,lvm-ext4-pre-spawn-recovery,lvm-ext4-growth,lvm-xfs-growth,lvm-ext4-lv-post-write-recovery,lvm-ext4-pv-post-write-recovery,lvm-ext4-pv-lv-filesystem-growth,lvm-ext4-gpt-partition-post-write-recovery,lvm-ext4-dos-partition-post-write-recovery,lvm-ext4-gpt-partition-pv-lv-filesystem-growth,lvm-ext4-dos-partition-pv-lv-filesystem-growth,partition-recovery-gpt,partition-recovery-dos,lvm-metadata-recovery cleanup=complete")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

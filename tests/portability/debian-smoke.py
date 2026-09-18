#!/usr/bin/env python3
"""Read-only Debian userland/collector compatibility; NOT a disk or kernel test."""
import json
import subprocess

BINARY = "/probe/storagemgr"


def run(*args, allowed=(0,)):
    result = subprocess.run([BINARY, *args], text=True, capture_output=True,
                            timeout=30, check=False)
    if result.returncode not in allowed:
        raise RuntimeError(f"{args!r}: exit={result.returncode}: {result.stderr}")
    return result.stdout


run("--version")
run("tree")
for command in ("json", "mounts", "fstab", "swap", "snapshot"):
    data = json.loads(run(command))
    if command == "snapshot":
        states = {row["component"]: row["state"] for row in data["collectors"]}
        assert states["lsblk"] == "complete", states
        assert states["mounts"] == "complete", states
        print("DEBIAN12_COLLECTORS " + json.dumps(states, sort_keys=True))
    print(f"DEBIAN12_COMMAND_OK command={command}")
# Root is a container filesystem, not a supported local LVM mount.
plan = json.loads(run("plan", "extend", "/", "--max", "--json", allowed=(2,)))
assert plan["dry_run"] is True and plan["executable"] is False
assert plan["steps"] == [] and plan["status"] == "blocked"
print("DEBIAN12_SMOKE_OK read-only-collectors=pass unsupported-plan=blocked")

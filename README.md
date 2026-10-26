# Linux Storage Manager

Linux Storage Manager is a native Rust terminal application for Linux storage
administration. Its TUI works locally and over SSH; the CLI uses the same discovery
and planning core. Administrators select a target and intent instead of composing
low-level partition, LVM and filesystem commands themselves.

## Current status

The normal `storagemgr` CLI and TUI are **read-only**: they discover storage, explain
blockers and preview changes. There is no general-purpose `storagemgr apply` command.

Implemented mutation paths are tested through separately enabled harnesses on
disposable loop devices. They include fresh identity checks, explicit operation
consent, pinned tools, durable journals, metadata backups, post-write verification
and recovery boundaries. A passing harness is evidence for its exact scenario,
not authorization to run on a production disk.

| Area | Available now |
| --- | --- |
| Discovery and planning | Block topology, GPT/DOS reconciliation, mounts, fstab, swap, LVM, target selection, Extend/Create previews |
| Extend acceptance | LV/filesystem growth; single-PV partition → PV → LV → filesystem growth; ext4 online/offline; XFS online; sibling isolation |
| Swap acceptance | DOS tail swap-partition migration to a swapfile, persistent configuration and old partition removal |
| Blank-disk Create acceptance | GPT/DOS × ext4/XFS, mount, atomic fstab persistence, restart verification and exact fixture cleanup |
| Existing GPT free-tail Create | Frozen intent, consent and runtime preflight; write/format execution and E2E acceptance remain pending |
| General operator apply flow and advanced layouts | Pending; unsupported or contradictory topology is blocked |

## Start testing

Use a **disposable Linux VM** for Wave 1 storage tests. The full procedure, required
tools and acceptance criteria are in [the pre-production test plan](docs/PREPROD_TEST_PLAN.md).

From a clean checkout, with Rust **1.88.0**, Python **3.10+** and the required host
storage tools installed:

```bash
# Build all six binaries and record their source and content identities.
python3 -I tools/preprod.py build

# Check prerequisites without launching storage tests.
python3 -I tools/preprod.py check --expected-source "$(git rev-parse HEAD)"

# Run only on a disposable VM. Three complete repetitions are required for PASS.
sudo python3 -I tools/preprod.py run \
  --expected-source "$(git rev-parse HEAD)" \
  --allow-disposable-vm-tests \
  --output /var/tmp/lsm-wave1-first-run
```

Choose a new output directory for each run. It contains `SUMMARY.txt`, `report.json`
and the complete emitted harness output for each repetition. Missing scenario
markers, a failed run, changed fstab, retained resources or missing final evidence
prevent acceptance. The wrapper never attempts to repair or remove uncertain
storage resources after a failure.

GitHub CI runs this same Wave 1 command on its disposable Ubuntu 24.04 VM and
uploads the evidence. Debian, Rocky and aarch64 VM acceptance require their own
complete reports. Portable artifact checks cover static linkage and userland smoke
tests separately; the downloadable `storagemgr` prototype remains read-only.

## Read-only CLI

```text
storagemgr                   # open the TUI
storagemgr tree              # normalized block topology
storagemgr snapshot          # complete multi-source host snapshot
storagemgr capabilities      # available host tools
storagemgr diagnose          # cross-source diagnostics
storagemgr explain /         # growth explanation for a target
storagemgr plan targets      # selectable targets and blockers
storagemgr plan create-spaces # verified/blocked provisioning sources
storagemgr plan extend / --max
storagemgr plan create <id> --max --purpose filesystem --fs ext4
```

Discovery works without root wherever the underlying tools permit it. Missing
permissions or tools are reported rather than treated as a complete inventory.

## Development

```bash
bash tools/validate.sh --source-only  # Python harness/runner tests; no disk writes
bash tools/validate.sh                # also formatting, clippy, Rust tests and build
```

See [AGENTS.md](AGENTS.md), [architecture](docs/ARCHITECTURE.md),
[roadmap](docs/ROADMAP.md), [safety model](docs/SAFETY.md) and
[current handoff](docs/HANDOFF.md). Support is determined from verified storage
capabilities, not a promise to handle every layout on every Linux release.

# Linux Storage Manager

Linux Storage Manager is a safety-first terminal application for inspecting and managing Linux storage without requiring administrators to manually compose low-level storage commands.

The project has completed the read-only **M0 — Storage Discovery** and **M1A — Planning** baselines and is in **M1B pre-executor foundation work**. M1B0-M1B10 freeze the exact handoff, host lock, locked identity/capability revalidation, durable journal and verified backup/pre-mutation evidence. M1B11 durably verifies exact current-session evidence and advances only `IdentityRevalidated -> PreconditionsVerified`. M1B12 adds a durable exact-plan/evidence/target approval record and advances only `PreconditionsVerified -> Approved`. Storage mutation remains disabled. Storage discovery, Grow/Create planning, target identity guards and all current M1B APIs are still non-mutating: no current CLI/TUI path changes disks, partitions, LVM metadata, filesystems, mounts, or swap configuration.

## Initial goals

- Full-screen TUI suitable for local consoles and SSH sessions.
- CLI for scripting and automation.
- Capability-based discovery instead of hard-coding Linux distributions.
- A normalized storage graph covering disks, partitions, LVM, filesystems, mounts, and swap.
- Independent partition-table verification through read-only `sfdisk --json`.
- Cross-source diagnostics before any future write planning.
- Explicit planning and dry-run before any future write operation.
- Metadata backup and post-operation verification for future mutating operations.
- Conservative safety model: unsupported, incomplete, or contradictory storage layouts must fail closed.

## Current read-only CLI

```text
storagemgr                  # open the read-only TUI
storagemgr tree             # normalized block topology
storagemgr json             # normalized lsblk graph as JSON
storagemgr snapshot         # complete multi-source host snapshot
storagemgr partition-tables # read-only sfdisk partition tables
storagemgr mounts           # active findmnt inventory
storagemgr fstab            # parsed /etc/fstab
storagemgr swap             # active swap inventory
storagemgr lvm              # PV/VG/LV inventory
storagemgr capabilities     # available host storage tools
storagemgr diagnose         # topology and cross-source diagnostics
storagemgr explain /        # read-only growth explanation for a target
storagemgr plan targets      # selectable Grow targets and current blockers
storagemgr plan create-spaces # verified/blocked provisioning sources
storagemgr plan extend / --max
storagemgr plan create <id> --max --purpose filesystem --fs ext4
```

## Current execution boundary

M1A plans and M1B handoff/evidence/approval objects remain non-mutating. M1B1-M1B12 add lock/revalidation/journal/backup foundations, disposable recovery evidence, non-mutating backup capture/revalidation, immutable pre-mutation evidence, durable `PreconditionsVerified` and a durable exact `Approved` record. There is no mutation-capable executor or apply command. Entering `Executing` remains separately gated on explicit owner acceptance and the remaining privileged execution/recovery controls described in the roadmap and safety documentation.

Implementation language: **Rust**.

> This repository is under active development. Current M0/M1A/M1B pre-executor code contains no storage-changing executor. Do not treat a preview, handoff, evidence bundle, `PreconditionsVerified` state or M1B12 `Approved` record as authorization to modify production storage.

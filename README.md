# Linux Storage Manager

Linux Storage Manager is a safety-first terminal application for inspecting and managing Linux storage without requiring administrators to manually compose low-level storage commands.

The project has completed the read-only **M0 — Storage Discovery** and **M1A — Planning** baselines and is in **M1B pre-executor foundation work**. M1B0 freezes an exact non-mutating execution handoff, M1B1 adds the host-exclusive advisory lock primitive, and M1B2 performs target/capability revalidation while that lock is held. Storage mutation remains disabled. Storage discovery, Grow/Create planning, target identity guards and the M1B0 execution handoff are still non-mutating: no current CLI/TUI path changes disks, partitions, LVM metadata, filesystems, mounts, or swap configuration.

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

M1A plans and M1B0 handoff bundles are data only. M1B1-M1B10 add lock/revalidation/journal/backup foundations, disposable recovery evidence, non-mutating backup capture/revalidation and an immutable pre-mutation evidence bundle. There is no mutation-capable executor
or apply command. Executor rollout remains gated on explicit owner acceptance plus the
lock, fresh identity revalidation, health checks, verified backups, durable journal and
post-mutation verification described in the roadmap and safety documentation.

Implementation language: **Rust**.

> This repository is under active development. Current M0/M1A/M1B0 code contains no storage-changing executor. Do not treat a preview or handoff bundle as authorization to modify production storage.

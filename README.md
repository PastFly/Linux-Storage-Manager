# Linux Storage Manager

Linux Storage Manager is a safety-first terminal application for inspecting and managing Linux storage without requiring administrators to manually compose low-level storage commands.

The project has completed the read-only **M0 — Storage Discovery** and **M1A — Planning** baselines and is now in the guarded **M1B executor** phase. M1B0-M1B15 establish the exact handoff, host lock, durable journal, verified backups and preconditions, explicit approval, immutable semantic/native manifests, deterministic bindings, exact chained LVM previews, and native mutation-layer ordering. M1B16 adds a deliberately narrow, feature-gated `disposable-executor` for the first `LV -> filesystem` profile: exact non-shell argv, owned-loop proof, one-shot execution permits, durable `Executing -> Verifying` state, fresh post-LV rediscovery, and a consumed verified-boundary token before the filesystem step can be authorized. Default production builds still expose no normal apply path, and `MUTATION_ENABLED=false` remains unchanged.

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

M1A plans and the normal CLI/TUI remain non-mutating. M1B1-M1B15 provide lock/revalidation/journal/backup foundations, exact approval, frozen execution intent, native validation, and chained LVM growth planning. M1B16 introduces a mutation-capable executor only behind the explicit `disposable-executor` Cargo feature and only for harness-owned loop-device evidence. It is bound to an exact durable execution ID, validated native manifest, owned loop association, and fresh target identity; after the LV command the journal must enter `Verifying`, fresh state must prove the exact expected LV size, and a non-cloneable verified boundary must be consumed before a fresh filesystem-growth permit can be minted. There is still no production `storagemgr apply` command, and default builds keep `MUTATION_ENABLED=false`.

Implementation language: **Rust**.

> This repository is under active development. The M1B16 disposable executor is a test-only safety boundary, not production authorization. Do not treat a preview, handoff, evidence bundle, `PreconditionsVerified` state, approval record, frozen/native manifest, disposable permit, or verified boundary as permission to modify production storage.

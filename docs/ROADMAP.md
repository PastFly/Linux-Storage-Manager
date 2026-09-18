# Roadmap

## M0 — Storage Discovery

Goal: safely understand a host before changing anything.

- [x] Define architecture and safety boundaries.
- [x] Define normalized block-device model.
- [x] Parse structured `lsblk` JSON with explicit columns.
- [x] Provide read-only CLI views.
- [x] Provide read-only TUI dashboard.
- [x] Add fixture-based discovery tests.
- [x] Add dedicated `pvs` / `vgs` / `lvs` JSON/report collectors.
- [x] Discover active swap files and swap partitions from `/proc/swaps`.
- [x] Read active mount state through a dedicated `findmnt` JSON adapter.
- [x] Add read-only `/etc/fstab` adapter.
- [x] Add initial topology consistency diagnostics.
- [x] Reconcile collectors into one degradation-tolerant host snapshot.
- [x] Add cross-source reconciliation diagnostics (lsblk/LVM/mount/fstab/swap).
- [x] Add read-only `explain` analysis for immediate LVM/VG growth capacity.
- [x] Collect partition start geometry and parent logical-sector sizes.
- [x] Extend `explain` to detect adjacent partition/PV growth capacity without writes.
- [x] Add authoritative disk/partition-table discovery with `sfdisk --json`.
- [x] Reconcile sfdisk label/sector/start/size/PARTUUID facts against lsblk.
- [x] Handle DOS/MBR extended containers and logical-partition sibling representation conservatively.
- [x] Add disposable loop-device integration harness for plain ext4, LVM/ext4 and LVM/XFS.
- [x] Execute the loop-device matrix repeatedly on GitHub Actions with strict before/after facts and sentinel checks.
- [x] Produce static musl x86_64 and aarch64 candidates and smoke-test the same binary across Debian, Ubuntu, Rocky and Alpine userlands.

## M1A — Experimental read-only previews (not release acceptance)

- [x] Implement a pure planner crate with immutable, nonexecutable preview data.
- [x] Add `plan extend TARGET --by SIZE | --max` and optional JSON output.
- [x] Collect exact VG extent facts and LV layout/role facts.
- [x] Reject incomplete collectors, ambiguous targets, unsupported layouts and contradictory capacities.
- [x] Freeze requests to observed extents; include backup and verification requirements.
- [x] Add SHA-256 preview/basis IDs and in-memory stale-basis checks.
- [x] Add and execute unit/CLI/parser tests on the exact feature head.
- [x] Validate M0 and M1A together in disposable Linux loop fixtures.
- [x] Add strict read-only LVM/ext4 and LVM/XFS growth previews using existing VG free extents.
- [x] Add strict read-only direct-partition ext4/XFS previews for verified adjacent free space on DOS/MBR or GPT.
- [x] Expose advisory extendability and strict previews in the TUI without an executor.
- [ ] Add broader fixture coverage for direct GPT/XFS and 4K-sector partition previews.
- [ ] Add filesystem feature/health/version preflight before any future executor work.
- [ ] Add concurrency/locking design and fresh runtime identity revalidation for M1B.

M0 must still pass its acceptance gates. M1A has no executor, cannot perform a
backup or resize, and does not authorize storage mutation. See M1A_PLANNER.md.

## M1B — Future executor and safe grow workflows

- authoritative immutable operation plans with live identity and health checks;
- explicit owner acceptance of M0 and M1A before executor rollout;
- partition-table metadata backup;
- LVM metadata backup;
- grow GPT/MBR partition where safe;
- `pvresize`;
- `lvextend`;
- ext4 online/offline growth as supported;
- XFS online growth;
- post-operation re-discovery and verification;
- no shrink support until separately designed and reviewed.

## M2 — Provisioning and swap

- create partitions;
- create/extend VGs and LVs;
- format ext4/XFS;
- mount/unmount and guarded fstab changes;
- swap file/partition lifecycle.

## M3 — Advanced storage

- LUKS;
- Btrfs;
- mdraid;
- LVM thin/snapshots;
- device replacement and advanced diagnostics.

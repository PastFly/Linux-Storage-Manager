# Roadmap

## M0 — Storage Discovery

Goal: safely understand a host before changing anything.

- [x] Define architecture and safety boundaries.
- [x] Define normalized block-device model.
- [x] Parse structured `lsblk` JSON with explicit columns.
- [x] Provide read-only CLI views.
- [x] Provide initial read-only TUI.
- [x] Add fixture-based discovery tests.
- [x] Add dedicated `pvs` / `vgs` / `lvs` JSON/report collectors.
- [x] Discover active swap files and swap partitions from `/proc/swaps`.
- [x] Read active mount state through a dedicated `findmnt` JSON adapter.
- [x] Add read-only `/etc/fstab` adapter.
- [x] Add initial topology consistency diagnostics.
- [x] Reconcile collectors into one degradation-tolerant host snapshot.
- [ ] Add cross-source reconciliation diagnostics (lsblk/LVM/mount/fstab/swap).
- [ ] Add VM/loop-device integration test matrix.

## M1 — Planner and safe grow workflows

- immutable operation plans;
- dry-run output;
- operation risk/reversibility classification;
- partition-table metadata backup;
- LVM metadata backup;
- grow GPT/MBR partition where safe;
- `pvresize`;
- `lvextend`;
- ext4 online/offline growth as supported;
- XFS online growth;
- post-operation re-discovery and verification.

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

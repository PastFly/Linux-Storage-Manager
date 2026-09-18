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
- [x] Add broader fixture coverage for direct GPT/XFS and 4K-sector partition previews.
- [x] Add structured planner preflight evidence (verified vs required future gates).
- [x] Add live TUI discovery refresh and explicit selected-disk kernel rescan without partition/filesystem mutation.
- [x] Detect DOS extended/swap layouts that hide usable disk-tail capacity and expose nonexecutable migration alternatives.
- [x] Make TUI growth choices include proven layout-opportunity sizes in addition to directly adjacent capacity.
- [x] Add responsive TUI tables for storage, diagnostics, preflight and plan steps.
- [x] Add a read-only catalog of selectable filesystem growth targets, including blocked/unsupported targets instead of hiding them.
- [x] Add a read-only provisioning-space catalog for free VG extents, blank disks and verified partition-table free ranges (internal gaps and tail).
- [x] Add stable free-space source IDs for intent planning.
- [x] Add a dedicated TUI Create section and CLI catalog commands without adding a provisioning executor.
- [x] Add a read-only Create intent planner for filesystem/swap on verified VG free space and partition-table gap/tail sources.
- [x] Add `plan create SOURCE_ID --by SIZE|--max --purpose filesystem|swap` plus TUI size/purpose/ext4-XFS controls.
- [x] Keep blank-disk Create plans blocked until partition-table/alignment policy is explicitly resolved instead of guessing.
- [x] Add exact blank-disk Create previews for explicit GPT or DOS/MBR policy with sector-aware metadata reservation, 1 MiB alignment and 512B/4Kn regression coverage.
- [x] Add read-only ext4/XFS filesystem metadata/version/features preflight evidence and expose it in strict previews.
- [x] Add filesystem block-size/block-count/total-size evidence from ext4 superblock and XFS data geometry.
- [x] Add executor-grade read-only filesystem decision policy: ext4 online/offline gating, XFS mounted grow dry-run plus explicit no-modify scrub requirement, and no automatic repair.
- [x] Expose filesystem execution-gate decisions through CLI and TUI without executing the proposed health command.
- [x] Add target-scoped identity manifests and fresh-snapshot revalidation for disk/partition/PV/VG/LV/filesystem/mount chains.
- [x] Bind observed filesystem size separately from backing-device size into target identity manifests.
- [x] Add concurrency/per-host exclusive locking design for M1B.
- [x] Add an interruption-safe operation journal state machine; once mutation may have started, interruption requires recovery/reconciliation rather than blind replay.
- [x] Detect advisory whole-disk/backing-device LVM growth routes where the backing device is larger than the current PV.
- [x] Detect advisory partition -> PV -> VG -> LV -> filesystem routes when authoritative adjacent capacity is proven.
- [x] Add a reusable semantic layer graph for disk -> partition -> encryption/RAID -> PV -> VG -> LV -> filesystem -> mount topology.
- [x] Add explicit CLI/TUI route diagnostics for LUKS/crypt, RAID, multi-PV/nonstandard LVM, Btrfs/ZFS and unknown filesystems so unsupported paths remain visible and fail closed.
- [x] Add `plan route TARGET [--json]` for scriptable read-only route inspection.
- [x] Route Extend target selection through semantic profiles for direct partitions, LVM and whole-device filesystems while retaining proven geometry/extent builders.
- [x] Use semantic layer issue codes for unsupported layered targets instead of leaking unrelated LVM/direct-partition errors.
- [x] Add filesystem-only ext4/XFS previews when verified filesystem geometry proves the backing disk/loop device is already larger than the filesystem.
- [ ] Refactor the remaining chained grow and Create builders to consume reusable semantic route adapters instead of topology-specific planner branches.
- [x] Add initial scenario-matrix contract tests for multiple selectable targets, blocked unknown filesystems, free ranges and chained LVM routes.
- [x] Add semantic route-graph tests for direct, LVM, LUKS/crypt, multi-PV and unknown-filesystem paths.
- [x] Add target identity revalidation tests, including target geometry/LVM changes, filesystem-size changes and unrelated-disk non-invalidation.
- [x] Add whole-device ext4/XFS filesystem-only growth tests, including max-safe and filesystem-block-aligned partial growth.
- [x] Add lock/journal regression tests for stale identity, exact approval, pre-mutation abort and post-mutation recovery-required states.
- [ ] Continue expanding scenario-matrix fixtures until every supported/blocked topology in docs/SCENARIO_MATRIX.md has a stable regression case.

M0 must still pass its acceptance gates. M1A has no executor, cannot perform a
backup or resize, and does not authorize storage mutation. See M1A_PLANNER.md.

## M1B — Future executor and safe grow workflows

The user selects the target and desired final growth. The resolver chooses the lowest-risk
verified route automatically; the user must not have to manually compose `sfdisk`,
`pvresize`, `lvextend` and filesystem commands.

- authoritative immutable operation plans with live identity and health checks;
- explicit owner acceptance of M0 and M1A before executor rollout;
- implement the already-designed host-exclusive advisory lock boundary in the future executor;
- wire the existing target-manifest revalidation into the locked execution path;
- persist the existing operation-journal model durably before the first mutating command;
- partition-table metadata backup plus recovery drill;
- LVM metadata backup plus recovery drill;
- grow GPT/MBR partition where safe without moving a partition start;
- resize an existing LVM PV after its containing partition/device grows;
- extend VG/LV using existing or newly exposed extents;
- ext4 online/offline growth as supported by the detected filesystem state;
- XFS online growth;
- automatically chain multi-layer growth: disk -> partition -> PV -> VG -> LV -> filesystem;
- keep every discovered filesystem selectable when several partitions/LVs exist;
- present blocked paths with the exact reason instead of silently omitting the target;
- support safe disk-tail migration strategies such as swap-partition -> swapfile only after dedicated hibernation/resume checks;
- post-operation re-discovery and verification at every destructive boundary;
- no shrink support until separately designed and reviewed.

## M2 — Provisioning and swap

The TUI has a separate Create workflow. It starts from discovered free-space sources and
asks for the minimum necessary intent: destination, size, filesystem/use and optional
mountpoint. Low-level layout steps are generated automatically.

- create GPT/DOS partition tables on verified blank disks;
- create partitions in verified usable free ranges, including disk tail and later internal gaps;
- initialize LVM PVs and create/extend VGs;
- create LVs from existing or newly added VG capacity;
- format ext4/XFS;
- mount/unmount and guarded fstab changes;
- create and manage swap files/partitions;
- show an exact before/after topology preview before any write;
- allow advanced users to inspect/override the automatically chosen route without requiring that knowledge for normal use.

## M3 — Advanced storage

- LUKS growth/provisioning with explicit crypt-layer identity checks;
- Btrfs single/multi-device growth and filesystem-aware allocation;
- mdraid member/array growth;
- LVM multi-PV, thin, cache, snapshots and RAID layouts;
- multipath/device-mapper stacks;
- ZFS discovery/planning where platform tooling is available;
- device replacement and advanced diagnostics;
- capability-based adapters so distro differences affect tooling discovery, not the storage model.

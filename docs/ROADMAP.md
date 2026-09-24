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
- [x] Refactor the remaining chained grow and Create builders to consume reusable semantic route/source adapters instead of topology-specific planner branches.
- [x] Add initial scenario-matrix contract tests for multiple selectable targets, blocked unknown filesystems, free ranges and chained LVM routes.
- [x] Add semantic route-graph tests for direct, LVM, LUKS/crypt, multi-PV and unknown-filesystem paths.
- [x] Add target identity revalidation tests, including target geometry/LVM changes, filesystem-size changes and unrelated-disk non-invalidation.
- [x] Add whole-device ext4/XFS filesystem-only growth tests, including max-safe and filesystem-block-aligned partial growth.
- [x] Add lock/journal regression tests for stale identity, exact approval, pre-mutation abort and post-mutation recovery-required states.
- [x] Expand scenario-matrix fixtures so every currently supported/blocked M1A topology in docs/SCENARIO_MATRIX.md has a stable regression contract.

M0 must still pass its acceptance gates. M1A has no executor, cannot perform a
backup or resize, and does not authorize storage mutation. See M1A_PLANNER.md.

## M1B — Future executor and safe grow workflows

The user selects the target and desired final growth. The resolver chooses the lowest-risk
verified route automatically; the user must not have to manually compose `sfdisk`,
`pvresize`, `lvextend` and filesystem commands.

- [x] Freeze the exact M1A plan, target identity manifest, filesystem decision and execution guard into a repeatable non-mutating M1B0 handoff.
- [ ] Obtain explicit owner acceptance of the completed M0/M1A baseline before any mutation-capable executor rollout.
- [x] Implement a non-mutating host-exclusive advisory lock primitive with nonblocking OS-backed locking and RAII release.
- [ ] Wire the host-exclusive lock into the mutation-capable executor only after the owner-acceptance gate is satisfied.
- [x] Wire target-manifest and capability-inventory revalidation into a non-mutating locked pre-executor session.
- [ ] Wire the revalidated locked session into mutation-capable execution only after owner acceptance and the remaining executor gates.
- [x] Add a non-mutating atomic durable journal-store primitive with strict reload validation and recovery-state preservation.
- [x] Persist HostLockHeld and successful IdentityRevalidated transitions from the non-mutating locked session through the durable journal store.
- [x] Persist the operation-journal model durably before the first mutating command.
- [x] Freeze exact partition-table/LVM metadata backup and recovery command manifests without executing them.
- [x] Prove GPT and DOS/MBR partition-table backup/restore on owned disposable loop fixtures with exact machine-readable geometry and sentinel verification.
- [x] Prove LVM VG metadata backup/restore on an owned disposable loop fixture with exact PV/VG/LV identity and sentinel verification.
- [x] Capture required partition/LVM metadata backups only after locked identity revalidation, with secure artifact paths and SHA-256 receipts, while keeping recovery/mutation disabled.
- [x] Revalidate captured backup receipts from disk against the exact frozen manifest, size and SHA-256 before any future precondition transition.
- [x] Freeze locked identity, fresh filesystem policy and revalidated backup evidence into a non-mutating pre-mutation evidence bundle without advancing the journal.
- [x] Durably verify exact current-session pre-mutation evidence and advance only `IdentityRevalidated -> PreconditionsVerified` while mutation remains disabled.
- [x] Bind explicit operator approval to the exact plan/evidence/current target and exact `PreconditionsVerified` journal state, and durably advance only `PreconditionsVerified -> Approved` while mutation remains disabled.
- [x] Freeze the exact approved semantic `PlanStep` graph into a deterministic non-executable execution-intent manifest with per-mutation verification barriers, while leaving the durable journal at `Approved` and mutation disabled.
- [x] Compile the frozen execution intent into a typed non-executable native manifest with exact operation payloads, preserved step order/dependencies and preserved verification barriers.
- [x] Fail closed when a native mutation step is missing its verification barrier, has duplicate barriers, references a non-mutation step, or weakens any required barrier flag.
- [x] Complete native dependency-graph validation and role/operation consistency checks before defining any executor boundary.
- [x] Add deterministic native-manifest identity/binding so a future executor can only consume the exact validated manifest.
- [x] Add an exact non-executable `ResizePhysicalVolume` contract across planner, frozen intent and native layers.
- [x] Promote proven single-PV underlying LVM capacity into exact dry-run chains for `partition? -> PV -> LV -> filesystem`, including `--max`.
- [x] Fail closed when native mutation layers are reordered or bypass required lower-layer dependencies.
- [x] Compile the first disposable-only `LV -> filesystem` profile into a minimal typed executable argv allowlist bound to fresh identity.
- [x] Execute the first `LV -> filesystem` profile only on harness-owned `/dev/loopN` fixtures while production `MUTATION_ENABLED=false` remains unchanged; ext4 completes the live mutation path and XFS remains fail-closed when the host kernel lacks online scrub support.
- [x] Prevent blind replay from replacing an existing durable journal with a fresh `HostLockHeld` record.
- [x] Prove a forced pre-spawn executor failure after durable `Executing` transitions to `RecoveryRequired`, preserves recovery evidence and leaves LV/filesystem/sentinel state unchanged.
- [x] Add partition-table metadata backup plus a recovery drill.
- [x] Add LVM metadata backup plus a recovery drill.
- [x] Grow existing GPT/MBR partitions on harness-owned loop fixtures without moving the partition start, using exact size-only `sfdisk -N` geometry plus fresh kernel/table verification.
- [x] Prove a successful partition-table write followed by kernel-refresh failure enters durable `RecoveryRequired`, blocks replay, preserves LVM/filesystem state, and reconciles exact GPT/DOS geometry on owned loops.
- [x] Resize an existing LVM PV after its containing partition/device grows in the disposable owned-loop executor, with exact PV UUID/PE-start/size verification.
- [x] Prove a successful `pvresize` followed by pre-`lvextend` failure enters durable `RecoveryRequired`, blocks replay, preserves LV/filesystem state, and reconciles the exact resized PV identity on owned loops.
- [x] Extend an LV using existing or newly exposed extents in the disposable single-PV executor profile.
- [x] Prove a successful `lvextend` followed by pre-filesystem-grow failure enters durable `RecoveryRequired`, blocks replay, preserves filesystem/sentinel state, and reconciles the exact resized LV identity on owned loops.
- [ ] Support ext4 online/offline growth as allowed by the detected filesystem state.
- [ ] Support XFS online growth.
- [x] Automatically chain verified single-PV disk-tail growth through disk -> partition -> PV -> VG -> LV -> filesystem on the disposable executor; broader layered profiles remain separately gated.
- [ ] Keep every discovered filesystem selectable when several partitions/LVs exist.
- [ ] Present blocked paths with the exact reason instead of silently omitting the target.
- [ ] Support safe disk-tail migration strategies such as swap-partition -> swapfile only after dedicated hibernation/resume checks.
- [x] Re-discover and verify after every destructive boundary in every currently executable disposable profile, including partition -> PV -> LV -> filesystem.
- [ ] Keep shrink unsupported until it is separately designed and reviewed.

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

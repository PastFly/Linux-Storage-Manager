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
- [x] Obtain explicit owner acceptance of the completed M0/M1A baseline before any mutation-capable executor rollout; owner acceptance was recorded on 2026-09-25 and does not bypass CI, identity, recovery or production-safety gates.
- [x] Implement a non-mutating host-exclusive advisory lock primitive with nonblocking OS-backed locking and RAII release.
- [x] Wire the host-exclusive lock into the production execution-start boundary: only the current durable locked session may persist an exact prepared invocation into `Executing`; no storage command is spawned by this gate.
- [x] Wire target-manifest and capability-inventory revalidation into a non-mutating locked pre-executor session.
- [x] Wire the revalidated locked session into the conservative pre-spawn execution-start gate after owner acceptance; exact execution/request/prepared-invocation bindings are required before the durable journal can enter `Executing`.
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
- [x] Define a versioned, digest-bound privileged-helper request protocol that carries one exact validated native mutation step, rejects foreign execution bindings and unsafe operation payloads, and contains no generic shell command surface; production mutation remains disabled.
- [x] Add a feature-gated non-mutating privileged-helper process boundary with bounded strict JSON decoding, protocol revalidation and validation-only receipts; no storage tool is spawned and production mutation remains disabled.
- [x] Bind privileged-helper protocol v2 to the exact target selector/resolved device and independently rediscover/revalidate the live target inside the helper process before any future command compilation; drift fails closed and mutation remains disabled.
- [x] Compile each live-revalidated privileged-helper mutation request into one exact typed non-shell command spec (including partition kernel refresh) with a SHA-256 command digest; the helper still does not spawn the command or advance the journal.
- [x] Resolve every compiled privileged command to a root-owned, non-group/world-writable executable from fixed system directories, reject distinct executable ambiguity, bind canonical device/inode/mode/size plus SHA-256 provenance (including `partx` refresh), and still perform no spawn or journal advance.
- [x] Freeze the validated request, live identity, exact command and trusted-tool resolution into a deterministic prepared-invocation receipt before any future spawn; tampering or command/tool mismatch fails closed and production mutation remains disabled.
- [x] Persist the exact prepared first-step invocation through the host-locked durable session before any future spawn, binding execution/request/prepared IDs and moving `Approved -> Executing` with `mutation_may_have_started=true` conservatively before process creation; this gate still spawns no storage tool.
- [x] Re-resolve and re-hash the exact trusted executables after the durable `Executing` transition and immediately before any future spawn, requiring unchanged command/tool digests and a tamper-evident spawn-authorization receipt; this gate still performs no process creation.
- [x] Pin the exact trusted executable objects as already-open `O_NOFOLLOW|O_CLOEXEC` file descriptors after pre-spawn authorization, rechecking device/inode/uid/mode/size/SHA-256 against the trusted identity so later path replacement cannot redirect a future spawn; no execution occurs in this gate.
- [x] Freeze an ELF-only descriptor launch contract over the pinned file objects: exact argv, fixed non-inherited PATH/locale, stdin length/SHA-256, optional kernel-refresh stage and `fexecve` descriptor semantics are digest-bound before any process creation; scripts and embedded-NUL arguments fail closed.
- [x] Seal the durable start, post-journal authorization and descriptor launch contract into one tamper-evident first-step launch permit; exact execution/start/authorization/step/command IDs must match and the permit still records `mutation_enabled=false` / `process_spawned=false`.
- [x] Implement the descriptor-only `fexecve` process primitive and prove it with benign ELF utilities using fixed argv/environment and exit-status capture; the production wrapper revalidates the full permit/launch/pin chain but still returns `ProductionMutationDisabled` while `MUTATION_ENABLED=false`.
- [x] Bind the exact stdin payload and optional kernel-refresh sequence to the descriptor exec contract: no-payload stages receive `/dev/null`, payload bytes are delivered through a close-on-exec pipe, primary nonzero exit suppresses refresh, and command/stdin/refresh digests must match before the still-disabled production gate.
- [x] Capture child stdout/stderr through dedicated close-on-exec pipes with independent draining and a 64 KiB retained cap per stream, preventing inheritance/deadlock while preserving bounded diagnostics and truncation evidence; production storage spawning remains disabled.
- [x] Classify every spawned descriptor sequence as either `rediscovery_required` or `recovery_required` in a tamper-evident receipt: zero exit is never completion, nonzero primary/refresh or missing expected refresh is recovery-required, and bounded stdout/stderr digests/truncation evidence are retained for reconciliation.
- [x] Verify each successful privileged mutation against a fresh read-only target identity before any continuation: partition start/metadata must stay stable with exact new size, PV/LV UUID and exact size must match, and filesystem growth must preserve identity/mount state while proving observed capacity increase; this verification remains journal-neutral.
- [x] Bind privileged process and live-verification receipts into the durable journal before continuation: later mutation requests consume the latest verified identity boundary, failures/mismatches enter recovery, and successful steps persist through `Verifying` before exact adjacent-step continuation or terminal completion.
- [x] Gate the first production descriptor execution behind a separate compile feature plus exact M1B35 activation, freshly revalidated M1B36 root consent, M1B37 execution permit, current durable mutation-step/rolling-identity boundary, and the pinned descriptor launch chain; default builds remain non-executing.
- [x] Pin the exact root-owned production consent file object across the final authorization path and revalidate both the current fixed pathname and the still-open descriptor immediately before production descriptor execution, rejecting consent replacement, removal, metadata drift or in-place content changes.
- [x] Hide raw production descriptor exit outcomes behind an immediate tamper-evident M1B31 process receipt: zero exit is exposed only as `rediscovery_required`, recovery outcomes are durably forced to `RecoveryRequired` before return, and classification failure also enters recovery.
- [x] Make the public production mutation call close each successful boundary synchronously: require the exact pre-spawn identity, rediscover full live state and capabilities after spawn, run M1B32 exact layer verification, and durably apply M1B33 continuation/completion before returning; any post-state failure enters recovery.
- [x] Bound post-mutation production rediscovery convergence: retry only transient snapshot/identity capture and expected layer-size/state mismatches for a fixed 20 x 50 ms window, while capability drift, target drift and receipt/binding failures remain immediate recovery conditions.
- [x] Collapse first-step and verified-continuation pre-spawn wiring into typed production builders that construct the exact request/command/provenance/pin/launch/permit chain and force durable recovery on any preparation failure after execution has entered a mutation boundary.
- [x] Prove the narrow activated production `LV -> filesystem` path end to end on a root-owned disposable loop fixture, including exact runtime consent, typed first/continuation preparation, real descriptor execution, bounded post-state convergence, durable completion, cleanup, and sentinel preservation.
- [x] Define a separate non-executing production activation contract for exact single-PV `partition -> PV -> LV -> filesystem` growth, binding the four-step mutation order/dependencies and exact pre-mutation partition/PV/LV/filesystem identity while keeping downstream production permits unable to consume the new scope.
- [x] Bind the chained activation to the same fixed root-owned runtime consent and pinned consent-file lease as the narrow LV/filesystem profile, while retaining a shared non-executing consent receipt and leaving chained descriptor execution unavailable.
- [x] Add a separate compile-time-gated chained production execution permit that binds exact consent and one of the four authorized launch steps while remaining non-spawning and incompatible with the existing production descriptor-execution chain.
- [x] Gate chained production descriptor execution behind a separate compile feature and exact M1B45/M1B46/M1B47 activation-consent-permit chain: revalidate pinned root consent immediately before each spawn, require the exact durable rolling-identity step boundary, classify raw child outcomes immediately, and leave successful outcomes at rediscovery_required until live post-state verification.
- [x] Close every successful chained production mutation synchronously with bounded live rediscovery, frozen capability revalidation, exact M1B32 per-layer verification, and M1B33 durable continuation/completion; no partition/PV/LV/filesystem step may return success while its real post-state remains unverified.
- [x] Collapse chained partition/PV/LV/filesystem pre-spawn wiring into typed production builders: the first step resolves all safe pre-execution state before durable start, while later steps consume only the exact verified durable successor boundary and force recovery on any preparation failure.
- [x] Prove the complete chained production path end to end on a root-owned disposable loop: force real partition/PV/LV/filesystem growth, execute only through typed chained builders, require synchronous verified boundaries and durable completion, preserve sentinel data, and run the production harness from the CI loop matrix.
- [x] Carry each verified later mutation step back through the full pre-spawn chain: bind prepared invocation to the exact durable boundary/journal/rolling identity, revalidate tool provenance again, and seal the descriptor launch permit for that continuation step without treating the first execution-start receipt as reusable.
- [x] Define an explicit compile-time production activation contract without enabling mutation: the initial scope is only existing free extents in a verified single-PV LVM `LV -> filesystem` chain (ext4/XFS), while partition/PV mutation remains excluded; the sealed activation intent is tamper-evident and still records `execution_enabled=false`.
- [x] Require a second runtime consent boundary before any future production execution: fixed-path root-owned one-link mode-0600 JSON under `/etc/linux-storage-manager`, exact activation/execution/target/device binding and exact destructive-action phrase; the consent receipt remains non-executing.
- [x] Seal the narrow activation intent, exact root-consent receipt and exact descriptor launch permit into a third production execution-permit object; only the activated LV/filesystem step IDs are admitted and the resulting permit still records `mutation_enabled=false` / `process_spawned=false`.
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
- [x] Prove a successful ext4 `resize2fs` followed by pre-terminal-verification failure enters durable `RecoveryRequired`, blocks replay, preserves sentinel data, and reconciles the already-grown filesystem without claiming completion.
- [x] Support ext4 online/offline growth as allowed by the detected filesystem state.
  - [x] Online ext4 growth remains mounted read-write and uses exact fresh identity/terminal verification.
  - [x] Offline ext4 growth uses `ReadyOfflineGrow`, an exact session-bound `e2fsck -f -n <device>` gate, optional mount identity, unmounted-only `resize2fs`, exact LV/backing-size verification, terminal verification, and remount/sentinel acceptance on owned loops.
- [x] Support XFS online growth on an exact mounted read-write target after verified `xfs_growfs -n` preflight evidence.
  - [x] Keep `xfs_scrub -n -k` as optional diagnostic evidence rather than a mandatory gate because common kernels can lack online scrub support.
  - [x] Execute exact non-shell `xfs_growfs -d <mountpoint>`, verify LV/filesystem growth and sentinel preservation on owned loops.
- [x] Automatically chain verified single-PV disk-tail growth through disk -> partition -> PV -> VG -> LV -> filesystem on the disposable executor; broader layered profiles remain separately gated.
- [x] Keep every discovered filesystem selectable when several partitions/LVs exist; live loop coverage proves two mounted LV targets remain isolated and two mounted partition targets remain visible even when one is blocked by its neighbor.
- [x] Present blocked paths with exact structured blocker code/message instead of silently omitting the target; the target catalog remains machine-readable and text CLI renders the same evidence.
- [x] Support safe disk-tail migration strategies such as swap-partition -> swapfile only after dedicated hibernation/resume checks.
  - [x] Prove the entire production swap-tail route end-to-end on an owned DOS loop fixture: replacement activation, old swapoff, exact persistent rewrite, logical/extended partition removal, durable Completed, sentinel preservation and cleanup.
  - [x] Discover kernel hibernation/resume evidence read-only from `/proc/cmdline`, `/sys/power/resume` and `/sys/power/resume_offset`; malformed/ambiguous evidence fails closed.
  - [x] Add a read-only `plan swap-migration TARGET` safety gate that requires the exact detected tail-swap layout, no configured resume target/offset, and one persistent fstab binding before future migration planning.
  - [x] Prove a concrete replacement swapfile destination read-only: exact available bytes from statvfs, exact old-swap replacement size, unique RW ext4 mount, and required mkswap/swapon/swapoff tools.
  - [x] Freeze a deterministic non-executing replacement-swap intent only after exact path vacancy, runtime swap identity/priority and persistent fstab binding are revalidated; existing files/symlinks fail closed.
  - [x] Prove replacement swapfile creation/activation and the pre-old-swapoff fault boundary on an explicitly owned disposable DOS loop: both swaps must remain active on injected interruption, successful old swapoff must leave the replacement active, and partition geometry/sentinel data must remain unchanged.
  - [x] Bind the frozen M1B54 intent to a separate compile-time production activation contract; exact ext4 swapfile profile/integrity must revalidate and the sealed activation remains `execution_enabled=false`.
  - [x] Bind M1B56 activation to a dedicated fixed-path root-owned 0600 runtime-consent document; exact activation/intent/target/old-swap/swapfile identity and an exact phrase are required, and the receipt remains execution_enabled=false.
  - [x] Seal M1B56 activation + M1B57 root consent into an independently digested non-spawning execution permit with mutation_enabled=false and process_spawned=false.
  - [x] Pin the root-owned swap consent file by open descriptor and revalidate both pathname identity and in-place metadata/content immediately before future runtime execution.
  - [x] Revalidate immediately before runtime crossing: pinned consent, exact non-spawning permit, hibernation/resume state, retiring swap size/priority, fstab binding, RW ext4 destination, live capacity, vacant swapfile path, and trusted mkswap/swapon/swapoff provenance.
  - [x] Pin the freshly validated mkswap/swapon/swapoff executables by open descriptor and revalidate exact inode/metadata/content so path replacement cannot alter the future runtime tools.
  - [x] Freeze the exact descriptor-based runtime launch contract after pinned-tool revalidation: mkswap -> swapon -> mandatory dual-active verification -> swapoff, with fixed argv/environment and no process spawned.
  - [x] Require a durable fsync-persisted swap-runtime state machine before the first production crossing; persist a Started phase before every mutation-capable syscall/exec, derive exact mutation/persistent-config/partition risk scope, and fail into RecoveryRequired after any ambiguous interruption.
  - [x] Add the separately feature-gated runtime crossing through replacement swapfile creation, mkswap, swapon, mandatory dual-active verification and old-partition swapoff; every mutation-capable action is journaled before crossing and any ambiguous failure enters durable RecoveryRequired.
  - [x] Atomically replace the exact frozen retiring swap entry in /etc/fstab only after M1B64 proves OldSwapDeactivated: exact pre-write backup, intent-before-write journal transition, same-directory fsynced temp + inode recheck + atomic rename + directory fsync, followed by parse/readback verification and PersistentConfigUpdated.
  - [x] Freeze the exact post-fstab old logical-swap + DOS extended-container removal geometry and capture a fresh fsynced sfdisk recovery artifact while leaving the journal at PersistentConfigUpdated.
  - [x] Pin trusted sfdisk/partx executables by open descriptor after the exact M1B66 preflight, and revalidate inode/metadata/content immediately before any future delete or kernel-refresh crossing.
  - [x] Execute final old swap/extended-partition removal from that exact permit, verify authoritative geometry, and complete the durable journal; any ambiguity after the removal boundary must require recovery.

- [x] Re-discover and verify after every destructive boundary in every currently executable disposable profile, including partition -> PV -> LV -> filesystem.
- [ ] Keep shrink unsupported until it is separately designed and reviewed.

## M2 — Provisioning and swap

The TUI has a separate Create workflow. It starts from discovered free-space sources and
asks for the minimum necessary intent: destination, size, filesystem/use and optional
mountpoint. Low-level layout steps are generated automatically.

- [x] M2A1: freeze a deterministic, non-executing blank-disk -> one partition -> ext4/XFS provisioning intent from a successful Create preview; revalidate exact blank-disk state/geometry and defer mount/fstab activation to a later gate.
- [x] M2A2: bind the exact M2A1 intent to a separate compile-time production activation contract; profile/integrity are revalidated and the sealed activation remains execution_enabled=false with no table/mkfs crossing.
- [x] M2A3: require an exact root-owned 0600 runtime-consent document bound to one M2A2 activation ID, create-intent ID, disk and filesystem; the receipt remains non-executing.
- [x] M2A4: pin the exact verified create-consent inode/content across later authorization; pathname replacement or in-place mutation invalidates the lease.
- [x] M2A5: seal the exact M2A2 activation plus revalidated M2A4 pinned consent into a deterministic non-spawning create execution permit; partition-table/mkfs mutation flags remain false.
- [x] M2A6: fresh create runtime preflight revalidates the exact blank-disk state/geometry, M2A5 permit and pinned consent, then resolves trusted sfdisk/partx/mkfs identities without spawning.
- [x] M2A7: pin the exact M2A6 sfdisk/partx/mkfs executable objects by open descriptor and rehash/revalidate them without spawning.
- [x] M2A8: freeze the exact descriptor-based create launch contract after M2A7 tool pinning: fixed sfdisk stdin/argv, exact partx partition-map add, exact ext4/XFS mkfs argv, pinned ELF identity, fixed environment and mandatory partition rediscovery before mkfs; no process is spawned.
- [x] M2A9: persist a typed create runtime journal before mutation, with irreversible boundaries for partition-table write and filesystem format; mkfs cannot be entered until a fresh partition rediscovery is durably verified, and any post-boundary failure can enter RecoveryRequired.
- [x] M2A10: first gated Create crossing executes only the exact descriptor-pinned sfdisk/partx stages after a durable pre-write boundary, then bounded fresh rediscovery must prove the exact single partition geometry before PartitionMappedVerified is persisted; mkfs is not executed.
- [x] M2A11: second gated Create crossing starts only from the exact persisted M2A10 PartitionMappedVerified journal and receipt, revalidates the complete authorization/consent/tool chain plus fresh partition geometry, durably enters BeginFilesystemFormat before executing only the exact pinned mkfs descriptor, then requires fresh exact ext4/XFS rediscovery before Completed; mount/fstab remain separate.
- [x] M2A12: seal a separate non-executing mount/persistence activation only from an integrity-valid completed M2A11 filesystem; bind the fresh canonical filesystem UUID, exact existing empty mountpoint inode/metadata, portable fstab source/options and absence of mount/fstab/swap conflicts; no mkdir, mount process or fstab write is reachable.
- [x] M2A13: add the fresh runtime mount preflight and pinned mount executable lease, including complete collector/geometry/UUID conflict revalidation, exact root-owned mountpoint inode recheck, descriptor-pinned trusted mount identity, and a non-spawning `mount -n -t ... -o rw UUID=... TARGET` fexecve contract; fstab mutation remains separately gated.
- [x] M2A14: execute the exact pinned mount descriptor only after recomputing the complete fresh M2A13 preflight/launch chain, fsync-persist a dedicated mount journal before `fexecve`, and require bounded fresh disk/partition/filesystem/UUID/mount verification with unchanged fstab before Completed; ambiguous post-boundary failures enter RecoveryRequired.\n- [ ] M2A14b: prove the complete M2A12 -> M2A14 live mount path end to end on a root-owned disposable loop fixture, including restart/recovery evidence and explicit unmount cleanup.
- [ ] M2A15: atomically persist the exact sealed UUID-based fstab entry only after M2A14/M2A14b prove the live mount, with backup, inode recheck, fsynced temp+rename+directory fsync, parse/readback verification and recovery semantics.

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

# Safety model

Storage management is destructive by nature. Safety is an architectural requirement, not a UI warning.

## Invariants

- **M0/M1A storage planning is non-mutating.** No planner preview is an authorization to change partitions, LVM, filesystems, mounts, swap or persistent configuration.
- **Fail closed.** Unknown device types, incomplete dependency chains, contradictory metadata, unsupported layouts and stale identities block future write plans.
- **No implicit shell.** Commands are invoked directly with explicit argument vectors.
- **Intent does not override topology.** The operator chooses the target/result; the planner must prove the route through the actual storage graph.
- **Re-discover under the execution lock.** A future executor must acquire the host storage lock, rediscover the host and reject the operation if the selected target identity changed.
- **Backup before the relevant mutation.** Partition-table and LVM metadata backups are mandatory when those layers will be changed; a filesystem-only growth route must not pretend such backups provide filesystem rollback.
- **Verify after every mutation boundary.** A dependent layer may advance only after rediscovery proves the previous layer reached the expected state.
- **No blind replay after uncertainty.** Once a mutating command may have started, interruption or an unexpected result requires reconciliation/recovery, not automatic command repetition.

## Concurrency boundary

The first write-capable executor is designed around one nonblocking, host-exclusive storage-operation lock:

`/run/lock/linux-storage-manager/storage.lock`

The lock scope is intentionally broader than one disk, LV or mount. Two apparently independent operations can still share a disk, VG, device-mapper layer, multipath device, mount namespace or other storage dependency.

Important rules:

- the future executor must acquire the OS-backed advisory lock before its final rediscovery;
- a busy lock means another storage mutation is in progress and the new operation fails closed;
- deleting a lock pathname is never evidence that a lock is stale;
- target resource keys are journal/audit metadata, not permission to bypass the host-exclusive lock.

## Implemented host-lock primitive

M1B1 adds a narrow Linux advisory-lock primitive without enabling storage mutation.

- the lock path remains `/run/lock/linux-storage-manager/storage.lock`;
- acquisition is nonblocking and host-exclusive via an OS-backed `flock`;
- a busy lock fails closed instead of waiting or racing another operation;
- the lock file is opened with `O_NOFOLLOW` and `O_CLOEXEC`, and must resolve to a regular file;
- the immediate lock directory must be a real directory rather than a symlink;
- lock ownership is RAII-scoped and closing/dropping the handle releases the kernel lock;
- no code treats deleting a lock pathname as stale-lock recovery;
- this primitive has no storage-command API and `MUTATION_ENABLED` remains false.

The primitive is not yet wired to a mutation-capable executor. Explicit owner acceptance remains required before that rollout.

## Target identity and stale-plan rejection

M1A already models a target-scoped identity manifest for the selected route. It records relevant disk/partition/PV/VG/LV/filesystem/mount facts rather than hashing unrelated devices on the host.

A future executor must revalidate the manifest after acquiring the host lock and before mutation. Relevant changes include:

- disk model/serial/path or capacity;
- authoritative partition-table identity and sector geometry;
- PV/VG/LV UUIDs, layout and capacity/allocation facts;
- filesystem type/version/UUID;
- observed filesystem size separately from backing-device size;
- mount source/options;
- semantic route status/issue changes.

An unrelated disk appearing on the host does not by itself invalidate the selected target. A change to the selected storage chain does.

## Locked revalidation session

M1B2 connects the M1B0 frozen handoff to the M1B1 host lock without enabling execution.

- the session rejects blocked or mutation-enabled handoffs before acquiring a lock;
- the host-exclusive lock is acquired before the caller supplies the fresh snapshot and capability inventory;
- target identity is compared against the frozen target-scoped manifest while the lock remains held;
- the complete tool-capability inventory is compared against the frozen handoff digest;
- any target-identity or capability change leaves the in-memory journal at `HostLockHeld` and blocks progress;
- a successful revalidation advances only to `IdentityRevalidated`;
- a failed revalidation cannot be retried inside the same session; the lock must be released and a fresh plan/handoff built;
- no API in this session can approve a plan, enter `Executing`, persist a journal, or run a storage command;
- `MUTATION_ENABLED` remains false and owner acceptance remains required before mutation-capable rollout.

## Filesystem health and growth decisions

Read-only metadata is evidence, not permission to repair or resize.

### ext4

- `tune2fs -l` is used only for read-only superblock metadata, feature flags and block geometry.
- A mounted, read-write ext4 filesystem with complete metadata and a clean superblock state can be classified as an online-grow candidate.
- `e2fsck` output from a mounted filesystem is not accepted as an executor health decision.
- When an offline check is required, the modeled command is `e2fsck -f -n DEVICE` and the filesystem must be unmounted.
- Linux Storage Manager must never silently turn a read-only check into repair mode.

### XFS

- XFS growth requires a validated mounted read-write filesystem.
- `xfs_info` supplies read-only filesystem feature/data geometry evidence.
- `xfs_growfs -n MOUNTPOINT` validates the growth path without changing the filesystem.
- Before future mutation, the modeled health gate is an explicit no-modify/no-optimization scrub: `xfs_scrub -n -k MOUNTPOINT`.
- Ordinary discovery refresh must not launch expensive health scans automatically.

Unknown filesystems or unsupported feature/layout combinations remain visible but require a dedicated adapter.

## Disposable partition-table recovery drill

M1B6 validates partition-table recovery only inside the root-only disposable integration harness.

- the drill accepts only loop devices created and ownership-checked by the harness;
- it runs separately for GPT and DOS/MBR;
- an ext4 sentinel is written and the filesystem is cleanly unmounted before table mutation;
- baseline and restored table identity/geometry are compared from `sfdisk --json`, not parsed human-readable output;
- the backup artifact is captured with `sfdisk --dump` and verified readable before mutation;
- the controlled mutation keeps the partition start unchanged and only grows the end inside a guarded free tail;
- the exact backup is then restored, kernel partition state is refreshed, and authoritative JSON facts must match the baseline exactly;
- the filesystem is remounted and the sentinel must match byte-for-byte;
- once table mutation begins, any ambiguity marks fixture state uncertain and automatic cleanup refuses to guess;
- none of these mutation calls are reachable from the production CLI, TUI, executor crate or backup-manifest API.

This is recovery-test evidence, not permission to enable the production backup/restore executor path.

## Immutable metadata-backup manifest

M1B5 adds a pure backup/recovery manifest without executing any backup or restore command.

- required backup steps are derived only from the frozen `PlanPreview` operations in the M1B handoff;
- partition-table backup identity must match the frozen disk/table label/table ID in the target manifest;
- LVM backup identity must resolve the exact frozen VG UUID to one frozen VG name;
- command descriptions are explicit program/argv/stdin/stdout fields rather than shell strings;
- partition capture is modeled as `sfdisk --dump DISK` to a dedicated artifact; recovery is separately modeled as `sfdisk DISK` with that artifact as stdin;
- LVM capture/recovery are modeled as `vgcfgbackup --file ... VG` and `vgcfgrestore --file ... VG`;
- capture specs are marked non-mutating for storage metadata; recovery specs are explicitly marked mutating;
- restore drills remain limited to disposable fixtures or an explicit future recovery workflow;
- blocked handoffs cannot produce an executor backup manifest;
- manifest identity is repeatable and bound to the exact handoff, plan and target manifest digest.

No command runner consumes these specs in M1B5.

## Durable journal storage primitive

M1B3 adds persistence for the existing journal state machine without enabling execution.

- records are written to the application journal directory through a same-directory temporary file, `fsync`, atomic rename and directory `fsync`;
- durable journal files are mode `0600`, opened with `O_NOFOLLOW` and `O_CLOEXEC`;
- directory components must be real directories rather than symlinks;
- the journal ID, plan ID and baseline manifest digest are validated as frozen SHA-256 identities;
- reload validates schema, event sequence, phase continuity, allowed transitions and the mutation-boundary flag before returning an `OperationJournal`;
- impossible/tampered histories fail closed;
- a persisted `RecoveryRequired` record reloads as `RecoveryRequired`; persistence never converts it into an automatic retry state;
- the store has no API for running storage tools and does not satisfy the owner-acceptance gate by itself.

The mutation-capable executor must later persist the relevant state before crossing the first mutation boundary; that wiring remains gated.

## Durable locked-session progression

M1B4 connects the M1B2 locked revalidation session to the M1B3 durable store while mutation remains disabled.

- entering a durable session acquires the host-exclusive lock and durably records `HostLockHeld` before returning the session;
- successful target/capability revalidation advances and durably records `IdentityRevalidated` while the same host lock remains held;
- blocked identity/capability revalidation does not advance the durable journal;
- a journal persistence failure aborts session construction or revalidation and the session cannot retry the failed revalidation;
- if initial durable persistence fails, the owned lock handle is dropped and the kernel lock is released;
- no precondition, approval, execution or verification transition is exposed by this session;
- `MUTATION_ENABLED` remains false and owner acceptance remains a separate required gate.

The future mutation-capable path must continue persistence through preconditions/approval and must durably cross into `Executing` before launching a mutating tool.

## Operation journal and crash boundary

M1A defines a future execution journal state machine:

`Planned -> HostLockHeld -> IdentityRevalidated -> PreconditionsVerified -> Approved -> Executing -> Verifying -> Completed`

Terminal alternatives are `Aborted` and `RecoveryRequired`.

Rules:

- approval is valid only for the exact frozen plan ID after fresh locked revalidation;
- the durable journal must exist before entering the first mutating execution boundary;
- before `Executing`, interruption may abort and require a completely fresh plan;
- once `Executing` is entered, a crash can occur after a mutating syscall/tool starts but before the next journal write;
- therefore any interruption from `Executing` or `Verifying` becomes `RecoveryRequired`;
- `RecoveryRequired` is terminal for automatic execution. The system must rediscover and reconcile reality before a new plan is produced.

## Blank-disk provisioning policy

A blank disk is never treated as "all bytes are freely writable" in a Create plan.

- authoritative partition-table discovery must complete and still report no table;
- the selected disk/loop must still have no children, filesystem, mount or active swap use;
- logical-sector size and raw capacity must match the discovered Create source;
- the planner requires a concrete GPT or DOS/MBR policy before freezing geometry;
- GPT reserves primary and backup header/entry-array sectors; DOS/MBR respects the 32-bit LBA range;
- the first partition is aligned to a 1 MiB boundary using the actual logical-sector size;
- CLI callers choose the policy with `--partition-table gpt|dos`;
- the TUI shows GPT as the visible default and allows switching to DOS/MBR with `t`;
- all of this remains preview-only until a separately approved write-capable executor exists.

## Unusable partition-table evidence

A disk is not free space merely because usable ranges cannot be calculated.

- a disk that still reports a partition-table marker is never reclassified as blank solely because authoritative table geometry is absent;
- an authoritative table with an unsupported label, incomplete bounds or internally inconsistent ranges is exposed as a blocked disk with zero allocatable capacity;
- blocked disks cannot enter a Create allocation route and must direct the operator toward recovery/reconciliation;
- direct Grow keeps returning explicit partition-table/geometry blockers instead of guessing adjacent capacity.

## Protected boot partition roles

Generic partition growth must not treat boot metadata as ordinary data capacity.

- known GPT EFI System, BIOS Boot and Extended Boot Loader partition types are blocked from the generic direct-partition Grow route;
- known MBR boot-loader/EFI partition types are blocked the same way;
- the authoritative partition type must be present and well-formed before a GPT partition can enter the generic Grow route;
- a protected partition requires a separately designed and proven workflow even if a supported filesystem is unexpectedly detected on it;
- DOS/MBR sectors before the first partition remain unavailable to generic Create planning because they may contain bootloader embedding data.

## Future operation classes

Every planned step carries a reversibility classification:

- `NotApplicable`
- `Reversible`
- `Irreversible`

A workflow containing an irreversible step must state that explicitly before execution. A label of “reversible” refers only to the modeled metadata step; it must not be interpreted as a promise that user data can be rolled back.

## Root privileges

Inspection should run unprivileged where possible. Future privileged operations should be isolated, minimal, auditable and invoked only after a validated plan, host lock, fresh revalidation and required approval.

## Unsupported examples in early write releases

- moving a partition start sector;
- shrinking filesystems/LVs/PVs/partitions;
- shrinking XFS;
- automatic RAID recovery;
- filesystem conversion;
- guessing through unknown device-mapper/multipath/encryption stacks;
- automatic filesystem repair as a resize side effect;
- arbitrary shell hooks;
- blind resume/replay after a crash or uncertain mutation result.

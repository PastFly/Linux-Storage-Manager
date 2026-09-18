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

# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager. Default branch: master.
The owner made the repository public on 2026-09-18 so GitHub-hosted Actions can run.
Do not change visibility, billing, permissions or merge the default branch without
appropriate approval. Read AGENTS.md and docs/SAFETY.md before writing.

## Development boundary

- M0 remains unmerged PR #1.
- Continue on draft PR #2, `feature/m1a-read-only-planner`. It includes M0.
- No storage-mutating executor or `apply` command exists.
- Planner previews remain `dry_run=true` / `executable=false`.
- Extend/Create plans, filesystem health decisions, lock plans and operation journals are
  models for a future executor; they do not execute the modeled commands.
- A deliberate kernel-rescan control action exists in the TUI:
  - lowercase `r` = repeat read-only discovery only;
  - uppercase `R` = write `1` only to the validated selected disk
    `/sys/class/block/<kname>/device/rescan`, then repeat discovery.
  This updates only the kernel's capacity view. It does NOT edit partitions,
  filesystems, LVM, fstab or user data.
- No automatic rescan is hidden behind ordinary refresh.
- Any M1B storage-mutating executor requires separate explicit owner approval.

## Current exact validated code

Exact validated **code** head:

`b54fb59f4e5e071e76c1d1acc4624a086afd9bb6`

CI #360 / run `35393154385`:
- harness safety tests PASS;
- rustfmt PASS;
- Clippy with `-D warnings` PASS;
- Rust workspace tests PASS, including route profiles, filesystem-only ext4/XFS growth,
  target filesystem-size identity changes, filesystem policy and lock/journal state machine;
- disposable loop integration PASS.

Portable Linux #239 / run `35393154466`:
- static musl x86_64 PASS;
- static musl aarch64 PASS;
- same binaries smoke-tested across Debian 12, Ubuntu 22.04, Ubuntu 24.04,
  Rocky Linux 9 and Alpine 3.22;
- Debian 12 collector probe PASS.

Artifacts:
- CI-tested x86_64: `storagemgr-linux-x86_64-35393154385`
- portable x86_64: `storagemgr-linux-x86_64-musl-35393154466`
- portable aarch64: `storagemgr-linux-aarch64-musl-35393154466`

ROADMAP/HANDOFF/SAFETY documentation commits may follow that code head. Do not claim a
later **code** head is validated unless its own workflows have completed.

## Product direction

Normal usage is intent-first. The operator chooses the desired result, not a sequence of
Linux commands.

Primary workflows:

1. **Extend existing**
   - select a filesystem/mount/device/LV;
   - choose an additional size or maximum verified capacity;
   - inspect the automatically resolved route and safety gates;
   - a future executor performs only the proven required layers.
2. **Create new**
   - select discovered free space;
   - choose size and intended use;
   - choose filesystem/mountpoint only when relevant;
   - planner generates partition/LVM/filesystem/mount/swap steps.

When several partitions, filesystems or LVs exist, each relevant leaf target stays
selectable. Unsupported/ambiguous paths stay visible with the exact blocking reason.

See `docs/SCENARIO_MATRIX.md` for the scenario coverage contract.

## Read-only CLI and TUI surfaces

Important CLI commands:
- `storagemgr plan targets [--json]`
- `storagemgr plan route TARGET [--json]`
- `storagemgr plan filesystem TARGET [--json]`
- `storagemgr plan extend TARGET --by SIZE|--max [--json]`
- `storagemgr plan create-spaces [--json]`
- `storagemgr plan create SOURCE_ID --by SIZE|--max --purpose filesystem|swap [--fs ext4|xfs] [--mount PATH] [--json]`

Dashboard sections:
- Disks
- Volumes
- Swap
- Mounts
- Diagnostics
- Extend
- Create

Extend shows:
- semantic storage route;
- route adapter/block status;
- filesystem execution gate;
- selected growth amount;
- strict read-only preview;
- preflight checks and ordered future operations;
- chained/advisory alternatives where proven.

Create shows:
- discovered free-space sources;
- size selection;
- filesystem/swap purpose;
- ext4/XFS selection;
- live read-only generated route.

TUI mountpoint text entry for Create is not implemented yet; CLI can validate an optional
future mountpoint.

## Semantic layer route graph and Extend profiles

M1A has a pure semantic route analyzer. It can describe routes such as:

`disk -> partition -> PV -> VG -> LV -> filesystem -> mount`

It also exposes unsupported layers rather than hiding them:
- LUKS/device-mapper encryption;
- RAID;
- multipath;
- multi-PV/nonstandard LVM;
- Btrfs/ZFS/unknown filesystems;
- zram/ROM/unknown block layers.

Each route is classified as `SupportedProfile`, `AdapterRequired` or `Blocked`.

`plan_extend` now uses the semantic graph to select the existing proven builder:
- `DirectPartition`
- `Lvm`
- `WholeBlockFilesystem`
- `LegacyFailClosed`

The direct-partition and LVM geometry/extent math was deliberately retained rather than
rewritten during this refactor. Layered unsupported targets now receive semantic issue
codes such as `luks-adapter-required` instead of unrelated fallback errors.

The remaining refactor is to move chained LVM and Create generation onto reusable route
adapters rather than topology-specific branches.

## Planner profiles

### Direct partition

Strict preview supports:
- mounted read-write ext4/XFS directly on a normal partition;
- DOS/MBR or GPT;
- authoritative lsblk+sfdisk sector/start/size agreement;
- verified directly adjacent free sectors;
- sector-aligned frozen growth;
- no moving partition starts;
- no DOS logical-partition growth inside an extended container.

### Existing LVM free capacity

Strict preview supports:
- mounted read-write ext4/XFS;
- normal public active linear LV;
- complete local single-PV VG;
- existing free extents;
- verified PV/VG/LV/filesystem identities.

Route:
`VG free -> LV -> filesystem`.

### Chained LVM underlying capacity

Read-only advisory detection supports:
1. whole-disk/loop PV whose backing device is already larger than the PV:
   `larger disk -> pvresize -> VG -> LV -> filesystem`;
2. PV on a normal partition where authoritative geometry proves free sectors directly
   after it:
   `disk tail -> partition end growth -> pvresize -> VG -> LV -> filesystem`.

The route records exact disk/PV/VG/LV identities, extent/sector sizes, existing VG free
capacity, PV device slack, adjacent raw capacity, maximum growth and required partition
growth. M1A does not execute it.

### Whole-device filesystem

Strict read-only preview now supports ext4/XFS directly on a disk/loop when the block
device is already larger than the filesystem.

Filesystem geometry comes from filesystem metadata, not from guessing:
- ext4: `tune2fs -l` block count × block size;
- XFS: `xfs_info` data block size × data block count.

The planner proves:
- exact device/mount/filesystem identity;
- filesystem geometry consistency;
- filesystem size <= backing device size;
- verified grow-tool availability;
- growth rounded to filesystem block size.

The strict plan is:
`revalidate -> grow filesystem -> rediscover/verify`

It does not claim partition/LVM metadata backup as a rollback mechanism because those
layers are not modified.

Tests cover:
- ext4 maximum verified slack;
- XFS maximum verified slack;
- `--by` rounding to a 4 KiB filesystem block;
- target catalog verified capacity.

## Filesystem decision policy

M1A has an executor-grade **decision model**, but it does not execute health commands or
repairs.

States:
- `ReadyOnlineGrow`
- `ReadOnlyHealthCheckRequired`
- `OfflineHealthCheckRequired`
- `MountRequired`
- `Blocked`
- `AdapterRequired`

### ext4

- `tune2fs -l` supplies read-only state/version/features/geometry.
- Mounted read-write ext4 with complete evidence and clean superblock state can be an
  online-grow candidate.
- Mounted `e2fsck` output is not accepted as an execution health decision.
- When an offline check is required, the modeled command is
  `e2fsck -f -n DEVICE` and the filesystem must be unmounted.
- Automatic repair is forbidden.

### XFS

- target must be mounted read-write for growth;
- `xfs_info` supplies features/data geometry;
- `xfs_growfs -n MOUNTPOINT` validates the growth path without mutation;
- the remaining explicit health gate is modeled as
  `xfs_scrub -n -k MOUNTPOINT`;
- ordinary refresh never launches the expensive scrub automatically.

Capability inventory includes `xfs_scrub`.

## Target-scoped identity guard

M1A can capture a target identity manifest and revalidate it against a fresh snapshot.
It is scoped to the selected route, so an unrelated disk appearing does not invalidate a
plan.

The manifest records:
- disk/device path, kernel identity, model/serial, UUIDs and backing capacity;
- authoritative partition-table label/ID and exact sector geometry;
- PV/VG/LV UUIDs, layouts and capacity/allocation facts;
- filesystem type/version/UUID;
- observed filesystem size separately from backing-device size;
- active mount source/options;
- semantic route status/issue codes.

Regression tests prove changes to target geometry, LVM identity/capacity and observed
filesystem size invalidate the manifest.

## Future execution lock and journal model

No lock is currently used to authorize storage writes because no executor exists. M1A
models the future boundary.

Host-exclusive lock path:
`/run/lock/linux-storage-manager/storage.lock`

Design:
- one nonblocking OS-backed advisory lock for the whole host;
- do not infer stale state by deleting a pathname;
- acquire lock before the final rediscovery;
- revalidate the selected target identity while the lock is held.

Journal directory:
`/var/lib/linux-storage-manager/journal`

State model:
`Planned -> HostLockHeld -> IdentityRevalidated -> PreconditionsVerified -> Approved -> Executing -> Verifying -> Completed`

Terminal alternatives:
- `Aborted`
- `RecoveryRequired`

Approval must match the exact fresh plan ID. Once `Executing` is entered, a crash may
occur after mutation started but before the next journal write; any interruption from
that point requires reconciliation and forbids blind automatic replay.

## Create/free-space planning

M1A discovers:
- free extents in an existing VG;
- verified internal GPT/DOS free ranges;
- verified raw disk tail;
- verified blank disks.

Sources have stable SHA-based IDs. CLI accepts the full ID or a unique 16+ character
prefix.

Read-only Create intent planning supports:
- exact size or maximum verified source capacity;
- filesystem or swap purpose;
- ext4/XFS filesystem intent;
- optional future mountpoint validation in CLI;
- sector-aligned partition allocation for gap/tail sources;
- extent-aligned LV allocation for VG-free sources.

Blank-disk exact allocation remains blocked until partition-table/alignment policy is
explicitly resolved. The planner never guesses GPT versus DOS/MBR policy.

No Create operation is executable in M1A.

## Live Debian 12 evidence

Host used for real topology observation: srv-phpIPAM.

Original DOS layout:
- `/dev/sda1`: ext4 root `/`
- `/dev/sda2`: DOS extended container
- `/dev/sda5`: active swap logical partition

Before VM-disk rescan Linux reported `/dev/sda = 10 GiB`.
After the user increased the virtual disk and selected-disk kernel rescan was performed,
Linux reported `/dev/sda = 11 GiB` while partitions remained unchanged.

The new ~1 GiB tail is not adjacent to `sda1`; the extended/swap partitions sit between
root and the new tail. The planner correctly did not pretend root could consume it
directly.

A narrow non-executable swap-partition -> swapfile migration alternative is modeled for
this shape, but migration remains blocked until hibernation/resume safety and execution
support are explicitly implemented.

## Remaining gates before any executor work

Read-only design now exists for identity revalidation, filesystem decisions, host lock
and interruption journal. Remaining work before any write-capable executor includes:

- implement verified partition-table and LVM backup creation plus restore/recovery drills;
- define/implement durable journal persistence semantics (fsync/atomic replacement,
  permissions, corruption handling);
- define exact privileged-helper boundary and command allowlist;
- wire lock + fresh discovery + identity revalidation + filesystem decision + exact
  approval into the future executor;
- complete semantic route adapters for chained LVM/Create and advanced stacks;
- dedicated safety adapters for multi-PV LVM, LUKS, mdraid, multipath, Btrfs,
  thin/cache/RAID/snapshot LVM and ZFS;
- hibernation/resume-aware swap migration;
- explicit owner approval for exact reviewed code before any M1B executor work.

No merge to master without explicit owner approval. Preserve Cargo.lock and use
`--locked`. Cache unchanged blob SHAs during one working context.

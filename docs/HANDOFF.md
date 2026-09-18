# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager. Default branch: master.
The owner made the repository public on 2026-09-18 so GitHub-hosted Actions can run.
Do not change visibility, billing, permissions or merge the default branch without
appropriate approval. Read AGENTS.md and docs/SAFETY.md before writing.

## Development boundary

- M0 remains unmerged PR #1.
- Continue on draft PR #2, `feature/m1a-read-only-planner`. It includes M0.
- No executor or apply command exists.
- Strict planner previews remain `dry_run=true` / `executable=false`.
- The new Extend/Create catalogs and chained growth routes are advisory/read-only.
- A deliberate kernel-rescan control action exists in the TUI:
  - lowercase `r` = repeat read-only discovery only;
  - uppercase `R` = write `1` only to the validated selected disk
    `/sys/class/block/<kname>/device/rescan`, then repeat discovery.
  This updates only the kernel's capacity view. It does NOT edit partitions,
  filesystems, LVM, fstab or user data.
- No automatic rescan is hidden behind ordinary refresh.
- Any M1B storage-mutating executor requires separate explicit owner approval.

## Current exact validated code

Exact validated code head:

`cba3f17de0adc4eb9631c90709bffcdea3875423`

CI #312 / run `35387848591`:
- harness safety tests PASS;
- rustfmt PASS;
- Clippy with `-D warnings` PASS;
- Rust workspace tests PASS, including Create, route-graph and target-identity regression tests;
- repeated disposable loop integration PASS.

Portable Linux #191 / run `35387848583`:
- static musl x86_64 PASS;
- static musl aarch64 PASS;
- same binaries smoke-tested across Debian 12, Ubuntu 22.04, Ubuntu 24.04,
  Rocky Linux 9 and Alpine 3.22;
- Debian 12 collector probe PASS.

Artifacts:
- CI-tested x86_64: `storagemgr-linux-x86_64-35387848591`
- portable x86_64: `storagemgr-linux-x86_64-musl-35387848583`
- portable aarch64: `storagemgr-linux-aarch64-musl-35387848583`

The branch may contain documentation-only commits after that code head. Do not claim a
later code head is validated unless its own workflows have completed.

## Product direction

Normal usage is intent-first. The operator should choose the desired outcome, not compose
Linux storage commands.

Primary workflows:

1. **Extend existing**
   - select a filesystem/mount/device/LV;
   - choose an additional size or maximum safe capacity;
   - inspect the automatically resolved route;
   - future executor performs only the verified required layers.
2. **Create new**
   - select discovered free space;
   - choose size and intended use;
   - choose filesystem/mountpoint only when relevant;
   - planner generates partition/LVM/filesystem/mount/swap steps.

When several partitions, filesystems or LVs exist, each relevant leaf target must remain
visible. Unsupported/ambiguous paths are shown as blocked with the exact reason rather
than silently omitted.

See `docs/SCENARIO_MATRIX.md` for the scenario coverage contract.

## Read-only target and provisioning catalogs

M1A exposes a storage-target catalog:
- direct filesystem partitions;
- normal LVM logical-volume filesystems;
- other/layered leaf filesystems as visible blocked targets when no proven route exists.

Each target records:
- target/mountpoint and device;
- filesystem;
- current block size;
- currently verified growth capacity;
- additional advisory underlying/layout capacity where proven;
- preview/advisory/blocked status and reason.

M1A also exposes a Create/free-space catalog:
- free extents in an existing VG;
- verified internal GPT/DOS free ranges;
- verified raw disk tail behind a partition table;
- verified blank disks.

Every source has a stable SHA-based ID. CLI accepts the full ID or a unique 16+
character prefix.

Read-only Create intent planning supports:
- exact size or maximum verified source capacity;
- filesystem or swap purpose;
- ext4/XFS filesystem intent;
- optional future mountpoint validation in CLI;
- sector-aligned partition allocations for verified gap/tail sources;
- extent-aligned LV allocations for VG-free sources.

Blank-disk exact allocation remains blocked until a partition-table/alignment policy is
explicitly resolved. The planner never guesses GPT/DOS policy.

CLI:
- `storagemgr plan targets [--json]`
- `storagemgr plan route TARGET [--json]`
- `storagemgr plan create-spaces [--json]`
- `storagemgr plan create SOURCE_ID --by SIZE|--max --purpose filesystem|swap [--fs ext4|xfs] [--mount PATH] [--json]`

No Create operation is executable in M1A.

## Semantic layer route graph

M1A now has a pure read-only semantic route analyzer. It resolves the selected target
into an ordered topology such as:

`disk -> partition -> PV -> VG -> LV -> filesystem -> mount`

and can also expose layers that are not yet writable by the generic planner:

- LUKS/device-mapper encryption;
- RAID;
- multi-PV or nonstandard LVM;
- Btrfs/ZFS/unknown filesystems;
- zram/ROM/unknown block layers.

Each route is classified as `SupportedProfile`, `AdapterRequired` or `Blocked`.
Unsupported layers stay visible with an explicit issue code instead of disappearing.

The route is available through `storagemgr plan route TARGET [--json]` and is summarized
inside the TUI Extend view. Route analysis performs no storage mutation.

## Target-scoped identity guard

M1A can capture a target identity manifest and revalidate it against a fresh snapshot.
The manifest is intentionally scoped to the selected storage chain and records:

- disk/device path, kernel identity, model/serial, UUIDs and capacity;
- authoritative partition-table label/ID and exact sector geometry;
- PV/VG/LV UUIDs, sizes and relevant allocation facts;
- filesystem type/version/UUID/capacity;
- active mount source/options;
- semantic route status and route issue codes.

Revalidation reports classified changes such as partition geometry, LVM identity/capacity,
filesystem identity, mount state or device-chain replacement. A change to an unrelated
disk does not invalidate the selected target manifest.

Future M1B execution should acquire the exclusive operation lock, rediscover the host,
revalidate this target manifest, and reject the operation before mutation if any relevant
identity changed.

## Planner profiles

### Existing VG free capacity

Strict preview supports:
- mounted read-write ext4/XFS;
- normal public active linear LV;
- complete local single-PV VG;
- existing free extents;
- verified PV/VG/LV/filesystem identities.

This route remains a strict non-executable preview:
`VG free -> LV -> filesystem`.

### Chained LVM underlying-capacity routes

The planner can now detect additional capacity below an LVM stack and expose an advisory
automatic route when the normal VG-free preview is insufficient.

Supported conservative M1A analysis:

1. PV is directly on a disk/loop and the backing device is already larger than the PV:
   `larger disk -> pvresize -> VG -> LV -> filesystem`.
2. PV is on a normal partition and authoritative geometry proves free sectors directly
   after that partition:
   `disk tail -> partition end growth -> pvresize -> VG -> LV -> filesystem`.

The route records exact disk/PV/VG/LV identities, optional partition, extent/sector
sizes, current VG free capacity, PV backing-device slack, verified adjacent raw
capacity, maximum growth, required partition growth and ordered future steps.

These routes are still `Blocked` / `executable=false` in M1A. They are evidence for
future M1B automation, not permission to mutate storage.

### Direct partition

Strict preview supports:
- mounted read-write ext4/XFS directly on a normal partition;
- DOS/MBR or GPT;
- authoritative lsblk+sfdisk sector/start/size agreement;
- verified directly adjacent free sectors;
- sector-aligned frozen growth;
- no moving partition starts;
- no DOS logical-partition growth inside an extended container.

## Live Debian 12 evidence

Host: srv-phpIPAM.

Original DOS layout:
- `/dev/sda1`: ext4 root `/`
- `/dev/sda2`: DOS extended container
- `/dev/sda5`: active swap logical partition

Before VM-disk rescan Linux reported `/dev/sda = 10 GiB`.

After the user increased the virtual disk and the validated selected-disk kernel rescan
was performed, Linux reported:
- `/dev/sda = 11 GiB`;
- partitions unchanged;
- TUI correctly reported Size 11.0 GiB and Tail free 1.0 GiB.

The new ~1 GiB tail is NOT directly adjacent to `sda1`: `sda2/sda5` sit between
root and the new tail. Direct root growth therefore still sees only the ~1023 KiB
pre-extended gap. This is expected topology behavior, not stale discovery.

## Disk-tail swap migration opportunity

The planner exposes a deliberately narrow non-executable DOS layout opportunity when a
primary filesystem is followed only by an extended container with one active Linux swap
logical partition, raw tail capacity exists and equivalent swap can be preserved.

For the live Debian 12 layout, a future route can model:
1. verify swap is not needed for hibernation/resume;
2. back up partition/fstab/resume metadata;
3. prepare swap migration;
4. deactivate old swap;
5. remove the logical swap and extended container;
6. grow root while reserving equivalent swap capacity;
7. grow ext4;
8. create/activate equivalent swapfile and update persistent config;
9. rediscover and verify.

M1A DOES NOT execute any of those steps.

## Capability model

Distribution names do not decide support. The normalized model is capability-based.

Discovery inventories tools needed for future routes, including:
- block/partition: `lsblk`, `blkid`, `sfdisk`, `partprobe`, `udevadm`;
- LVM: `pvs`, `vgs`, `lvs`, `pvresize`, `pvcreate`, `vgcfgbackup`,
  `vgcreate`, `vgextend`, `lvextend`, `lvcreate`;
- filesystems: `resize2fs`, `e2fsck`, `tune2fs`, `xfs_growfs`,
  `xfs_info`, `xfs_repair`, `mkfs.ext4`, `mkfs.xfs`;
- mount/swap: `findmnt`, `mount`, `umount`, `swapon`, `swapoff`, `mkswap`;
- advanced stacks: `cryptsetup`, `mdadm`, `btrfs`, `multipath`, `zpool`, `zfs`.

M1A only checks availability; it does not invoke mutating tools.

## Preflight model

Successful strict previews contain structured preflight checks.

Verified examples:
- required collectors complete;
- no error-level diagnostics;
- one matching read-write mount;
- required operation tools available;
- partition geometry or LVM identities/capacity consistent.

Required before future execution:
- target-scoped fresh runtime identity recheck (read-only manifest/revalidation is now implemented);
- executor-grade filesystem health/grow decision, including any required offline check;
- exclusive operation lock;
- verified partition/LVM metadata backup where relevant;
- recovery procedure validation;
- explicit approval of the exact fresh plan.

Blocked plans never pretend these future execution gates passed.

## TUI state

Dashboard sections:
- Disks
- Volumes
- Swap
- Mounts
- Diagnostics
- Extend
- Create

Current UI:
- structured tables for devices/volumes/mounts/swap;
- structured Diagnostics list with Details panel;
- capabilities panel;
- responsive Extend view with Summary / Preflight / Plan steps;
- semantic storage-route summary with explicit adapter/block reason;
- selectable filesystem targets even when a route is blocked;
- automatic chained LVM route details where proven;
- compact fallback on narrow terminals;
- DOS extended container rendered as a container;
- Tail free shown in disk Details;
- advisory Can Grow analysis;
- strict plan preview;
- Tail opportunity summary and detailed advisory layout alternative;
- Create free-space source table/details;
- live read-only Create preview with source, size, filesystem/swap purpose and ext4/XFS selection;
- exact blocked reason for unsupported filesystems instead of hiding targets;
- contextual toolbar.

Key controls:
- navigation: arrows / Tab / 1-7;
- Extend size: PgUp/PgDn plus legacy +/-/[ ];
- Create: ↑/↓ source, PgUp/PgDn size, `p` filesystem/swap, `f` ext4/XFS;
- TUI mountpoint text entry is not implemented yet; CLI can validate an optional mountpoint;
- `r` = discovery refresh;
- `R` = selected-disk kernel rescan + refresh;
- `q`/Esc = quit.

Only `KeyEventKind::Press` mutates state; Repeat/Release are ignored.

## Remaining gates before any executor work

- executor-grade filesystem health decision policy, including required offline checks;
- concurrency and per-host exclusive locking design;
- wire the validated target identity manifest into the future executor immediately before every mutation boundary;
- verified backup policy and recovery drills;
- operation journal/resume semantics for interruption or power loss;
- dedicated safety adapters for multi-PV LVM, LUKS, mdraid, multipath, Btrfs,
  thin/cache/RAID/snapshot LVM and other layered topologies;
- explicit owner approval for exact reviewed code before any M1B executor work.

No merge to master without explicit owner approval. Preserve Cargo.lock and use
`--locked`. Cache unchanged blob SHAs during one working context.

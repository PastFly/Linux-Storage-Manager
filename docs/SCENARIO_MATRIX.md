# Storage Scenario Matrix

This document is the coverage contract for Linux Storage Manager. The goal is not to
hard-code a distro-specific recipe. The goal is to accept high-level user intent,
discover the actual storage graph, resolve a safe route through that graph, and fail
closed when a route cannot be proven.

Status vocabulary:

- **Preview now** — M1A can discover/model the case without storage mutation.
- **Planned write** — intended for the first guarded executor/provisioning releases.
- **Later adapter** — requires a dedicated topology/filesystem adapter before mutation.
- **Never automatic** — must not be guessed or silently performed.

## User-facing intent

### Extend existing

1. Select the target filesystem/mount/device/LV.
2. Select `+size` or `maximum safe`.
3. Review the automatically generated route and resulting size.
4. In a future executor, confirm the exact fresh plan.

The user should not need to know whether the correct route is filesystem-only,
LV + filesystem, PV + VG/LV + filesystem, partition + PV + VG/LV + filesystem,
partition + filesystem, or a supported migration such as swap partition -> swapfile.

### Create new

1. Select a free-space source.
2. Choose size and purpose: filesystem volume, LVM capacity, or swap.
3. Choose filesystem and mountpoint only when applicable.
4. Review the automatically generated topology before any write.

Advanced details remain inspectable but are not mandatory for routine use.

## A. Backing capacity changes

| Scenario | Current | Target behavior |
| --- | --- | --- |
| Virtual/physical disk enlarged but kernel still reports old size | Preview now | Explicit selected-disk rescan, then rediscover; never hide a rescan behind ordinary refresh |
| Kernel sees larger disk and target partition has adjacent raw tail | Preview now | Partition end -> filesystem or partition -> PV -> VG -> LV -> filesystem |
| Partition/backing device is already larger than LVM PV | Preview now | `pvresize` -> VG -> LV -> filesystem |
| Whole-disk PV is on an enlarged disk | Preview now | `pvresize` -> VG -> LV -> filesystem |
| Existing VG already has free extents | Preview now | LV -> filesystem |
| No underlying physical capacity exists | Preview now | Report zero safe growth; never fabricate capacity |
| Storage device identity changed since preview | Planned write | Reject stale plan and rediscover before mutation |

## B. Partition-table layouts

| Scenario | Current | Target behavior |
| --- | --- | --- |
| GPT normal partition with adjacent free sectors | Preview now | Guarded partition-end growth or new partition |
| DOS/MBR primary with adjacent free sectors | Preview now | Guarded partition-end growth after slot/boundary validation |
| DOS extended/logical partition chain | Preview now | Model container/siblings conservatively; dedicated write route required |
| Raw free tail after last partition | Preview now | Offer as Create source and as input to proven growth routes |
| Free internal gap between partitions | Preview now | Expose exact verified sector range; future write still revalidates alignment and partition-slot policy |
| Multiple filesystem partitions/LVs | Preview now | Show each leaf target explicitly so the user chooses the one to extend |
| EFI System Partition / BIOS boot / bootloader metadata areas | Preview now as topology | Protect by role/type; never resize/reformat automatically without a dedicated proven route |
| Partition start would need to move | Never automatic | Block; first write releases only move partition ends |
| Geometry disagreement between sources | Preview now | Block all affected mutation routes |
| Corrupt/unknown partition table | Preview now as diagnostics | Block write and direct user to recovery/repair workflow |

## C. LVM

| Scenario | Current | Target behavior |
| --- | --- | --- |
| Normal active public linear LV, single-PV VG, existing VG free | Preview now | Extend LV and filesystem |
| Single PV on growable partition | Preview now advisory | Grow partition -> `pvresize` -> LV -> filesystem |
| PV backing device already larger than PV | Preview now advisory | `pvresize` -> LV -> filesystem |
| Whole-disk PV | Preview now advisory when backing slack exists | Same route without partition-table write |
| Add a new disk/partition as a PV to existing VG | Create source discovery partial | Planned write with explicit disk/PV/VG identity checks |
| Create new PV + VG + LV | Create source discovery partial | Planned write |
| Multi-PV ordinary VG | Discovery | Later guarded route with exact allocation impact |
| Thin pool / thin LV | Discovery facts where available | Later adapter |
| Cached LV | Discovery facts where available | Later adapter |
| LVM RAID/mirror | Discovery facts where available | Later adapter |
| Snapshot origin/snapshot | Discovery facts where available | Later adapter; block generic growth path |

## D. Filesystems

| Filesystem/state | Current | Target behavior |
| --- | --- | --- |
| ext4 mounted read-write | Preview now | Online grow where supported; offline checks when required |
| ext4 unmounted | Discovery | Planned explicit offline health/grow route |
| XFS mounted read-write | Preview now | Online grow |
| XFS unmounted | Discovery | Mount/health prerequisites must be explicit before grow |
| Btrfs single-device | Discovery | Later filesystem-aware adapter |
| Btrfs multi-device | Discovery | Later device/allocation-aware adapter |
| ZFS pool/dataset | Capability inventory | Later ZFS-specific adapter; do not treat as a normal partition filesystem |
| Unknown filesystem | Visible blocked target | Never guess a resize command |
| Read-only/bind/ambiguous mount | Preview diagnostics | Block until topology/state is unambiguous |
| Filesystem health/features incompatible with grow | Preflight planned | Block executor before first mutation |

## E. Layered storage stacks

| Stack | Current | Target behavior |
| --- | --- | --- |
| Partition -> LVM -> ext4/XFS | Preview now for conservative profiles | Automatic route across proven layers |
| Whole disk -> LVM -> ext4/XFS | Preview now for conservative profiles | Automatic route across proven layers |
| Partition -> LUKS -> filesystem | Discovery topology | Later crypt-layer adapter |
| Partition -> LUKS -> LVM -> filesystem | Discovery topology | Later crypt + LVM chained adapter |
| mdraid -> filesystem | Discovery topology | Later mdraid adapter |
| mdraid -> LVM -> filesystem | Discovery topology | Later mdraid + LVM chained adapter |
| multipath/device-mapper -> LVM -> filesystem | Discovery/capability facts | Later multipath adapter |
| Unknown nested device-mapper stack | Visible blocked | Never infer mutation order |

Each adapter must prove parent/child identity, size propagation semantics, required tools,
online/offline constraints and the correct rediscovery point between layers.

## F. Swap and hibernation

| Scenario | Current | Target behavior |
| --- | --- | --- |
| Swap file | Discovery | Planned create/resize/activate/deactivate lifecycle |
| Swap partition | Discovery | Planned guarded lifecycle |
| DOS extended container holds only active swap and blocks root growth | Preview now advisory | Optional swap-partition -> swapfile migration route |
| Swap partition mixed with unrelated payload partitions | Preview diagnostics | Block generic migration |
| Hibernation/resume may reference swap identity | Planned preflight | Never migrate swap until resume configuration is detected and safely updated |
| Insufficient space to preserve equivalent swap | Preview now | Do not offer migration as safe capacity |

## G. Create/provision workflows

| Source / action | Current | Target behavior |
| --- | --- | --- |
| Existing VG free extents | Preview now + Create intent preview | Create LV -> filesystem/swap -> optional mount/fstab |
| Verified raw disk tail | Preview now + Create intent preview | Create partition -> filesystem/swap; later optional PV/VG/LV route |
| Verified blank disk | Preview now + exact Create intent preview with concrete GPT/DOS policy | Future guarded table init -> aligned primary partition -> filesystem/swap; GPT is visible TUI default, DOS/MBR is selectable |
| Internal verified free range | Preview now | Read-only Create plan from exact range; future executor revalidates alignment/slot policy before partition creation |
| New filesystem on partition/LV | Capability inventory | Planned write for ext4/XFS first |
| New swap file | Capability inventory | Planned write |
| New swap partition | Capability inventory | Planned write |
| New VG from one or more selected PVs | Partial discovery | Planned write with explicit disk selection |
| Persistent mount | fstab discovery now | Planned atomic guarded fstab update + validation |

Before creation, the preview must show the exact before/after topology and which
identifiers will be created.

## H. Distribution and tooling differences

Support is capability-based, not a hard-coded distribution whitelist.

Portable artifacts are currently tested across Debian 12, Ubuntu 22.04, Ubuntu 24.04,
Rocky Linux 9, AlmaLinux 9, Fedora 44 and Alpine 3.22.

Additional validation targets include RHEL, Arch, SUSE/openSUSE and other Linux systems. Equivalent storage capabilities should map into the same normalized
model.

Distro differences that may require adapters:
- command/package availability and paths;
- initramfs/resume configuration;
- udev/kernel rescan behavior;
- filesystem tool versions/features;
- mount/fstab conventions;
- SELinux/AppArmor integration where configuration files are created or moved.

Missing tools are prerequisites/blockers. The program must never substitute an
unverified command because a distro name "usually" uses it.

## I. Safety and transaction boundaries

Every future write route must enforce:

1. Acquire exclusive per-host operation lock.
2. Rediscover storage immediately before the first write.
3. Compare exact device identities, geometry and plan basis; reject stale plans.
4. Validate filesystem health/features and online/offline requirements.
5. Back up partition-table and/or LVM metadata before the relevant mutation.
6. Verify the backup is readable and tied to the exact target.
7. Execute one narrowly scoped layer transition.
8. Rediscover and verify that layer before continuing to the next.
9. Journal completed steps so interruption cannot cause blind replay.
10. Verify final topology, capacity, mounts, fstab and swap state.

First write releases must not:
- shrink filesystems, LVs, partitions or PVs;
- move partition starts;
- silently delete non-swap payload partitions;
- guess through unknown device-mapper stacks;
- continue after an unexpected identity or size change;
- auto-repair a damaged filesystem as a side effect of resizing.

## J. UX acceptance criteria

The normal TUI should make a common VM expansion require approximately:
- select **Extend**;
- select target such as `/` or `/var`;
- select `+N GiB` or `Max safe`;
- review/confirm.

A common provisioning flow should require approximately:
- select **Create**;
- select free-space source;
- choose size and filesystem/swap purpose;
- choose ext4/XFS when filesystem is selected;
- optionally set a mountpoint in the future wizard;
- review/confirm.

Current M1A TUI already supports source, size, filesystem/swap purpose and ext4/XFS
selection as a read-only preview. Mountpoint entry and all execution remain future work.

The details panel should explain the resolved route in human terms while retaining exact
device IDs, sizes and low-level operations for advanced inspection.

If a requested action is impossible, the UI should state **why** and what prerequisite
would make it possible. It should not force the user to reverse-engineer the storage
topology from raw Linux commands.

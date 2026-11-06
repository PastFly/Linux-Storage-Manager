# Support matrix

Status values: `Discovery`, `Preview`, `Operator apply`, `Harness only`, `Planned`, `Later`, `Not supported`.

| Technology / workflow | Current branch | First write release |
| --- | --- | --- |
| Physical / virtual disks | Discovery + explicit kernel rescan | Planned guarded capacity revalidation |
| Multiple disks / partitions | Discovery + selectable targets | Planned target-specific grow/create |
| GPT partitions | Discovery + authoritative `sfdisk` cross-check + grow preview | Planned guarded grow/create |
| DOS/MBR primary partitions | Discovery + authoritative `sfdisk` cross-check + grow preview | Planned guarded grow/create |
| DOS extended/logical partitions | Discovery + conservative topology model | Planned after dedicated route rules |
| Partition geometry reconciliation | Discovery | Planned mandatory preflight enforcement |
| Blank disks | Discovery + exact GPT/DOS Create preview with 1 MiB alignment | Planned guarded GPT/DOS initialization |
| Verified raw disk tail | Discovery + Create opportunity preview | Planned partition creation |
| Internal partition-table gaps | Discovery | Planned after range/slot validation |
| LVM PV / VG / LV | Operator apply for single-PV VG existing-free → LV → ext4/XFS | Chained partition/PV/LV is harness-only |
| LVM multi-PV | Discovery | Later guarded grow |
| LVM thin/cache/RAID/snapshots | Discovery facts where available | Later |
| ext4 | Operator apply for supported existing-VG-free LV profile; direct partition grow preview | Guarded direct partition grow planned |
| XFS | Operator apply for supported existing-VG-free LV profile when mounted | Other routes planned |
| Btrfs | Discovery | Later |
| LUKS / dm-crypt | Discovery topology | Later |
| mdraid | Discovery topology | Later |
| Multipath / other device-mapper | Discovery topology | Later |
| ZFS | Capability placeholder / later discovery | Later |
| Active mount table | Discovery | Planned guarded mount changes |
| `/etc/fstab` | Discovery | Planned guarded write |
| Swap partition | Discovery + DOS tail migration advisory | Planned lifecycle/migration |
| Swap file | Discovery | Planned lifecycle |
| Read-only extendability analysis | Discovery | Planner input |
| Selectable growth target catalog | Preview | Planned executor input |
| Create/free-space catalog | Preview | Planned provisioning input |
| Automatic multi-layer route selection | Partial advisory | Planned disk -> partition -> PV -> VG -> LV -> filesystem |
| Filesystem health/features gate | ext4/XFS decision policy + explicit read-only check plan | Required before executor |
| Exclusive operation lock | Host-exclusive lock + interruption journal model | Required before executor |
| Metadata backup/recovery verification | Captured and revalidated for operator LV profile; durable identity pinning remains in progress | Required throughout execution and recovery |
| Shrink/move partition starts | Not supported | Not supported in first write release |

The matrix describes storage capabilities rather than a fixed distro whitelist. Linux
Storage Manager should behave the same way on distributions that expose equivalent
kernel/storage tooling and structured metadata.

Portable static builds are already exercised across Debian 12, Ubuntu 22.04/24.04,
Rocky Linux 9 and Alpine 3.22. Additional distributions are validation targets, not
separate storage implementations.

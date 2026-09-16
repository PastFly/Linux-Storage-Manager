# Support matrix

Status values: `Discovery`, `Planned`, `Later`, `Not supported`.

| Technology | M0 | First write release |
| --- | --- | --- |
| Physical disks | Discovery | Planned |
| GPT / MBR partitions | Discovery | Planned |
| LVM PV / VG / LV | Discovery | Planned |
| ext4 | Discovery | Planned grow |
| XFS | Discovery | Planned grow |
| Active mount table | Discovery | Planned guarded mount changes |
| Swap partition | Discovery | Planned |
| Swap file | Discovery | Planned |
| `/etc/fstab` | Discovery | Planned guarded write |
| Topology diagnostics | Discovery | Planned preflight enforcement |
| LUKS | Later | Later |
| Btrfs | Later | Later |
| mdraid | Later | Later |
| LVM thin | Later | Later |
| Multipath | Later | Later |
| ZFS | Later | Later |

The matrix describes capabilities, not a fixed list of Linux distributions. Distribution/package-manager support is tracked separately from storage capability support.

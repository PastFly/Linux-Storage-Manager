# Support matrix

Status values: `Discovery`, `Planned`, `Later`, `Not supported`.

| Technology | M0 | First write release |
| --- | --- | --- |
| Physical disks | Discovery | Planned |
| GPT / MBR partitions | Discovery | Planned |
| LVM PV / VG / LV | Partial discovery | Planned |
| ext4 | Discovery | Planned grow |
| XFS | Discovery | Planned grow |
| Swap partition | Discovery | Planned |
| Swap file | Planned | Planned |
| `/etc/fstab` | Planned read | Planned guarded write |
| LUKS | Later | Later |
| Btrfs | Later | Later |
| mdraid | Later | Later |
| LVM thin | Later | Later |
| Multipath | Later | Later |
| ZFS | Later | Later |

The matrix describes capabilities, not a fixed list of Linux distributions. Distribution/package-manager support is tracked separately from storage capability support.

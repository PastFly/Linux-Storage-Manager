# Storage model

The normalized model represents storage as a hierarchy for M0 and will evolve into a dependency graph where one device may have multiple relationships.

Typical topology:

```text
Disk
└── Partition
    └── LUKS (future M1)
        └── LVM PV
            └── Volume Group
                └── Logical Volume
                    └── Filesystem
                        └── Mount
```

M0 starts with the block hierarchy reported by `lsblk` and normalizes device classes into `NodeKind`.

## Required device facts

- stable device path where available;
- kernel name;
- device class;
- size in bytes;
- partition start offset as reported by `lsblk START`;
- logical-sector size where reported;
- filesystem type/version/UUID when present;
- mount points;
- parent kernel name when present;
- model and serial when reported;
- partition UUID and partition-table type when reported;
- child devices.

## Geometry unit rule

`lsblk START` is explicitly defined upstream as a partition start offset in **512-byte sectors**. The normalized model therefore stores this value as `start_512_sector` and converts it to bytes using a fixed factor of 512.

`LOG-SEC` is stored separately as `logical_sector_bytes`. It must not be used to convert `START`. It is relevant to partition-table details such as GPT logical-block boundaries and will also be required by the future write planner.

The M0 extendability analyzer may calculate a conservative upper bound for adjacent partition capacity. That value is informational only: M1 must re-read authoritative partition-table metadata before producing or executing a write plan.

Raw command output must not leak into planning logic. Discovery adapters translate external schemas into the normalized model first.

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
- filesystem type/version/UUID when present;
- mount points;
- parent kernel name when present;
- model and serial when reported;
- partition UUID and partition-table type when reported;
- child devices.

Raw command output must not leak into planning logic. Discovery adapters translate external schemas into the normalized model first.

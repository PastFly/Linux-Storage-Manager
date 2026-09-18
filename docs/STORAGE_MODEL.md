# Storage model

The normalized model represents storage as a hierarchy for M0 and will evolve into a dependency graph where one device may have multiple relationships.

Typical topology:

```text
Disk
└── Partition
    └── LUKS (later)
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

`LOG-SEC` is stored separately as `logical_sector_bytes`. It must not be used to convert `START`.

## Independent partition-table view

For disks where `lsblk` reports a partition table, M0 also reads `sfdisk --json` and normalizes:

- disk-label type and table identifier;
- first/last usable LBA where reported;
- partition-table sector size;
- partition node, start and size in partition-table sectors;
- partition type, UUID, name, attributes and boot flag where reported.

The `sfdisk` sector values are interpreted using that table's `sector_size_bytes`. M0 cross-checks their byte offsets and sizes against the independent `lsblk` view. Contradictions are error diagnostics; future write planning must not silently choose one conflicting source.

## Advisory partition-tail capacity

See [GEOMETRY_AUDIT.md](GEOMETRY_AUDIT.md). The analyzer requires complete,
one-to-one table/kernel agreement for every direct partition. Missing siblings,
overlap, duplicate identities, unsupported units or incomplete collectors yield
unknown capacity, not zero or a guessed positive value.

GPT's `last_lba` is inclusive: the exclusive byte boundary is
`(last_lba + 1) * sector_size_bytes`. No fixed tail reservation or extension
beyond the reported usable range is assumed, even after the backing disk grows.
The result measures only partition-tail space inside the table's current bounds,
not achievable filesystem growth or unused capacity already inside a PV.

The value is informational only. M1 must re-read and reconcile metadata and
validate identity, health, locks and filesystem constraints before any future
write plan. An independent sfdisk report is not by itself proof of GPT CRC
validity or an atomic, race-free snapshot. M0 performs no repair or writes.

Raw command output must not leak into planning logic. Discovery adapters translate external schemas into the normalized model first.

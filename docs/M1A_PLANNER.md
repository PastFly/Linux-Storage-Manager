# M1A: read-only plan previews

Status: experimental, nonexecutable. Depends on M0 discovery/reconciliation.
M1A does not authorize storage mutation and contains no executor.

## Interface

```sh
storagemgr plan extend / --by 8GiB
storagemgr plan extend / --max
storagemgr plan extend /dev/vg0/root --by 512MiB --json
```

Exactly one of `--by` or `--max` is required. `--by` means additional
capacity, not final size. Units are case-sensitive B/KiB/MiB/GiB/TiB and
accept positive whole numbers only.

A successful preview returns exit code 0, a blocked preview returns 2,
and discovery/planner errors return 1. Invalid CLI syntax also returns 2.
JSON is emitted for blocked previews. No `apply` command exists.

## Supported profile A — LVM growth using existing VG free extents

Candidate:
- mounted read-write ext4 or XFS;
- normal public linear active LV;
- local, writable, resizable, nonpartial, nonshared single-PV VG;
- verified PV/VG/LV/filesystem identities;
- complete lsblk, partition-table, mounts, fstab, swap and LVM collectors;
- no error-level diagnostics;
- required future operation tools available.

The request is rounded UP to complete VG extents. Both requested and rounded
growth are serialized. `--max` freezes the observed free extent count, not a
future dynamic `100%FREE` expression.

Typed preview steps:
1. revalidate snapshot;
2. require LVM metadata backup;
3. describe LV growth by frozen extent count;
4. describe filesystem growth;
5. rediscover and verify.

## Supported profile B — direct partition growth into verified adjacent space

Candidate:
- mounted read-write ext4 or XFS directly on a partition;
- no stacked child consumer above that partition;
- parent is a normal disk or disposable loop device;
- DOS/MBR or GPT partition table;
- authoritative sfdisk and lsblk start/size/sector facts agree;
- verified adjacent free sectors immediately after the target;
- lsblk, partition_tables, mounts, fstab and swap collectors complete;
- LVM collector is not required for this profile;
- no error-level diagnostics;
- `sfdisk` plus the filesystem grow tool are available.

For direct partitions the requested growth is rounded UP to the logical-sector
size. The rounded request must fit the verified adjacent gap. `--max` freezes
that observed gap.

DOS/MBR handling is conservative:
- extended partition containers are treated as primary boundaries;
- logical partitions wholly inside the extended container are not mistaken for
  overlapping primary partitions;
- growing a logical partition inside an extended container remains unsupported;
- protective/empty and contradictory layouts block.

GPT handling requires first/last usable LBA bounds and rejects overlaps or
out-of-range partitions.

Typed preview steps:
1. revalidate snapshot;
2. require partition-table metadata backup;
3. describe moving ONLY the partition end to a frozen new sector count;
4. describe filesystem growth;
5. rediscover and verify.

## Plan data, not operations

`lsm-planner` performs no process, filesystem or device I/O. It only constructs
typed data. Every serialized preview includes:

```text
dry_run: true
executable: false
```

A backup step does not mean a backup happened. An ExtendPartition,
ExtendLogicalVolume or GrowFilesystem step is not a command invocation.

The preview currently exposes either:
- `size_change` for LVM; or
- `partition_size_change` for direct partitions.

Blocked plans contain neither size change and have an empty steps array.

## Immutability and freshness

`PlanPreview` has private fields and no Deserialize implementation.
Its SHA-256 plan ID includes the request, basis digest, size change, steps,
notices and blockers. The basis digest covers the serialized snapshot and
capability inventory.

`matches_basis` is only an exact-input freshness check. It is not a lock,
signature, hardware identity proof or mutation authorization.

## Safety boundaries

M1A deliberately does NOT:
- shrink anything;
- move partition starts;
- grow logical partitions inside DOS extended containers;
- resize PVs;
- extend multi-PV or thin/RAID/cached LVs;
- operate through LUKS, mdraid or multipath;
- run filesystem checks;
- perform backups;
- execute storage commands.

A future executor must add fresh runtime identity checks, locks, filesystem
health/feature checks, verified backup/recovery policy, bounded commands,
explicit approval and post-operation verification.

## Validation

The exact source at cbcf838afa8d6f1432832c7313a0ca7c0a1329a6 passed:
- rustfmt;
- Clippy with `-D warnings`;
- Rust workspace tests;
- harness safety tests;
- repeated disposable loop integration for plain ext4, LVM/ext4 and LVM/XFS;
- static musl x86_64 and aarch64 builds;
- five-userland smoke tests and Debian 12 collector probes.

The direct-partition loop scenario verifies `--by`, `--max`, oversized refusal,
`--apply` rejection, unchanged owned storage facts and unchanged sentinel data.

## Primary references

- sfdisk JSON/table semantics: util-linux sfdisk(8)
- lsblk topology/udev synchronization: util-linux lsblk(8)
- LVM reporting fields: https://gitlab.com/lvmteam/lvm2/-/raw/main/lib/report/columns.h
- LV attribute meanings: https://man7.org/linux/man-pages/man8/lvs.8.html
- Extent growth semantics: https://man7.org/linux/man-pages/man8/lvextend.8.html
- SHA-256 API: https://docs.rs/sha2/0.10.9/sha2/

# M0 advisory geometry hardening

This source change follows PR #2 head
`e66f414e5ca404f77bc3b421998ef16432f3a4a8`. It changes the old read-only
`explain` analyzer, not the M1A planner, executor, CI policy or branch protections.

## Defects addressed

The previous analyzer skipped siblings with missing start offsets, ignored some
overlap patterns, and estimated GPT's tail using a fixed 34-sector reservation.
It could also expose a partial sum of PV tail capacity before testing whether all
PVs had been resolved. Error-level diagnostics did not stop advisory claims.

The geometry helper now requires exactly one complete lsblk and partition-table
collector record, one parent, one matching table, and a one-to-one match for
**all** direct partitions. Start/size/sector/parent and GPT partition UUID facts
must agree. Zero sizes, out-of-bounds or overflowing ranges, overlap anywhere,
missing siblings, duplicate identity and unsupported units return unknown.

GPT uses the table's inclusive `last_lba`: the exclusive upper byte bound is
`(last_lba + 1) * sector_size_bytes`. `lsblk START` still uses 512-byte units.
There is no guessed reservation and no extrapolation beyond the reported GPT
boundary when the device becomes larger. Plain primary DOS/MBR geometry is
conservatively bounded to its 32-bit address range. Extended/logical and
protective/hybrid MBR interpretation, and sector sizes other than 512/4096,
remain unsupported for this advisory calculation.

PV aggregation now requires the reported PV count, unique resolved device and
PV identities, complete geometry for every PV, and checked arithmetic. A
positive partial result is not exposed as known capacity. An error diagnostic
returns Unknown with no capacity or proposed operations, including for a VG
that reports existing free extents.

## Meaning of the result

`potential_underlying_growth_bytes` is only the observed gap after a partition,
within the independent table's current usable bounds. It is not the achievable
filesystem growth, an extent-aligned allocation, a complete scan of unused
space inside a PV container, or a verified resize plan. Zero is distinct from
unknown (`null`). No backups, mounts, resize, GPT repair or other writes occur.

This does not establish GPT CRC validity, that sfdisk has not normalized its
in-memory view, freshness under concurrent root changes, device health, or
filesystem limits. Legacy target/alias resolution and the immediate-VG `Ready`
branch still require further review. `Ready` remains advisory, NOT permission
to execute anything. M1A does not consume it.

## Regression coverage and evidence

`geometry_hardening.rs` introduces 17 test declarations covering inclusive GPT
bounds, 512/4096-byte sectors, nonstandard/stale bounds, next-partition limits,
zero capacity, missing and overlapping siblings, collector ambiguity, UUID
mismatches, overflow and restricted MBR handling. `extendability.rs` preserves
four existing scenarios and adds four PV/error-diagnostic regressions.
That is 25 declarations in these two files, 21 newly added.

**These Rust tests have NOT run.** The local environment still has no Cargo or
rustc and cannot resolve the official toolchain download host. Locally checked:
UTF-8 source, removal of the unsafe geometry implementation, independence from
process/filesystem I/O, raw JSON fixture syntax, and six exact arithmetic
expectations. These checks are not compilation, rustfmt, Clippy, unit-test or
real-device acceptance. The baseline analysis bytes were verified against blob
`7b4ad9c5d0cb33ed656867be98b8007585c1c6f5` before editing.

With Rust available, run the complete validator and then the dedicated suites:

```sh
bash tools/validate.sh
cargo test -p lsm-discovery --test extendability --test geometry_hardening
```

The disposable-VM integration matrix and exact-head GitHub CI remain mandatory
before acceptance. No writes or merge are authorized by this source change.

## Primary reference

UEFI 2.10, section 5: LastUsableLBA is the last usable logical block, and GPT's
partition-array size is described by NumberOfPartitionEntries and
SizeOfPartitionEntry, not one universal tail-size constant.
https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html

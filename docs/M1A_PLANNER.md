# M1A: read-only plan previews

Status: experimental, not accepted for release. Depends on M0 (PR #1).
This work does not close the M0 CI or disposable-VM acceptance gates.

## Interface

```sh
storagemgr plan extend / --by 8GiB
storagemgr plan extend / --max
storagemgr plan extend /dev/vg0/root --by 512MiB --json
```

Exactly one of `--by` or `--max` is required. `--by` means additional LV
capacity, not the final size. Units are case-sensitive B/KiB/MiB/GiB/TiB
and accept positive whole numbers only. The requested amount is rounded UP
to complete VG extents; both the requested and rounded amount are shown.
The rounded request must fit existing free extents. `--max` freezes the
observed free extent count, not a future dynamic `100%FREE` expression.

A successful preview returns exit code 0, a blocked preview returns 2,
and discovery/planner errors return 1. Invalid CLI syntax also returns 2.
JSON is printed even for blocked previews. No `apply` command exists.

## Deliberately narrow supported candidate

A single-PV, local, nonshared, nonpartial VG containing a public linear LV,
with an unambiguous read-write ext4 or XFS mount. Normal LV/VG attribute
profiles are allowlisted conservatively. All six M0 collectors must report
complete; unknown/duplicate collectors, relevant identity/capacity mismatches,
missing extent facts, error-level diagnostics and unavailable operation tools
block the candidate. The typed snapshot is produced by the M0 discovery and
reconciliation pipeline; this API does not independently re-probe its input.

Partition/PV changes, multi-PV layouts, thin pools, snapshots, striped/RAID,
LUKS, multipath, detached filesystems and bind/ambiguous mounts are not covered.
They return blockers with an EMPTY steps array. The old `explain` advisory
status is not used as an authorization or as planner validation.

## Plan data, not operations

`lsm-planner` depends on the core model, serialization and hashing only. It
has no process/filesystem/device I/O. It constructs:

1. A snapshot revalidation requirement.
2. An LVM metadata backup requirement.
3. A frozen LV growth request in extents.
4. A filesystem-growth description.
5. A rediscovery/verification requirement.

These are typed descriptions, NOT shell commands. Every serialized document
has `dry_run: true` and `executable: false`, including an otherwise successful
`preview`. A backup step does not mean a backup was made. Neither the CLI nor
the planner invokes vgcfgbackup, lvextend, resize2fs or xfs_growfs.

LV and filesystem growth are conservatively classified irreversible in this
preview model: no automatic rollback is promised. LVM metadata backups do NOT
back up filesystem data. Filesystem capacity, health, feature limits, online
grow support, live device identity and tool versions are not fully validated
by this stage. Displayed expected size is the LV size, not a prediction of
filesystem usable space.

## Immutability and freshness

`PlanPreview` has private fields and no setters or Deserialize implementation.
Its SHA-256 plan ID includes the request, basis digest, steps and blockers.
The basis digest covers the exact serialized snapshot and capability inventory.
`matches_basis` is a pure equality check, not a lock or execution authorization.
Ordering changes and usage changes can conservatively invalidate the preview.
It is not a signed artifact, machine identity proof, or persistent import format.

A future executor must add fresh hardware/device-mapper identity checks,
capability/version and filesystem-health checks, concurrency protection,
verified metadata and data-backup policy, explicit approval, bounded command
execution and post-operation verification. It must not accept this preview
schema as an executable transaction.

## Tests and acceptance

Added tests cover extent rounding, frozen max, aliases, XFS mount state,
missing/failed collectors, error diagnostics, duplicate sources, unsupported
layouts, capacity/UUID mismatch, missing tools, invalid sizes and stale bases.
LVM parser tests reject fractional, nonfinite, exponent and overflowing values
without f64 conversion, and distinguish empty inventories from missing reports.

These tests must actually execute successfully before acceptance. Source review
and a test count are not substitutes for cargo fmt, clippy, compilation, unit
results or disposable-VM integration. M0's first real CI run remains required.

## Primary references

- LVM reporting fields: https://gitlab.com/lvmteam/lvm2/-/raw/main/lib/report/columns.h
- LV attribute meanings: https://man7.org/linux/man-pages/man8/lvs.8.html
- Extent growth semantics: https://man7.org/linux/man-pages/man8/lvextend.8.html
- SHA-256 API: https://docs.rs/sha2/0.10.9/sha2/

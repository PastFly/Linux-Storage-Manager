# Advisory target resolution follow-up

Source base: PR #2 at 24929b73cef10ef151730de545f82cf82c151407.
Publication preserves concurrent CI-only commit e2cdc39dd02e7492b124de0a99b1929e59c03a96.
Scope: legacy read-only `explain` only. No planner, executor, UI, CI or storage writes.
This source change is not accepted until real Rust and disposable-VM tests pass.

## Defects in the baseline

- Target lookup returned the first lsblk mountpoint/path match, ahead of findmnt.
- A failed/absent mount collector could be ignored in favor of an lsblk claim.
- A direct `/dev/VG/LV` target did not use the LVM alias bridge used for mount sources.
- `/dev/NAME` was fabricated from the lsblk display name, including LVM display names.
- LV/VG selection used the first matching report, permitting order-dependent identity
  or free-capacity selection from duplicated input.

## Source changes

`analysis/identity.rs` resolves an absolute target using a unique completed lsblk
collector, exact reported device paths/kernel names and, where required, one
completed LVM report. Canonical `/dev/VG/LV`, reported `lv_path`, mapper paths
with escaped hyphens and `/dev/dm-N` are considered against the same snapshot.
A reported path is evidence only: no live symlink or device identity check occurs.

Mount targets require a unique completed mounts collector and one exact mount
record. Both mount targets and direct device paths then cross-check known mount
claims in both directions. Source, filesystem type and read-write/non-bind options
must agree. Overmounts, conflicting claims and unsupported subdirectory sources
are refused; source suffixes are not stripped. An empty successful mount table
is distinct from an unavailable collector, including for detached XFS advice.

Distinct graph occurrences are not coalesced by path or UUID. Even identical
repeated nodes are ambiguous in the current tree model. This intentionally
refuses some legitimate multi-parent layouts until canonical graph identity and
mount IDs are available. It does not declare those layouts corrupt.

Resolution refusals produce `unknown` with no selected device, capacity, size or
steps. A genuinely absent target retains the existing not-found error. Duplicate
VG reports produce `unknown` with no capacity/steps after device resolution.
PV lookups also use uniqueness checks; no partially resolved sum is exposed.

## Regression declarations

21 new `target_resolution.rs` tests cover normal aliases, hyphen escaping,
fabricated display-name paths, duplicate/conflicting mount rows, conflicting
lsblk mount claims, missing sources, absent mount rows, reverse mount disagreement,
failed/missing/duplicate collectors, duplicate graph/kernel identities, conflicting
direct/LVM aliases, duplicate LV/VG reports, filesystem mismatch, read-only/bind
mounts, bracketed source suffixes, invalid targets, not-found and detached XFS.
Several cases permute input order to ensure a first-match result is not accepted.

Existing geometry/extendability fixtures now include explicit matching mount
records and successful collector statuses. Their capacity expectations are
unchanged. Duplicate parent/device evidence is now rejected before geometry, so
that case explicitly expects `unknown` with no selected device rather than
`needs_geometry`. Missing-table tests still remove the table collector, not the
new mount collector.

## Verification status

The test file was written before the implementation. Cargo/rustc are unavailable,
so no runtime RED/GREEN result was observed. Tests are declarations, not passes.
Baseline source copies were checked against Git blob IDs before patching.
Local checks cover UTF-8, embedded literal JSON syntax, preserved regression
counts/numeric expectations, removed first-match helpers, and source-level absence
of process/filesystem I/O in the new helper. These do not type-check or execute Rust.
A later live check found a real CI run on the concurrent CI-only base: #116
(35328857790) passed the harness, Clippy and Test steps but failed Format.
Its downloaded source archive and digest were verified against that exact tree.
Those results do not validate this new target-resolution change. No local Rust
execution or actual loop integration success is claimed here.

## Remaining limits

- Immediate-VG free-space advice still needs layout, capacity-accounting and extent
  validation review. `Ready` is advisory, never an executable authorization.
- The stricter M1A planner remains unchanged and never consumes this `explain` result.
- No general symlink, UUID/LABEL, mount namespace/ID, bind-subtree, stacked-storage,
  filesystem-health, kernel-device-lifetime or concurrent-root proof is provided.
- An unsupported source is not silently rewritten to a recognized device name.
- Full-tree compilation, formatting, Clippy, all Rust tests and disposable-VM
  ext4/XFS/LVM integration remain acceptance gates; do not merge on source checks.

## Primary references

- util-linux findmnt(8), exact mountpoint selection and kernel mount information:
  https://www.man7.org/linux/man-pages/man8/findmnt.8.html
- Red Hat, device-mapper escaping of hyphens in VG/LV names:
  https://access.redhat.com/solutions/2267481

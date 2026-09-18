# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager. Default branch: master.
Visibility was observed as public on 2026-09-18; this continuation did not change it.
Read AGENTS.md and docs/SAFETY.md before writing. Default-branch merges require
explicit owner approval and passing CI for the exact reviewed head.

## Development boundary

- M0 is unmerged PR #1: bootstrap/m0-storage-discovery, baseline
  2e447f1d5bc52f403adc08916480a35f634c85e4.
- M1A is draft PR #2: feature/m1a-read-only-planner, based on unmerged M0.
- Initial planner: 6f2b5ad3737eeb5b768cc91339ec444a6ac5c486.
- Harness follow-up: e66f414e5ca404f77bc3b421998ef16432f3a4a8.
- Geometry follow-up: 24929b73cef10ef151730de545f82cf82c151407.
- Concurrent CI diagnostics commit preserved: e2cdc39dd02e7492b124de0a99b1929e59c03a96.
- No executor/apply or default-branch merge. Read-only previews do not complete M0.
- docs/M1A_PLANNER.md describes the single-PV linear LV preview profile.
- Legacy `explain` Ready is advisory and never consumed by the planner.

## Latest source work

The follow-up to 24929b7 addresses legacy target/alias resolution. Read
TARGET_RESOLUTION_AUDIT.md and GEOMETRY_AUDIT.md. It replaces first-match lookup
with unique snapshot evidence, cross-checks mounts for both mountpoint and device
queries, supports the common LVM paths without fabricating /dev/display-name,
and refuses duplicate LV/VG/device/collector evidence. Refused target selection
returns unknown without a guessed device, capacity or proposed steps.

21 new Rust regression declarations were added. Existing geometry fixtures now
supply matching mounts and collector statuses; their capacity expectations are
preserved. Duplicate parent evidence is rejected earlier at target resolution.
No planner, CI, UI or storage-writing behavior is added. Immediate-VG layout and
capacity-accounting review remains open; this is not full analyzer acceptance.

## Validation status

CI now runs: run 35328857790 / #116 at e2cdc39 assigned real GitHub runners.
Harness safety tests, Clippy and the Rust Test step PASSED for that base tree.
Format FAILED, so real loop integration was skipped. Do not describe #116 as a
billing failure. Historical runs through #115 failed before runner assignment.
The account billing and repository visibility were not changed by this work.

The #116 diagnostic ZIP digest was checked, and its source.tar reconstructs the
exact tested tree 87e09aeebf0b81b7a5842295e04eaab3148310d6. It contains a real
Cargo-generated lockfile and a rustfmt-generated patch; neither was fabricated.
The new target-resolution tests are NOT covered by the earlier passing Test step.
Their fresh CI result must be read after publishing this continuation.

Local source checks cover the baseline blob IDs, UTF-8, literal JSON fixtures,
retained numeric expectations and source-level I/O boundary only. No local Rust
compiler, rustfmt, Clippy or runtime test result is established: Cargo/rustc are
absent. The new tests were written first, but a runtime RED/GREEN cycle was not
observed. The real ext4/XFS/LVM matrix remains unvalidated until it actually runs.
Read docs/VALIDATION.md before running any privileged harness.

## Resume

Read live PR heads and exact workflow results. Keep work on PR #2's existing
feature branch; do not create throwaway branches or merge master. Obtain a real
complete-tree build, fmt, Clippy and Rust test results; fix actual diagnostics.
Generate Cargo.lock only with real dependency resolution, then run the opt-in
harness in a dedicated disposable Linux VM. Continue the remaining immediate-VG
advisory audit. Storage mutation stays gated on acceptance and separate review.

Within the same chat cache unchanged blob SHAs; fetch changed content only.

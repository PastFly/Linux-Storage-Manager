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

The owner made the repository public. CI #117 / 35330217493 at source
8390a5ee0dbcb6d555e3e272bfee884c57586136 actually passed Clippy, all 74 Rust tests
and 24 harness mock tests. Only Format failed; loop integration was skipped.
Historical failures through #115 were pre-runner billing blocks, not test results.

The #117 artifact digest and archived source tree
54ca412436f4c8e3e56495272fe19db5b7f949cf were verified. Its actual Rust 1.88
formatter patch and Cargo-generated lockfile reconstruct the reviewed tree
60ac6554e529322959045c965f20e78d0205ee97. A one-shot exporter reproduced that
exact tree and uploaded only matching Git blobs (run 35331188889); the temporary
workflow is removed with this import. Normal CI retains contents: read.
No formatter rules, tests or failed checks were disabled.

Cargo.lock is now committed; validation fetches and builds with --locked instead
of re-resolving dependencies. CI builds the release binary and subjects that same
binary to the opt-in disposable ext4/LVM/ext4/LVM/XFS matrix before packaging it.
Read this commit's own CI result; the new integration result is not assumed here.
The next successful artifact is a Linux x86_64 Ubuntu 24.04 prototype, not a claim
of portability to every distribution or of production-ready storage writes.

Local source-only validation reran all 24 harness mocks successfully. Local Rust
is still unavailable; actual Rust test evidence comes from the GitHub runner.
Read docs/VALIDATION.md before running any privileged harness.

## Resume

Read live PR heads and exact workflow results. Keep work on PR #2's existing
feature branch; do not create throwaway branches or merge master. Obtain a real
complete-tree build, fmt, Clippy and Rust test results; fix actual diagnostics.
Preserve the committed Cargo.lock with --locked; run the opt-in
harness in a dedicated disposable Linux VM. Continue the remaining immediate-VG
advisory audit. Storage mutation stays gated on acceptance and separate review.

Within the same chat cache unchanged blob SHAs; fetch changed content only.

# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager. Default branch: master.
The owner made the repository public on 2026-09-18. Do not change visibility,
billing, permissions or merge the default branch without appropriate approval.
Read AGENTS.md and docs/SAFETY.md before writing.

## Development boundary

- M0 is unmerged PR #1, bootstrap/m0-storage-discovery, at
  2e447f1d5bc52f403adc08916480a35f634c85e4.
- Continue on draft PR #2, feature/m1a-read-only-planner. It includes unmerged M0.
- No executor or apply command. Previews always have dry_run=true/executable=false.
- M1A supports only mounted ext4/XFS on a normal public linear LV in a local,
  complete single-PV VG, using existing free extents. Read docs/M1A_PLANNER.md.
- Legacy explain is advisory; the stricter planner never trusts its Ready state.
- Geometry/target follow-ups: 24929b73cef10ef151730de545f82cf82c151407 and
  8390a5ee0dbcb6d555e3e272bfee884c57586136. Read GEOMETRY_AUDIT.md and
  TARGET_RESOLUTION_AUDIT.md. Immediate-VG advisory audit remains open.

## Actual build and test evidence

Historical CI through #115 failed before runner assignment due the owner's
billing/spending-limit error. Do not apply that explanation to newer runs.
CI #117 at 8390a5e passed Clippy, 74 Rust tests and 24 Python harness mocks;
Format alone failed. The real formatter patch and Cargo.lock from its artifact
were verified against source tree 54ca412436f4c8e3e56495272fe19db5b7f949cf.
Formatting/import commit c2b65c3f83bf7f751f615e2bc8aaebe6d309f9a3 pins that lock.
The temporary Git-blob exporter was removed; normal CI uses contents: read.

CI #119 / 35331638796 passed fmt, Clippy, Rust tests and release compilation,
but the first plain-ext4 integration case saw different before/after facts.
That run did not record the exact differing field; do not claim proven data
corruption or a conclusively identified udev race from that message alone.
Observation-only CI #120 / 35331995907 at
9a1f471228d0de33bfa99b8e7bdf86a41d1d0c59 passed ALL THREE JOBS, including actual
plain-ext4, LVM/ext4, LVM/XFS fixture tests and complete cleanup. It packaged the
tested Linux x86_64 release prototype. This is not production-write acceptance.

## Readiness follow-up in this tree

Before testing nonmutation, the harness now waits for udev's queue and requires
two equal owned-fixture samples. Setup waiting is bounded and fails closed.
After planning starts, any changed geometry/identity/sentinel still fails
immediately; post-test mismatches are never retried or ignored. Such failures now
include before/after OWNED facts (not the full host snapshot). Temporary trace
wrapper removed. CI runs the complete matrix three times; any failure stops it.

A mocked unstable-setup regression failed on the old harness and passed after
this change. All 28 Python harness tests pass locally, including settle timeout,
baseline timeout, genuine post-plan drift and resource ownership/cleanup tests.
Read this exact head's CI result; do not assume #120 validates the follow-up.
Reference: lsblk(8) documents udev synchronization after device creation/changes.

## Resume and release gates

Read live PR heads, latest CI and PR #2 validation comments once. Preserve the
committed Cargo.lock; use --locked. The local assistant container lacks Rust,
so compiler evidence comes from actual GitHub jobs, not local source checks.
Run privileged integration ONLY in a dedicated disposable Linux VM with explicit
--allow-disposable-loop-tests; read docs/VALIDATION.md first.

Artifacts are Linux x86_64 binaries built/tested on Ubuntu 24.04, not universal
Linux packages. TUI visual/PTY acceptance, ARM64 and broader distribution tests,
remaining advisory review and future mutation safety are separate next gates.
No merge without explicit owner approval of the exact reviewed head. Do not
silently mark PR #1 green based on PR #2: their source trees differ.
Cache unchanged blob SHAs in this chat and preserve existing feature work.

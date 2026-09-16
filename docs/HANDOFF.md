# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager (private). Default branch: master.
Read AGENTS.md and docs/SAFETY.md before writing. Default-branch merges require
explicit owner approval and passing CI for the exact reviewed head.

## Current development boundary

- M0 is unmerged PR #1, branch bootstrap/m0-storage-discovery.
- M1A feature branch: feature/m1a-read-only-planner.
- M1A starts from M0 commit 2e447f1d5bc52f403adc08916480a35f634c85e4.
- M1A adds pure read-only previews; it does not complete M0 acceptance.
- No storage executor, no apply flag, no resize/mount/backup execution.
- Read docs/M1A_PLANNER.md for the restricted single-PV linear LV profile.
- The old `explain` Ready state is advisory and is never trusted by the planner.

## Validation status at implementation

The owner supplied GitHub's failed-payment/spending-limit error. The latest
observed M0 CI run 35126662572 failed; loop integration was skipped. Do not
infer that compilation or tests passed from this account-level failure.
Rust/cargo are absent in the assistant container and an attempted toolchain
fetch failed because external DNS was unavailable. Added Rust tests therefore
have not executed locally. Source checks are not compiler/test evidence.

## Resume

Read live PR heads and exact workflow results first. Do not repeatedly rerun
billing-blocked jobs or create throwaway branches. Compile, run rustfmt/clippy,
fix actual diagnostics, then run fixture tests and disposable-VM integration.
Keep incomplete work in draft and do not introduce mutation until acceptance.
The unmerged M0 base also needs real formatting/compilation validation and a
review of the legacy advisory analyzer before any release.

Within the same chat cache unchanged file blob SHAs; fetch changed content only.

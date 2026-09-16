# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager (private). Default branch: master.
Read AGENTS.md and docs/SAFETY.md before writing. Default-branch merges require
explicit owner approval and passing CI for the exact reviewed head.

## Development boundary

- M0 is unmerged PR #1: bootstrap/m0-storage-discovery.
- M1A is draft PR #2: feature/m1a-read-only-planner, based on M0
  2e447f1d5bc52f403adc08916480a35f634c85e4.
- Initial planner commit: 6f2b5ad3737eeb5b768cc91339ec444a6ac5c486.
- Read-only preview logic does not complete M0 acceptance. No executor/apply.
- docs/M1A_PLANNER.md describes the restricted single-PV linear LV profile.
- Legacy M0 `explain` Ready is advisory and never trusted by the planner.

## Latest validation work

The continuation on PR #2 replaces unsafe Bash cleanup with an opt-in Python
integration harness, adds 24 mocked unit tests and tools/validate.sh, and removes
duplicate feature push + PR CI triggers. Read docs/VALIDATION.md before running
anything as root. The application remains Rust; Python is test-only.

Local evidence: 24 harness tests PASS; Python syntax and Bash syntax checks PASS.
The full validator was also invoked and exited 2 because Cargo is missing. These
are NOT passed Rust tests or passed real storage integration. The three real
cases (plain ext4, LVM/ext4, LVM/XFS) are implemented but have not run locally.
External Rust toolchain retrieval failed due unavailable DNS in the container.

The owner supplied GitHub's failed-payment/spending-limit error. Last observed
pre-change run 35128772184 (CI #113) at the initial planner commit failed before
runner assignment; real storage integration was skipped. Query current heads
and CI results once; do not keep polling or changing YAML to mask account limits.
No billing/permissions/visibility changes are authorized by this development work.

## Resume

Read live PR heads and exact workflow results. Keep code changes on PR #2's
feature branch; do not create throwaway branches or merge into master. First
obtain actual compilation/formatting/Clippy/workspace test results and fix them.
Generate/commit Cargo.lock only with real Cargo resolution. Then run the opt-in
harness in a dedicated disposable Linux VM and address real integration results.
Review the legacy advisory analyzer before release; no write executor until
acceptance. Source/mock checks never replace these gates.

Within the same chat cache unchanged blob SHAs; fetch changed content only.

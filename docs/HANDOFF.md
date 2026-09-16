# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager (private). Default branch: master.
Read AGENTS.md and docs/SAFETY.md before writing. Default-branch merges require
explicit owner approval and passing CI for the exact reviewed head.

## Development boundary

- M0 is unmerged PR #1: bootstrap/m0-storage-discovery.
- M1A is draft PR #2: feature/m1a-read-only-planner, based on M0
  2e447f1d5bc52f403adc08916480a35f634c85e4.
- Initial planner commit: 6f2b5ad3737eeb5b768cc91339ec444a6ac5c486.
- Harness follow-up: e66f414e5ca404f77bc3b421998ef16432f3a4a8.
- Read-only preview logic does not complete M0 acceptance. No executor/apply.
- docs/M1A_PLANNER.md describes the restricted single-PV linear LV profile.
- Legacy M0 `explain` Ready is advisory and never trusted by the planner.

## Latest source work

The follow-up to e66f414 hardens the legacy advisory geometry calculation.
Read docs/GEOMETRY_AUDIT.md. It removes the fixed GPT tail constant, requires
complete authoritative table/kernel agreement for every sibling, refuses
unknown/overlapping geometry and partial PV sums, and blocks capacity claims
when the snapshot contains an error diagnostic. It adds 21 Rust regression
test declarations (25 total in the two touched suites). They have NOT run.
No planner/executor/UI features or CI configuration are added by this change.
The rest of the legacy alias resolution and immediate-VG advisory branch still
need review. This is a partial source audit, not acceptance of the analyzer.

## Validation status

The earlier harness follow-up replaced unsafe Bash cleanup with an opt-in
Python integration harness, added 24 mocked unit tests and tools/validate.sh,
and removed duplicate feature push + PR CI triggers. Read docs/VALIDATION.md
before running anything as root. Python is test-only; the application is Rust.

Earlier local evidence: 24 harness mock tests and Python/Bash syntax checks
passed. The three real cases (plain ext4, LVM/ext4, LVM/XFS) have not run locally.
Current source work checked UTF-8, JSON fixture syntax, six arithmetic
expectations and the new geometry module's I/O-free boundary, not Rust execution.
Cargo/rustc are still absent; official toolchain download DNS is unavailable.
No generated Cargo.lock, compiled Rust binary or passed Rust tests exist yet.

The owner supplied GitHub's failed-payment/spending-limit error. Last observed
pre-change run 35132771828 (CI #114) failed before assigning a runner to Harness
safety tests; Rust and integration were skipped. Read the next head's actual
result separately. Do not treat infrastructure failure as a code test result,
keep rerunning blocked jobs, or change YAML to hide account limits. No billing,
permissions, visibility or self-hosted-runner changes are authorized.

## Resume

Read live PR heads and exact workflow results. Keep changes on PR #2's feature
branch; do not create throwaway branches or merge into master. Obtain a real
complete-tree Rust build, fmt, Clippy and test results; fix actual diagnostics.
Generate/commit Cargo.lock only through real Cargo dependency resolution. Then
run the opt-in harness in a dedicated disposable Linux VM. Review the remaining
legacy analyzer before release; no write executor until acceptance.

Within the same chat cache unchanged blob SHAs; fetch changed content only.

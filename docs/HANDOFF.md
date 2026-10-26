# Linux Storage Manager — current engineering handoff

Updated: **2026-10-26**. Repository: `PastFly/Linux-Storage-Manager`, default branch
`master`. Read live GitHub refs and checks before continuing; historical SHAs in
older milestone documents are not the current baseline.

`AGENTS.md` governs engineering. The owner has explicitly authorized autonomous
development, feature-branch PRs and merges in this project, and asks that completed
PRs be closed. Preserve that authorization across sessions. Require successful
checks for the exact candidate head before merging.

## Current work

- M1B Extend and swap paths have guarded execution and disposable-loop acceptance.
- M2A blank-disk Create has GPT/DOS × ext4/XFS coverage through mount, fstab
  persistence, restart verification and exact cleanup.
- M2B1–M2B5 freeze and authorize existing-GPT-tail intent without storage writes.
- PR #175 adds M2B6 fresh runtime preflight, including target-scoped kernel/GPT
  reconciliation. Regression coverage rejects changed, missing, extra or ambiguous
  partitions and preserves the fixed 512-byte lsblk START units on 4Kn media.
- The Wave 1 evidence runner uses those existing executable profiles to produce a
  three-repetition VM acceptance report. Read `docs/PREPROD_TEST_PLAN.md` and the
  2026-10-26 specification/plan under `docs/superpowers/` for its contract.

## Honest readiness boundary

Normal CLI/TUI builds remain read-only and have no general `apply` entry point.
The native harnesses are separate, explicitly opted-in disposable-VM tests.
Existing-GPT-tail writes/formats and advanced storage layouts are still pending.

Do not delay Wave 1 testing for completion of M2B. Wave 2 adds GPT-tail Create only
after its own backup, slot selection, pinned launch, durable write/format sequence
and destructive sentinel-preservation acceptance exist.

## Verification and evidence

1. `bash tools/validate.sh --source-only` runs rootless harness and runner tests.
2. `bash tools/validate.sh` additionally runs Rust 1.88.0 formatting, clippy, tests
   and build. Feature-specific tests remain in `.github/workflows/ci.yml`.
3. `python3 -I tools/preprod.py build` creates the source-bound native binaries.
4. `check` inspects prerequisites; `run` requires exact source, root/Linux and
   `--allow-disposable-vm-tests`. It runs all profiles three times, stops on failure
   and retains the report/logs. It performs no independent storage cleanup.
5. CI uploads `wave1-ubuntu24-x86_64-<run>-<attempt>` evidence even after a failed
   test. Read `report.json` and `SUMMARY.txt`; workflow success alone is not a
   substitute for a report from a different distribution or a real extra disk.

## Next useful work

- Collect complete Wave 1 reports from Debian 12, Rocky Linux 9 and an aarch64 VM.
- Exercise operator-facing read-only target selection on a disposable VM with a
  dedicated additional virtual disk; keep this evidence separate from loop tests.
- Continue M2B runtime backup/slot/launch/journal/write/format as a coherent feature,
  with preservation of existing partition geometry and sentinel data proved E2E.
- Connect accepted execution paths to a deliberate operator-facing apply workflow
  only with the existing consent, recovery and fresh-state safeguards intact.

`docs/M1B_HANDOFF.md` is historical implementation detail. Do not restart at its
older M1B checkpoint or repeat already merged milestones.

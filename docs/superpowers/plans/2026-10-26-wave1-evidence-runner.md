# Wave 1 Evidence Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Provide a repeatable disposable-VM test command and retained three-run evidence for existing Wave 1 profiles.

**Architecture:** A Python standard-library wrapper builds and identifies the native harnesses, validates prerequisites and invokes the unchanged loop matrix. The matrix retains all storage mutation and cleanup responsibility. GitHub CI uses the same wrapper.

**Tech Stack:** Python 3.10+, Rust 1.88.0, existing Cargo features and GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-26-wave1-evidence-runner-design.md`

## Global Constraints

- No new production storage operation or authorization boundary.
- Exactly three successful complete repetitions are required for PASS.
- Default mode is read-only `check`; destructive mode requires root/Linux and explicit VM opt-in.
- Reuse all six native binaries and the existing separate Cargo feature builds.
- Keep uncertain fixtures for inspection; never add broad cleanup or fstab repair.
- Require clean exact source and a matching build manifest; preserve logs and terminal failure evidence.

## Review Focus

- Zero child exit with omitted optional profiles must fail on missing markers.
- A changed binary or source tree must fail before destructive launch.
- Ctrl-C/SIGTERM must allow matrix cleanup and retain an interrupted report.
- Evidence capture failure or changed fstab/resource identities must prevent PASS.
- Preexisting report paths, symlinks and partial previous manifests must not be overwritten or accepted.

## Task 1: Runner and behavioral tests

**Files:** Create `tools/preprod.py`, `tests/integration/test_preprod.py`.

**Interfaces:** Produce the `build`, `check`, `run` CLI from the spec; output `target/preprod/build.json`, `report.json`, `SUMMARY.txt`, per-attempt logs and snapshots.

- [ ] Write rootless regressions for the five review-focus failures plus three-run success and first-failure stop.
- [ ] Run `python3 -I tests/integration/test_preprod.py -v`; observe RED for missing behavior.
- [ ] Implement source/build validation, stable inventory comparison, complete marker acceptance and retained reports.
- [ ] Run the same suite; expect all tests PASS. Run the existing harness tests; expect 42 PASS.
- [ ] Review the diff and commit the runner with its tests.

## Task 2: CI and operator entry point

**Files:** Modify `tools/validate.sh`, `.github/workflows/ci.yml`, `README.md`, `docs/HANDOFF.md`, `docs/PREPROD_TEST_PLAN.md`, `docs/ROADMAP.md`.

**Interfaces:** Consume Task 1 CLI and report paths. CI uses its checkout SHA, builds all six binaries via `build`, runs with explicit VM opt-in and uploads the output directory with `if: always()`.

- [ ] Add runner tests to source validation and replace the repeated CI shell matrix with the same runner.
- [ ] Update the test instructions and current handoff; distinguish read-only CLI, harness-tested paths and pending manual distribution acceptance.
- [ ] Run source validation and workflow syntax validation; expect clean exits.
- [ ] Obtain independent branch review, fix material findings with regressions, and open a PR.
- [ ] Require all exact-head CI checks, inspect the real three-run report, merge and verify post-merge CI.

# M1B13 Frozen Execution Intent Manifest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze the exact approved M1A semantic plan into a deterministic, immutable, non-executable M1B13 intent manifest bound to the current locked durable `Approved` journal, without synthesizing storage mutations.

**Architecture:** Add `crates/executor/src/execution_intent.rs`. It consumes only the current `LockedExecutionSession` and M1B12 `ExactPlanApproval`, revalidates durable approval/session/journal identity, translates every approved `PlanStep` one-to-one into typed semantic intent, validates graph/target identity, and derives read-only verification barriers. The journal remains unchanged in `Approved`; command compilation and execution remain outside M1B13.

**Tech Stack:** Rust 1.88, `serde`, `serde_json`, `sha2`, `thiserror`, `lsm-planner`, `lsm-executor`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-21-m1b13-frozen-execution-intent-design.md`

## Global Constraints

- Baseline master: `e4c34bf952b942a37b4ea7c79effd2f18162fc03`; CI #512 and Portable Linux #391 succeeded.
- `MUTATION_ENABLED = false`.
- No `apply`, privileged helper, `Command::new`, shell execution, or transition to `Executing`.
- No execution of `sfdisk`, `pvresize`, `lvextend`, `resize2fs`, `xfs_growfs`, recovery, mount/fstab, or swap mutations.
- Manifest is serialization-only; no `Deserialize`.
- Never synthesize `pvresize` or any mutation absent from approved `PlanStep`s.
- Intent freezing never appends journal events or changes `mutation_may_have_started`.
- Every mutation candidate receives a read-only verification barrier.
- Owner acceptance for mutation-capable rollout remains outstanding.


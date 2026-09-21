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

## Review Focus

1. Non-linear/cyclic dependencies: Task 4 tests duplicate IDs, unknown dependencies, self-dependency and cycles.
2. 4Kn partition geometry: Task 5 tests exact 4096-byte sector preservation.
3. Ambiguous LV identity: Task 5 rejects duplicate matching LV UUIDs.
4. Filesystem/mount alias drift: Task 5 rejects a mountpoint mismatch even when filesystem type matches.
5. Approved journal memory/disk divergence: Task 6 rejects a live journal that differs from durable state.

---

### Task 1: Correct the post-M1B12 continuity baseline

**Files:** `docs/HANDOFF.md`, `docs/M1B_HANDOFF.md`

**Interfaces:** consumes merged M1B12 master `e4c34bf952b942a37b4ea7c79effd2f18162fc03`, CI #512 and Portable Linux #391; produces accurate M1B13 continuation context.

- [ ] **Step 1: Update stale continuity.** Mark PR #26/`feature/m1b12-exact-plan-approval` historical; record master `e4c34bf952b942a37b4ea7c79effd2f18162fc03`, CI #512, Portable Linux #391, and the x86_64 attempt #2 success after the external Docker Hub reset while pulling `almalinux:9`. Mark `feature/m1b13-frozen-execution-intent` current.

- [ ] **Step 2: Verify continuity**

```bash
grep -n "Current PR:.*#26\|feature/m1b12-exact-plan-approval" docs/HANDOFF.md docs/M1B_HANDOFF.md
grep -n "e4c34bf952b942a37b4ea7c79effd2f18162fc03\|M1B13" docs/HANDOFF.md docs/M1B_HANDOFF.md
```

Expected: no stale-current match; new master/M1B13 are present.

- [ ] **Step 3: Commit**

```bash
git add docs/HANDOFF.md docs/M1B_HANDOFF.md
git commit -m "docs: advance continuity to merged M1B12"
```

---

### Task 2: Establish the positive M1B13 contract and durable read boundary

**Files:** create `crates/executor/src/execution_intent.rs`; modify `crates/executor/src/lib.rs`, `crates/executor/src/locked_session.rs`.

**Interfaces:** consumes `LockedExecutionSession<'_>`, `ExactPlanApproval`, approved `OperationJournal`, `FrozenExecutionHandoff::plan()`; produces `freeze_execution_intent(...)`, `require_current_durable_journal()`, and immutable manifest getters.

- [ ] **Step 1: Write RED test `exact_approved_session_freezes_non_executable_intent`.** Compose existing revalidation/preconditions/approval helpers to reach `Approved`, retain `before = session.journal().clone()`, call `freeze_execution_intent`, and assert:

```rust
assert_eq!(manifest.status(), ExecutionIntentManifestStatus::FrozenNonExecutable);
assert_eq!(manifest.approval_id(), approval.approval_id());
assert_eq!(manifest.plan_id(), handoff.plan().plan_id());
assert_eq!(manifest.evidence_bundle_id(), approval.evidence_bundle_id());
assert_eq!(manifest.locked_session_id(), session.session_id());
assert_eq!(manifest.steps().len(), handoff.plan().steps().len());
assert!(manifest.owner_acceptance_required());
assert!(!manifest.mutation_enabled());
assert_eq!(session.journal(), &before);
assert_eq!(session.journal().phase, JournalPhase::Approved);
assert!(!session.journal().mutation_may_have_started);
assert_eq!(store.load(&before.journal_id).unwrap(), before);
```

Also assert a second lock returns `HostLockError::Busy`.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p lsm-executor exact_approved_session_freezes_non_executable_intent -- --exact
```

Expected: compile failure because the M1B13 API/types do not exist.

- [ ] **Step 3: Add the read-only durable helper**

```rust
pub(crate) fn require_current_durable_journal(&self) -> Result<(), LockedSessionError> {
    let store = self
        .journal_store
        .ok_or(LockedSessionError::DurableJournalRequired)?;
    let persisted = store.load(&self.journal.journal_id)?;
    if persisted != self.journal {
        return Err(LockedSessionError::DurableJournalMismatch);
    }
    Ok(())
}
```

Refactor the existing durable transition helpers to call this before cloning/persisting.

- [ ] **Step 4: Add the minimal immutable model**

`execution_intent.rs` defines:

```rust
pub enum ExecutionIntentManifestStatus { FrozenNonExecutable }
pub enum FrozenIntentRole { PreExecutionEvidence, MutationCandidate, Verification }

pub enum FrozenIntentAction {
    RevalidateSnapshot
# Linux Storage Manager — engineering handoff

Last live GitHub audit: **2026-09-21**.

`AGENTS.md` is the governing engineering document. Re-check live GitHub refs and changed
governing-document blob SHAs before continuing.

## Verified master baseline

Repository: `PastFly/Linux-Storage-Manager`

Verified master:

`e4c34bf952b942a37b4ea7c79effd2f18162fc03`

Latest merged milestone:

- PR **#26 — M1B12: bind exact operator approval durably**
- approved PR head: `031b0afd1ac9ac527d8d0f3617824a0c11ef7edf`
- squash result / master: `e4c34bf952b942a37b4ea7c79effd2f18162fc03`
- post-merge **CI #512: success**
- post-merge **Portable Linux #391: success**
- Portable Linux #391 x86_64 succeeded on attempt #2 after attempt #1 hit an external
  Docker Hub connection reset while pulling `almalinux:9`.

M0 discovery, M1A planning and M1B0-M1B12 are merged. PR #26 and
`feature/m1b12-exact-plan-approval` are historical continuation points only.

## Current milestone — M1B13 frozen execution intent

Current branch:

`feature/m1b13-frozen-execution-intent`

M1B13 remains strictly non-mutating. It freezes the exact approved semantic `PlanStep`
graph into a typed, immutable, non-executable intent manifest. It revalidates the current
locked session, exact approval binding and durable `Approved` journal before freezing.

M1B13 adds no journal transition. The durable journal remains exactly `Approved`, and
`MUTATION_ENABLED=false`.

## Durable approval safety rules

Before `PreconditionsVerified -> Approved`:

1. the host-exclusive lock is still held by the same session;
2. the session journal is exactly `PreconditionsVerified`;
3. a durable journal store is attached;
4. the durable journal on disk exactly equals the live session journal;
5. the supplied M1B11 verification matches the same session/journal/plan/target;
6. the current journal SHA-256 still equals the verification's frozen journal digest;
7. the explicitly approved plan/evidence/target values exactly match;
8. mutation remains disabled;
9. owner acceptance remains an explicit future gate.

The next journal is built on a clone, durably persisted, and only then replaces the
in-memory journal.

On durable reload, the store reconstructs the exact pre-approval journal from the event
history and verifies its digest against the stored approval binding. Changing only the stored
preconditions digest and recomputing the approval ID is therefore insufficient to make a stale
approval record validate. These SHA-256 values are structural identity fingerprints, not a
secret-key authenticity mechanism.

## Historical TDD evidence for M1B12

The milestone has explicit RED proofs:

- **CI #472**: initial contract failed because `approve_exact_plan` and durable
  `OperationJournal.approval` did not exist;
- **CI #482**: planner accepted an approval whose preconditions-journal binding was changed;
  the dedicated regression test failed until the transition itself validated that digest;
- **CI #484**: durable reload accepted a tampered preconditions-journal binding even after
  its approval fingerprint was recomputed; the journal store was then hardened to reconstruct
  and verify the original `PreconditionsVerified` state;
- **CI #499**: durable reload ignored an injected unknown approval-binding schema field; the
  binding now carries an explicit schema version, v1 is part of its fingerprint, and any other
  durable approval schema fails closed.

Final M1B12 release evidence is the merged master plus post-merge CI #512 and Portable Linux #391.

## M1B12 regression contract

Positive path proves:

- exact approval advances only `PreconditionsVerified -> Approved`;
- the host lock remains exclusive;
- durable reload preserves `Approved` plus the exact approval binding;
- `mutation_may_have_started=false`;
- owner acceptance remains required;
- `MUTATION_ENABLED=false`.

Fail-closed coverage includes:

- wrong explicit plan ID;
- wrong explicit evidence bundle ID;
- wrong explicit target-manifest digest;
- stale preconditions-journal digest;
- M1B11 verification from another locked session;
- wrong journal phase;
- repeated approval;
- durable journal divergence;
- approval binding for another preconditions journal;
- durable reload tampering, including recomputed approval fingerprints.

Every failed approval attempt must leave the live journal unadvanced.

## Safety boundary

`MUTATION_ENABLED = false`

M1B12 does **not** add:

- `apply`;
- `ExecutionStarted` through the executor layer;
- privileged helpers;
- partition-table writes;
- `pvresize`;
- `lvextend`;
- `resize2fs` / `xfs_growfs` execution;
- mount/fstab mutation;
- swap mutation;
- recovery-command execution;
- automatic owner acceptance.

The planner retains its future journal state model, but no M1B12 executor API crosses the
mutation boundary.

## M1B13 boundary and later work

Do not enable production storage writes merely because an exact approval record exists.

Before a first write-capable executor milestone, separately design and review:

- explicit owner acceptance for mutation-capable rollout;
- privileged-helper boundary and privilege model;
- minimal executable command allowlist;
- exact argv specs;
- per-layer rediscovery and verification;
- interruption handling;
- recovery semantics and UX;
- test-only mutation adapters;
- disposable write matrix.

## Git workflow

- Start work from live `master`.
- Use feature branches and PRs.
- Require complete CI and Portable Linux success on the exact PR head.
- Do not merge any M1B13 public-main PR without explicit owner authorization for that PR and its exact head SHA.
- After an authorized squash merge, verify the new master and post-merge Actions before starting the next milestone.

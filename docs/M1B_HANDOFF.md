# M1B pre-executor handoff

M1B is the safety foundation between read-only planning and any future mutation-capable
executor. It remains fail-closed and capability/topology driven.

Verified master baseline on 2026-09-21:

`e4c34bf952b942a37b4ea7c79effd2f18162fc03`

That master contains M1B0 through M1B12 and passed post-merge CI #512 and Portable Linux #391. Portable Linux #391 x86_64 succeeded on attempt #2 after attempt #1 hit an external Docker Hub connection reset while pulling `almalinux:9`.

## Non-negotiable boundary

`MUTATION_ENABLED = false`

There is no current production API that resizes partitions, PVs, LVs or filesystems,
changes mount/fstab or swap state, executes recovery commands, or starts mutation-capable
execution.

## Milestone map

### M1B0 — frozen execution handoff
Freezes the exact M1A plan, basis/capability identity, target manifest, filesystem decision,
guard state, owner-acceptance requirement and `mutation_enabled=false`.

### M1B1 — host-exclusive lock
Adds the nonblocking OS-backed host storage lock with RAII release.

### M1B2 — locked revalidation
Revalidates exact target identity and capability inventory while the lock remains held.

### M1B3 — durable journal store
Adds secure atomic persistence, reload validation and recovery-state preservation.

### M1B4 — durable locked-session progression
Durably records `HostLockHeld` and `IdentityRevalidated`.

### M1B5 — immutable backup manifest
Freezes exact partition/LVM metadata capture and recovery command specs without executing them.

### M1B6/M1B7 — disposable recovery evidence
Proves GPT/DOS partition-table and LVM metadata recovery on owned disposable fixtures.

### M1B8 — locked backup capture
Captures required metadata backup artifacts after locked revalidation and produces SHA-256
receipts while recovery/mutation remains disabled.

### M1B9 — backup receipt revalidation
Reopens the exact artifacts and verifies manifest binding, size and SHA-256 from disk.

### M1B10 — immutable pre-mutation evidence
Combines fresh identity/capability/filesystem decisions and revalidated backup evidence into
an immutable bundle without advancing the journal.

### M1B11 — durable preconditions verification
Merged as PR #25. Binds evidence to the current locked session and durably advances only:

`IdentityRevalidated -> PreconditionsVerified`

It freezes the exact `PreconditionsVerified` journal identity for later approval and keeps
owner acceptance/mutation as future gates.

### M1B12 — exact-plan approval

Merged as PR #26 at master `e4c34bf952b942a37b4ea7c79effd2f18162fc03`.
Post-merge CI #512 and Portable Linux #391 succeeded.

M1B12 durably records only:

`PreconditionsVerified -> Approved`

The exact schema-v1 approval binding remains part of the durable journal. It does not authorize this codebase to enter `Executing`.

### M1B13 — frozen execution intent

Current branch: `feature/m1b13-frozen-execution-intent`.

M1B13 freezes the exact approved `PlanStep` graph into typed semantic intent plus mandatory read-only verification barriers. It adds no journal transition and keeps `MUTATION_ENABLED=false`.

## ExactApprovalBinding

The durable `OperationJournal` now carries an optional structured approval binding.

For an `Approved` journal it contains:

- `schema_version` (currently exactly `1`);
- `approval_id`;
- `plan_id`;
- `evidence_bundle_id`;
- `target_manifest_digest`;
- `locked_session_id`;
- `preconditions_journal_digest`.

`approval_id` is a SHA-256 fingerprint over the schema version and exact binding fields.
Durable reload rejects any approval-binding schema other than v1.

A journal containing an approval transition without a binding, or a binding without an
approval transition, fails durable reload validation.

Durable reload additionally reconstructs the pre-approval journal by removing the approval
event/binding and restoring the `PreconditionsVerified` phase. Its SHA-256 must exactly match
`preconditions_journal_digest`. Recomputing the approval fingerprint after substituting a
different journal digest is therefore insufficient to forge a valid durable approval.

## Atomic transition semantics

M1B12 follows the same durability pattern as M1B11:

1. require the durable journal on disk to equal the current live session journal;
2. clone the live `PreconditionsVerified` journal;
3. apply the exact approval transition/binding to the clone;
4. durably persist the clone;
5. update the in-memory journal only after successful persistence.

A failed persist or binding check cannot make the live session appear approved.

## M1B12 tests

Positive:

- exact caller-supplied plan/evidence/target approval succeeds;
- host lock remains exclusive;
- durable reload returns `Approved`;
- exact approval binding survives reload;
- mutation boundary is not crossed;
- owner acceptance remains required.

Fail-closed:

- wrong explicit plan;
- wrong explicit evidence bundle;
- wrong explicit target manifest;
- stale preconditions-journal digest;
- verification from another lock lifetime;
- wrong phase;
- repeated approval;
- durable journal mismatch;
- planner approval bound to another journal state;
- recomputed/tampered durable approval binding.

TDD RED history includes CI #472, #482, #484, #499 and #507. CI #499 proved that durable
reload did not yet reject an unknown approval-binding schema; CI #507 then proved that the
in-memory planner transition also needed the same explicit schema-v1 rejection. The merged
M1B12 exact head passed CI #511 and Portable Linux #390 before merge, followed by post-merge
CI #512 and Portable Linux #391.

## M1B13 safety boundary

Even after M1B12, `Approved` is an authorization record, not permission for this codebase to
mutate storage.

Before any production path can enter `Executing`, separately review:

- explicit owner acceptance for mutation-capable rollout;
- privileged-helper architecture;
- minimal command allowlist;
- exact executable argv specs;
- post-each-layer rediscovery;
- per-layer verification;
- crash/interruption semantics;
- recovery UX;
- disposable integration matrix.

Backups and approval are defense-in-depth. Neither permits bypassing topology proof.


## M1B13 frozen execution intent contract

M1B13 freezes the exact M1B12-approved plan into `FrozenExecutionIntentManifest`.

The manifest binds approval ID, approved journal ID/digest, plan ID, evidence bundle ID, target
manifest digest and locked-session ID. Every source `PlanStep` is represented exactly once,
dependency lists are preserved, and malformed/cyclic graphs fail closed.

Semantic actions are typed as pre-execution evidence, mutation candidates or verification.
No `pvresize` or other absent mutation is synthesized. Every mutation candidate receives a
read-only barrier requiring fresh target identity, fresh capabilities, expected-state validation
and stop-on-mismatch before any later mutation can be considered by a future executor.

Freezing the manifest does not change the durable journal: it remains `Approved`, with
`mutation_may_have_started=false` and `MUTATION_ENABLED=false`.

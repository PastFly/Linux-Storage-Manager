# M1B pre-executor handoff

M1B is the safety foundation between read-only planning and any future mutation-capable
executor. It remains fail-closed and capability/topology driven.

Verified master baseline on 2026-09-21:

`72594ed3128d5c373e79c53ec81a4d9107817b16`

That master contains M1B0 through M1B11 and passed post-merge CI #471 and Portable Linux #350.

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

Current PR: **#26**, branch `feature/m1b12-exact-plan-approval`.

M1B12 adds only:

`PreconditionsVerified -> Approved`

It does not cross into `Executing`.

The caller must explicitly supply the values being approved:

- exact plan ID;
- exact M1B11 evidence bundle ID;
- exact target-manifest digest.

The approval API also requires the M1B11 verification object from the same locked session.
That object freezes:

- evidence bundle ID;
- locked-session ID;
- journal ID;
- plan ID;
- target-manifest digest;
- SHA-256 of the exact `PreconditionsVerified` journal.

Before approval, all six identities are checked against the live session.

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

TDD RED history includes CI #472, #482, #484 and #499. CI #499 specifically proved that an
unknown durable approval-binding schema was not yet rejected; explicit schema-v1 validation
closes that fail-open path. Use the final exact PR-head Actions as the actual completion evidence.

## Next safety boundary

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

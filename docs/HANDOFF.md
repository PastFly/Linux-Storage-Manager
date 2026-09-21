# Linux Storage Manager — engineering handoff

Last live GitHub audit: **2026-09-21**.

`AGENTS.md` is the governing engineering document. Always re-check live GitHub refs and
the blob SHA of governing documentation before continuing from this handoff.

## Verified master baseline

Repository: `PastFly/Linux-Storage-Manager`

Verified master:

`810dcc512a0f23000d7bf49f090ed22d5688ab01`

Latest merged milestone on that master:

- PR **#24 — M1B10: freeze non-mutating pre-mutation evidence**
- PR head: `358ea9a8034f931aaf0b74146c330f3e569cffff`
- squash result / master: `810dcc512a0f23000d7bf49f090ed22d5688ab01`
- post-merge **CI #452: success**
- post-merge **Portable Linux #331: success**
- PR-head CI immediately before merge was CI #451 / Portable Linux #330.

The obsolete M1A draft PR #2 and `feature/m1a-read-only-planner` are historical only.
They are not a continuation point.

## Current milestone

M0 discovery and M1A planning are complete. M1B0 through M1B10 are merged into master.

Current development is **M1B11 — durable preconditions verification**, isolated in:

- branch: `feature/m1b11-preconditions-verification`
- PR: **#25**

M1B11 remains strictly non-mutating. Its boundary is:

`IdentityRevalidated -> PreconditionsVerified`

The transition is accepted only when an immutable pre-mutation evidence bundle proves the
same current locked execution session, exact frozen handoff/plan/target identity, successfully
revalidated backup evidence, and a filesystem decision with no outstanding mandatory check.

The verifier additionally requires the durable journal on disk to equal the in-memory
`IdentityRevalidated` journal before creating and atomically persisting the next journal state.

A process-local locked-session binding is frozen into evidence schema v2 and included in the
bundle fingerprint. This prevents replaying evidence from an earlier locked session even when
the handoff, plan and target identity are otherwise identical.

## Safety state

The project remains safety-first and fail-closed.

`MUTATION_ENABLED = false`

M1B11 does **not** add:

- an `apply` command;
- `ExecutionStarted`;
- partition writes;
- `pvresize`;
- `lvextend`;
- `resize2fs` or `xfs_growfs` execution;
- mount/fstab mutation;
- swap mutation;
- recovery-command execution;
- automatic owner acceptance;
- exact-plan approval.

The host lock remains owned through the transition. Any binding mismatch, incomplete evidence,
filesystem prerequisite, mutation-enabled state, wrong journal phase, cross-session evidence,
missing/tampered backup evidence, or durable-journal divergence fails without advancing the
journal.

## M1B foundation already merged

The master baseline already contains:

1. frozen non-mutating M1B0 execution handoff;
2. host-exclusive advisory lock;
3. locked target/capability revalidation;
4. atomic durable journal storage;
5. durable `HostLockHeld` and `IdentityRevalidated`;
6. immutable backup/recovery manifests;
7. GPT/DOS partition recovery drills on disposable loops;
8. LVM metadata recovery drill on disposable loop/LVM fixtures;
9. locked metadata backup capture with SHA-256 receipts;
10. receipt revalidation from disk;
11. immutable M1B10 `PreMutationEvidenceBundle`.

## M1B11 regression contract

The M1B11 test matrix covers positive durable transition plus fail-closed rejection of:

- foreign plan ID;
- foreign handoff ID;
- changed target manifest binding;
- tampered backup receipt evidence;
- missing backup binding;
- stale capability evidence;
- changed filesystem identity;
- filesystem `Blocked`;
- filesystem `AdapterRequired`;
- required offline ext4 health check;
- required XFS read-only scrub check;
- wrong journal phase;
- repeated transition;
- evidence replayed from another locked session;
- non-durable session;
- unexpected mutation-enabled evidence;
- durable journal diverging from the live locked session.

No test touches host block devices. Existing destructive integration drills remain restricted to
owned disposable loop/LVM fixtures.

The initial TDD RED run was **CI #453**, which failed because `verify_preconditions`
did not yet exist. Later branch heads must be judged from live PR #25 checks; do not copy a
stale run number from this document.

## Next milestone after M1B11

The intended next step is a separate **M1B12 — exact-plan approval model**.

It should bind explicit operator approval to:

- exact plan ID;
- exact pre-mutation evidence bundle ID;
- current target identity;
- current durable journal state.

Only then may the journal transition:

`PreconditionsVerified -> Approved`

Even after M1B12, storage mutation should remain disabled until the privileged-helper,
command allowlist, per-layer rediscovery/verification, interruption/recovery model and
disposable write matrix are separately reviewed and accepted.

## Git workflow

- Always start new work from live `master`.
- Work in feature branches.
- Keep commits logically scoped.
- Push and open a PR to master.
- Run CI and Portable Linux to completion and fix every failure.
- Do **not** merge PR #25 or any later public-main PR without explicit owner authorization
  for that exact PR/head.
- After an authorized squash merge, re-read the new master and post-merge Actions before
  starting the next milestone.

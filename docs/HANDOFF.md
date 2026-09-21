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

M1B13 is still strictly non-mutating. It freezes the exact approved semantic plan into a typed, immutable, non-executable intent manifest. The durable journal remains `Approved`.

The approved M1B13 design is in:

`docs/superpowers/specs/2026-09-21-m1b13-frozen-execution-intent-design.md`

The implementation plan is in:

`docs/superpowers/plans/2026-09-21-m1b13-frozen-execution-intent.md`

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


## M1B13 implementation state

Branch: `feature/m1b13-frozen-execution-intent`.

The branch now contains the typed frozen-intent model, exact approval/durable-journal binding,
one-to-one operation mapping, dependency-graph validation, frozen target semantic validation,
and fail-closed approval mismatch coverage. CI #526 is retained as a RED/diagnostic run that
exposed a duplicate contract test and a missing test-only approval fixture; both were corrected.
Final completion evidence must come from CI and Portable Linux on the final exact PR head.

M1B13 adds no journal transition and no process execution. The next intended milestone is M1B14,
a non-executing semantic-to-argv compiler plus minimal executable allowlist.

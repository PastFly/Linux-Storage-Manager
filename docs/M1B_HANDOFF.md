# M1B pre-executor handoff

M1B is the guarded foundation between read-only planning and any future mutation-capable
executor. It must remain fail-closed and capability/topology driven.

Live master baseline verified on 2026-09-21:

`810dcc512a0f23000d7bf49f090ed22d5688ab01`

That master contains M1B0 through M1B10 and passed post-merge CI #452 and Portable Linux #331.

## Non-negotiable boundary

`MUTATION_ENABLED = false`

No current production API may resize partitions, PVs, LVs or filesystems, change mount/fstab
state, mutate swap, or execute recovery commands.

Owner acceptance remains an explicit future gate.

## Milestone map

### M1B0 — frozen execution handoff

Freezes one exact M1A plan together with:

- plan-basis digest;
- capabilities digest;
- target identity manifest;
- filesystem growth decision;
- execution guard;
- explicit owner-acceptance requirement;
- mutation disabled.

### M1B1 — host-exclusive lock

Adds the OS-backed nonblocking host storage lock with RAII release.

### M1B2 — locked revalidation

While the lock is held, revalidates the exact target identity and capabilities.
Any change fails closed.

### M1B3 — durable journal store

Persists validated journal records with secure same-directory temporary files, fsync,
atomic rename and directory fsync. Tampered/impossible histories fail closed.

### M1B4 — durable locked-session progression

Durably records `HostLockHeld` and, after successful locked revalidation,
`IdentityRevalidated`.

### M1B5 — immutable metadata backup manifest

Freezes exact partition/LVM backup and recovery command specs without executing them.

### M1B6 — partition metadata recovery drill

Proves GPT and DOS/MBR metadata backup/restore on owned disposable loop fixtures.

### M1B7 — LVM metadata recovery drill

Proves VG metadata backup/restore on an owned disposable loop/LVM fixture.

### M1B8 — locked backup capture

After successful locked identity revalidation, captures required partition/LVM metadata
backups with secure artifact paths and SHA-256 receipts. Recovery execution remains disabled.

### M1B9 — backup receipt revalidation

Reopens backup artifacts with fail-closed path rules and verifies exact manifest binding,
size and SHA-256 from disk.

### M1B10 — immutable pre-mutation evidence

Builds `PreMutationEvidenceBundle` from:

- the identity-revalidated locked session;
- a fresh target identity check;
- a fresh capability check;
- a freshly recomputed filesystem decision;
- revalidated backup evidence.

M1B10 deliberately leaves the durable journal at `IdentityRevalidated`.

### M1B11 — durable preconditions verification

Current PR: **#25**, branch `feature/m1b11-preconditions-verification`.

M1B11 introduces the first safe journal progression after M1B10:

`IdentityRevalidated -> PreconditionsVerified`

It still performs no storage mutation.

The verifier accepts only:

- the current `LockedExecutionSession`;
- the corresponding immutable `PreMutationEvidenceBundle`.

Required invariants:

- the host lock is still owned by the session;
- the journal is exactly `IdentityRevalidated`;
- a durable journal store is attached;
- the durable journal on disk exactly equals the session journal;
- evidence schema is the M1B11-aware schema v2;
- evidence fingerprint exactly matches its contents;
- evidence is bound to the exact live locked-session ID;
- handoff ID exactly matches;
- plan ID exactly matches;
- target-manifest digest exactly matches;
- backup manifest and receipt IDs are present digest identities;
- the backup receipt was successfully revalidated;
- evidence status is `EvidenceComplete`;
- no evidence blocker remains;
- filesystem state is `ReadyOnlineGrow`;
- no mandatory filesystem read-only check/future gate remains;
- `mutation_enabled` remains false everywhere;
- owner acceptance remains required rather than being auto-granted.

A clean mounted ext4 decision can contain informational guidance such as not running e2fsck
on the mounted filesystem. M1B11 therefore distinguishes those notes from an actual
mandatory filesystem check.

The transition is produced by cloning the current journal, applying
`JournalTransition::PreconditionsVerified` to the clone, durably persisting that next
state, and only then replacing the in-memory session journal. A failed persist cannot make the
live session appear advanced.

## Locked-session evidence replay protection

M1B10 originally bound evidence to handoff/plan/target identity. M1B11 additionally creates a
process-local SHA-256 locked-session binding token when a session is acquired. Evidence schema
v2 freezes this token and includes it in the bundle fingerprint.

This prevents evidence from a previous lock lifetime from authorizing the same transition in
a later locked session, even when both sessions use the same plan and target identity.

The token is not a cross-process recovery credential. `PreMutationEvidenceBundle` has no
Deserialize implementation; after process restart the executor must rediscover and build fresh
evidence rather than replaying an old in-memory bundle.

## M1B11 tests

Positive:

- exact current-session evidence advances to `PreconditionsVerified`;
- the host lock is still exclusive during verification;
- durable reload returns exactly `PreconditionsVerified`;
- `mutation_may_have_started` remains false;
- owner acceptance remains outstanding.

Fail-closed:

- foreign plan ID;
- foreign handoff ID;
- changed target manifest;
- tampered backup receipt;
- missing backup;
- stale capabilities;
- changed filesystem identity;
- filesystem `Blocked`;
- filesystem `AdapterRequired`;
- required offline ext4 check;
- required XFS check;
- wrong journal phase;
- repeated transition;
- evidence from another locked session;
- non-durable session;
- mutation flag unexpectedly true;
- durable journal mismatch.

All of these must leave the journal unadvanced.

The initial TDD RED proof was CI #453: it failed specifically because the new
`verify_preconditions` API did not yet exist.

## Next: M1B12 exact-plan approval

Do not combine approval with M1B11.

M1B12 should bind an explicit operator decision to:

- exact plan ID;
- exact pre-mutation evidence bundle ID;
- current target identity;
- durable journal state.

Only an exact accepted approval may advance:

`PreconditionsVerified -> Approved`

Do not add `ExecutionStarted` or any storage-changing command as part of M1B12.

## Before first real mutation

Separately design and review:

- explicit owner acceptance;
- privileged-helper boundary;
- minimal executable allowlist;
- exact argv command specs;
- privilege model;
- per-layer rediscovery;
- per-layer verification;
- interruption semantics;
- recovery semantics and UX;
- exact approval UX;
- test-only mutation adapters;
- disposable integration matrix.

Backups are defense-in-depth, not permission to bypass topology proof.

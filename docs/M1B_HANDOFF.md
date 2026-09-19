# M1B0: frozen execution handoff

Status: pre-executor foundation, non-mutating.

M1B0 bridges the completed M1A planner into future executor work without enabling any
storage mutation. The handoff is an immutable, non-deserializable Rust data structure with private fields and read-only accessors; external callers cannot construct or flip its safety flags.
It performs no process execution, filesystem writes, lock acquisition, journal writes,
backup commands, resize commands or mount changes.

## What the handoff freezes

`build_frozen_execution_handoff(snapshot, capabilities, plan)` accepts only a
preview-ready M1A `PlanPreview` whose exact serialized discovery/capability basis still
matches the supplied inputs.

From that same basis it derives and binds:

- the exact M1A plan, plan ID and serialized discovery/capability basis digest;
- a separate capability-inventory digest for future live tool-capability revalidation;
- the target-scoped identity manifest and manifest digest;
- the filesystem growth/preflight decision;
- the existing execution-guard plan, including host-exclusive lock and durable-journal
  gates;
- one repeatable handoff ID over those frozen inputs.

A stale or blocked M1A preview is rejected before a handoff is produced.

## Deliberate execution boundary

Every M1B0 handoff contains:

- `mutation_enabled = false`;
- `owner_acceptance_required = true`.

This is architectural state, not UI wording. There is no API in M1B0 that flips either
field and no CLI command that consumes a handoff to run storage tools.

Before executor rollout, the project still requires explicit owner acceptance of the
completed M0/M1A safety baseline. A future executor must additionally:

1. acquire the host-exclusive storage-operation lock;
2. rediscover under that lock;
3. revalidate the frozen target identity;
4. satisfy filesystem health/online-offline preconditions;
5. create and verify required metadata backups;
6. obtain approval for the exact fresh plan;
7. durably create the operation journal;
8. execute only a separately implemented supported operation adapter;
9. rediscover and verify after every mutation boundary.

## Preflight status

A handoff is `future_executor_gates_required` only when the semantic route is supported
and the filesystem decision is not itself blocked/adapter-only. Health checks such as
offline ext4 verification or read-only XFS scrub remain explicit future gates.

If the filesystem decision is blocked or requires an unsupported adapter, the handoff is
created as `blocked` so the reason stays inspectable, while mutation remains disabled.

## M1B3 durable journal foundation

The dedicated executor crate now has an atomic durable journal store for the already-defined
`OperationJournal` model. It can persist/reload validated journal state, including
`RecoveryRequired`, but it is not connected to any mutation command. The owner-acceptance
gate and exact-plan approval requirements remain unchanged.

## M1B4 durable locked revalidation

The non-mutating locked session can now opt into a `DurableJournalStore`. In that mode,
`HostLockHeld` is persisted before the session is returned, and a successful fresh
identity/capability check persists `IdentityRevalidated` while the same host lock is still
held. Failed revalidation remains at the prior durable phase and requires a fresh session.

This does not expose precondition approval or execution transitions and does not authorize
storage mutation.

## M1B5 backup/recovery manifest

The executor crate can now derive an immutable metadata-backup manifest from one frozen
handoff. It contains only exact future process specifications and verification expectations
for required partition-table and LVM metadata backups. The model is deterministic,
non-deserializable as an execution authorization, and exposes no command runner.

Capture/restore execution and recovery drills remain future gated work.

## Non-goals

M1B0 does not implement:

- `sfdisk`, `pvresize`, `lvextend`, `resize2fs` or `xfs_growfs` execution;
- privileged helpers;
- lock-file I/O;
- persistent journal I/O;
- metadata backup/restore commands;
- automatic recovery;
- shrink or partition-start movement.


## M1B1/M1B2 locked pre-executor boundary

The frozen handoff can now enter a non-mutating host-exclusive lock session.

1. Reject a blocked or mutation-enabled handoff.
2. Acquire the host-wide advisory lock nonblockingly.
3. Capture fresh discovery/capability inputs while the lock remains held.
4. Revalidate the target-scoped identity manifest.
5. Revalidate the frozen tool-capability inventory.
6. Advance the in-memory journal only from `Planned` to `HostLockHeld` and, on exact revalidation, `IdentityRevalidated`.

A mismatch is terminal for that session: release the lock, rediscover, and build a fresh plan/handoff. There is still no apply path, durable journal write, metadata-backup execution, approval transition, or storage mutation API. Explicit owner acceptance remains a prerequisite for any mutation-capable executor rollout.

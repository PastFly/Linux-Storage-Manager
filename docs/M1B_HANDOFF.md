# M1B0: frozen execution handoff

Status: pre-executor foundation, non-mutating.

M1B0 bridges the completed M1A planner into future executor work without enabling any
storage mutation. The handoff is an immutable, non-deserializable Rust data structure.
It performs no process execution, filesystem writes, lock acquisition, journal writes,
backup commands, resize commands or mount changes.

## What the handoff freezes

`build_frozen_execution_handoff(snapshot, capabilities, plan)` accepts only a
preview-ready M1A `PlanPreview` whose exact serialized discovery/capability basis still
matches the supplied inputs.

From that same basis it derives and binds:

- the exact M1A plan and plan ID;
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

## Non-goals

M1B0 does not implement:

- `sfdisk`, `pvresize`, `lvextend`, `resize2fs` or `xfs_growfs` execution;
- privileged helpers;
- lock-file I/O;
- persistent journal I/O;
- metadata backup/restore commands;
- automatic recovery;
- shrink or partition-start movement.

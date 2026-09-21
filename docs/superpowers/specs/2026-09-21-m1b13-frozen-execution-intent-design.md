# M1B13 Frozen Execution Intent Manifest — Design

Date: 2026-09-21

## Status

Approved design for the next non-mutating Linux Storage Manager milestone.

Baseline:

- repository: `PastFly/Linux-Storage-Manager`
- master: `e4c34bf952b942a37b4ea7c79effd2f18162fc03`
- merged milestone: M1B12 / PR #26
- post-merge CI #512: success
- post-merge Portable Linux #391: success
- `MUTATION_ENABLED = false`

M1B13 must not add an `apply` command, a privileged helper, an executor path to
`ExecutionStarted`, or any storage-changing process execution.

## Intent

Linux Storage Manager is intended to let the user select the desired storage outcome rather
than manually compose a command chain. The system should derive the route automatically while
remaining fail-closed when topology or execution semantics are not proven.

M1B12 now proves that one exact plan/evidence/target/journal state was explicitly approved.
M1B13 adds the missing artifact between that approval and any future command compiler:
an immutable semantic description of exactly what the approved plan intends to change.

The artifact is data only. It is not executable authority.

## Goals

M1B13 must:

1. build a `FrozenExecutionIntentManifest` only from the current locked durable session and
   the exact M1B12 `ExactPlanApproval`;
2. bind the manifest to the exact approved journal state, approval, plan, evidence, target and
   locked-session identity;
3. preserve the exact M1A `PlanStep` dependency graph and reversibility metadata;
4. translate every currently supported `Operation` into a typed semantic intent without
   constructing shell commands or executable argv;
5. distinguish historical pre-execution prerequisites from future mutation candidates and
   verification actions;
6. derive mandatory post-mutation verification barriers without inventing additional mutation;
7. fail closed on stale approval/session/journal state, malformed identities, unsupported
   operation semantics, dependency inconsistencies or mutation-enabled state;
8. keep owner acceptance for mutation-capable rollout explicitly outstanding;
9. keep `MUTATION_ENABLED = false`.

## Non-goals

M1B13 does not:

- compile `sfdisk`, `pvresize`, `lvextend`, `resize2fs`, `xfs_growfs` or other
  storage-changing argv;
- spawn any process;
- write partition tables, LVM metadata, filesystems, mount state or swap state;
- enter `JournalPhase::Executing`;
- set `mutation_may_have_started=true`;
- create a privileged helper;
- grant owner acceptance;
- infer or synthesize a missing mutation operation;
- make a plan executable merely because an intent manifest exists.

## Alternatives considered

### 1. Compile exact argv immediately

Rejected for M1B13. This would couple the approval model to concrete tools before the semantic
operation set and verification boundaries have been frozen and reviewed.

### 2. Build the privileged helper immediately

Rejected for M1B13. That would cross the process/privilege boundary before the project has a
reviewed minimal allowlist and exact semantic-to-command compiler.

### 3. Freeze semantic execution intent first

Selected. It creates a narrow immutable contract between approved planning and a future command
compiler. The future compiler may only reduce this contract to allowlisted argv; it may not
expand it.

## Architecture

Add a focused executor module:

`crates/executor/src/execution_intent.rs`

The module owns:

- `FrozenExecutionIntentManifest`;
- `FrozenIntentStep`;
- `FrozenIntentAction`;
- `FrozenIntentRole`;
- `VerificationBarrierSpec`;
- `ExecutionIntentManifestStatus`;
- `ExecutionIntentError`;
- `freeze_execution_intent(...)`.

The planner remains the authority for the approved semantic plan. M1B13 does not move planner
logic into the executor.

The manifest derives from:

`LockedExecutionSession + ExactPlanApproval + FrozenExecutionHandoff + approved OperationJournal`

and never from free-form caller strings.

## Manifest identity

The manifest is serialization-only and has no `Deserialize` implementation.

Proposed shape:

```rust
pub struct FrozenExecutionIntentManifest {
    schema_version: u32,
    manifest_id: String,
    approval_id: String,
    approved_journal_id: String,
    approved_journal_digest: String,
    plan_id: String,
    evidence_bundle_id: String,
    target_manifest_digest: String,
    locked_session_id: String,
    status: ExecutionIntentManifestStatus,
    mutation_enabled: bool,
    owner_acceptance_required: bool,
    steps: Vec<FrozenIntentStep>,
    verification_barriers: Vec<VerificationBarrierSpec>,
    blockers: Vec<String>,
    future_gates: Vec<String>,
}
```

`manifest_id` is a SHA-256 structural fingerprint over schema version and every immutable
field except `manifest_id` itself.

The fingerprint is an identity/integrity binding inside the trusted state model. It is not a
secret-key authenticity mechanism.

## Required approval/session binding

`freeze_execution_intent` accepts only:

```rust
pub fn freeze_execution_intent(
    session: &LockedExecutionSession<'_>,
    approval: &ExactPlanApproval,
) -> Result<FrozenExecutionIntentManifest, ExecutionIntentError>
```

Before translating any plan step it must prove:

- session journal phase is exactly `Approved`;
- session still owns the host lock by construction;
- durable journal storage is attached;
- `MUTATION_ENABLED == false`;
- session/handoff mutation state is false;
- the durable journal on disk exactly equals the live session journal;
- journal `mutation_may_have_started == false`;
- journal contains the exact approval binding;
- approval ID matches the journal binding;
- approval plan ID matches handoff plan ID and journal plan ID;
- approval evidence bundle ID matches the journal approval binding;
- approval target-manifest digest matches handoff and journal;
- approval locked-session ID matches the current session;
- approval journal ID matches the current durable journal;
- the SHA-256 digest of the exact current `Approved` journal is frozen as
  `approved_journal_digest`;
- owner acceptance remains required.

Any mismatch returns an error before a manifest is returned.

## Semantic step model

Every source `PlanStep` is retained exactly once by ID and dependency list.

```rust
pub struct FrozenIntentStep {
    pub plan_step_id: u32,
    pub depends_on: Vec<u32>,
    pub reversibility: Reversibility,
    pub role: FrozenIntentRole,
    pub action: FrozenIntentAction,
}
```

Roles:

```rust
pub enum FrozenIntentRole {
    PreExecutionEvidence,
    MutationCandidate,
    Verification,
}
```

Actions map one-to-one from the current planner operations:

```rust
pub enum FrozenIntentAction {
    RevalidateSnapshot,
    BackupLvmMetadata { vg_uuid: String },
    BackupPartitionTableMetadata {
        disk: String,
        table_label: String,
        table_id: Option<String>,
    },
    ExtendPartition {
        partition: String,
        start_sector: u64,
        old_size_sectors: u64,
        new_size_sectors: u64,
        sector_size_bytes: u64,
    },
    ExtendLogicalVolume {
        lv_uuid: String,
        additional_extents: u64,
        expected_lv_size_bytes: u64,
    },
    GrowFilesystem {
        fs_type: String,
        mountpoint: String,
    },
    RediscoverAndVerify,
}
```

The mapping must not synthesize a storage mutation that is absent from the approved plan.

In particular, the current planner deliberately does not attempt partition/PV expansion in
the existing-VG-free LVM profile. M1B13 must not invent a `pvresize` semantic operation.
Future support for disk -> partition -> PV -> VG -> LV -> filesystem requires the planner to
gain an explicit PV-resize operation before any command compiler can authorize that layer.

## Historical prerequisite versus future execution

`RevalidateSnapshot`, `BackupLvmMetadata` and `BackupPartitionTableMetadata` are retained
in the manifest because they are part of the exact approved plan, but they are classified as
`PreExecutionEvidence`.

M1B13 does not mean these operations should be executed again. M1B8-M1B12 already provide the
locked evidence path. A future executor must consume their verified evidence rather than blindly
re-running them.

`ExtendPartition`, `ExtendLogicalVolume` and `GrowFilesystem` are
`MutationCandidate` intents.

`RediscoverAndVerify` is a `Verification` intent.

## Verification barriers

The current M1A plan can contain more than one mutating step before its final
`RediscoverAndVerify`. A future safe executor must not perform multiple destructive layers
without rediscovery between them.

M1B13 therefore derives safety-only `VerificationBarrierSpec` records. This does not expand
the approved mutation set.

For every `MutationCandidate` step, create one barrier:

```rust
pub struct VerificationBarrierSpec {
    pub after_plan_step_id: u32,
    pub before_next_mutation: bool,
    pub require_fresh_target_identity: bool,
    pub require_fresh_capabilities: bool,
    pub require_expected_state_check: bool,
    pub stop_on_mismatch: bool,
}
```

Required values are all `true`.

The future executor must complete the barrier after a mutation candidate and before any later
mutation candidate. The final barrier must also complete before the journal may reach
`Completed`.

Adding a read-only verification barrier is permitted because it narrows execution; adding a
mutation not present in the approved plan is forbidden.

## Dependency validation

Before returning a manifest:

- plan step IDs must be unique and non-zero;
- every dependency must reference an existing step;
- a step may not depend on itself;
- the dependency graph must be acyclic;
- all current plans must preserve the exact source dependency lists;
- step order in the manifest must be deterministic;
- every source step must map to exactly one intent step;
- no extra mutation candidate may appear;
- every mutation candidate must have exactly one derived verification barrier.

A dependency failure blocks manifest creation rather than being repaired automatically.

## Semantic validation

M1B13 validates intent values conservatively:

### ExtendPartition

- partition path is non-empty and contains no control characters;
- sector size is exactly 512 or 4096;
- `new_size_sectors > old_size_sectors`;
- start sector is unchanged because no move operation is supported;
- size multiplication is checked for overflow;
- frozen target identity must contain the exact partition identity expected by the approved
  handoff.

### ExtendLogicalVolume

- LV UUID is non-empty;
- `additional_extents > 0`;
- expected size is non-zero;
- frozen target identity must contain exactly one matching logical-volume UUID.

### GrowFilesystem

- filesystem type and mountpoint are non-empty;
- filesystem type must match the frozen filesystem decision;
- mountpoint must match the approved target filesystem identity;
- the filesystem decision must still represent the approved grow route.

M1B13 does not invent an exact filesystem size when the current M1A plan does not provide one.
That limitation remains explicit for M1B14 rather than being hidden by inference.

### Backup intents

Backup identities must match the already-frozen handoff identities. They remain evidence
records, not future recovery execution permission.

## Manifest status and future gates

A successfully frozen manifest uses:

`ExecutionIntentManifestStatus::FrozenNonExecutable`

and always contains:

- `mutation_enabled = false`;
- `owner_acceptance_required = true`.

The manifest's future gates include at least:

- explicit owner acceptance for mutation-capable rollout;
- reviewed semantic-to-argv compiler;
- minimal executable allowlist;
- privileged-helper protocol;
- per-layer rediscovery implementation;
- interruption/recovery semantics;
- disposable write matrix.

These are descriptive gates, not booleans that M1B13 can satisfy.

## Error handling

Errors are typed and fail closed. The minimum error surface includes:

- `SessionNotApproved`;
- `DurableJournalRequired`;
- `DurableJournalMismatch`;
- `MutationEnabled`;
- `MutationMayHaveStarted`;
- `ApprovalSessionMismatch`;
- `ApprovalJournalMismatch`;
- `ApprovalPlanMismatch`;
- `ApprovalEvidenceMismatch`;
- `ApprovalTargetMismatch`;
- `ApprovalBindingMismatch`;
- `InvalidApprovedJournalDigest`;
- `DuplicateStepId`;
- `UnknownDependency`;
- `DependencyCycle`;
- `InvalidPartitionIntent`;
- `InvalidLogicalVolumeIntent`;
- `InvalidFilesystemIntent`;
- `FrozenIdentityMismatch`;
- `Serialization`.

No error path advances the journal.

## Journal semantics

M1B13 does not add a journal transition.

The durable journal remains exactly:

`Approved`

Building or inspecting an intent manifest must not append an event, change
`mutation_may_have_started`, or enter `Executing`.

This keeps intent freezing separate from the future execution boundary.

## TDD contract

Implementation must begin with RED tests.

Positive tests:

1. exact current approved session produces one deterministic manifest;
2. manifest IDs are stable for identical approved inputs;
3. every source plan step maps exactly once;
4. every mutation candidate receives a verification barrier;
5. owner acceptance remains required;
6. mutation remains disabled;
7. journal remains byte-for-byte/digest-identical and in `Approved`;
8. host lock remains exclusive while the manifest is frozen.

Fail-closed tests:

1. wrong approval ID;
2. approval from another locked session;
3. approval from another durable journal;
4. wrong plan ID;
5. wrong evidence bundle ID;
6. wrong target manifest;
7. stale/tampered approved journal;
8. non-durable session;
9. wrong journal phase;
10. `mutation_may_have_started=true`;
11. mutation-enabled state;
12. duplicate step ID;
13. unknown dependency;
14. dependency cycle;
15. invalid partition geometry;
16. unknown LV UUID;
17. filesystem identity mismatch;
18. a source step that cannot be represented exactly;
19. attempted synthesis of an extra mutation.

Every failure must leave the journal unadvanced.

## Documentation and continuity

The M1B13 branch must first correct the post-merge continuity drift from M1B12:

- master is `e4c34bf952b942a37b4ea7c79effd2f18162fc03`;
- PR #26 is merged/historical;
- post-merge CI #512 is success;
- post-merge Portable Linux #391 is success, with x86_64 succeeding on attempt #2 after an
  external Docker Hub connection reset during attempt #1.

Then update:

- `README.md`;
- `docs/HANDOFF.md`;
- `docs/M1B_HANDOFF.md`;
- `docs/ROADMAP.md`;
- `docs/SAFETY.md`.

The docs must continue to state that `Approved` and a frozen intent manifest are not
authorization for this codebase to mutate production storage.

## Acceptance criteria

M1B13 is complete only when:

- the exact M1B12 approval/session/journal binding is revalidated;
- the semantic intent manifest is deterministic and immutable;
- every approved plan step is represented exactly once;
- no storage mutation is synthesized;
- verification barriers exist after every mutation candidate;
- all negative binding/graph/semantic tests fail closed;
- the journal remains `Approved`;
- `MUTATION_ENABLED=false`;
- no process execution or privileged helper is added;
- full CI and Portable Linux pass on the exact PR head;
- continuity reflects the merged M1B12 baseline and current M1B13 state.

## Next milestone

M1B14 may introduce a reviewed semantic-to-argv compiler and minimal executable allowlist.

M1B14 must still be non-executing: it may produce exact typed command specifications from the
M1B13 manifest, but must not spawn them.

Only after that compiler, the privileged-helper protocol, per-layer verification implementation,
interruption/recovery semantics, disposable write matrix and a fresh explicit owner-acceptance
gate are separately reviewed should a mutation-capable executor milestone be considered.

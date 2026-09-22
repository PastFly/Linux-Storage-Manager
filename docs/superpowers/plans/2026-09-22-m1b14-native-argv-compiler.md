# M1B14 Native semantic-to-argv compiler implementation plan

Date: 2026-09-22  
Baseline: `master@1ee443f1482733480a6700e7b94a610f1b3ce014`  
Branch: `feature/m1b14-native-argv-compiler`  
Design: `docs/superpowers/specs/2026-09-22-m1b14-native-argv-compiler-design.md`

## Working rule

Use strict TDD. Every meaningful safety contract starts RED, is observed failing on the branch,
then receives the minimum GREEN implementation. Keep all production compilation data-only:
M1B14 must never spawn a process or advance the journal.

## Task 1 — Define the closed compiled-command contract

Files:

- add `crates/executor/src/argv_compiler.rs`;
- update `crates/executor/src/lib.rs`.

RED tests first:

- the public API exposes a closed `NativeProgram` enum with exactly `Lvextend`,
  `Resize2fs`, `XfsGrowfs`;
- compiled manifest status is `CompiledNonExecutable`;
- no generic/string executable variant exists;
- compiled step model can represent evidence, verification and a typed native command;
- all public compiled types are Serialize-only.

GREEN:

- add data types and getters only;
- no compiler function yet;
- no `std::process`, `Command`, shell or helper type.

Commit after the first observed RED and after GREEN.

## Task 2 — Bind compiler to the exact approved durable session

Files:

- `crates/executor/src/argv_compiler.rs`;
- if required, add only crate-private read accessors to
  `crates/executor/src/execution_intent.rs` / `locked_session.rs`.

RED:

- non-durable session is rejected;
- stale durable journal is rejected;
- live phase other than `Approved` is rejected;
- `mutation_may_have_started` is rejected;
- wrong intent session/journal/digest/plan/target binding is rejected;
- mutation-enabled state or missing owner-acceptance invariant is rejected;
- all failures leave the live/durable journal unchanged.

GREEN:

- add `compile_native_argv(session, intent)`;
- reuse the existing exact durable-journal equality gate;
- compare all immutable M1B13 binding fields before translating a step;
- compute no output until validation succeeds.

## Task 3 — Preserve the exact semantic step graph

RED:

- every M1B13 step appears exactly once in compiled output;
- order, ID, dependencies, reversibility and role are identical;
- evidence steps have no native command;
- `RediscoverAndVerify` has no native command;
- all M1B13 verification barriers are copied/bound exactly;
- deterministic identical input produces an identical manifest ID.

GREEN:

- translate to `CompiledStepDisposition::{EvidenceAlreadySatisfied,
  VerificationBarrier, NativeCommand(...)}`;
- fingerprint the complete compiled manifest;
- no synthesized step and no hidden mutation.

## Task 4 — Compile exact LVM argv

RED:

- `ExtendLogicalVolume` resolves exactly one frozen logical-volume UUID;
- exact operand comes from frozen `LvmIdentity.name`;
- argv is exactly:
  `["--extents", "+N", "<exact-lv-path>"]`;
- `-r` and `--resizefs` are absent;
- expected LV size is preserved as a postcondition;
- zero extents, missing UUID match, duplicate match and unsafe/non-/dev path fail closed.

GREEN:

- implement `NativeProgram::Lvextend` mapping only;
- validate the frozen path and size relation;
- do not query the host.

## Task 5 — Compile exact ext4 argv

RED:

- exact frozen filesystem type/device/mount binding is mandatory;
- whole-filesystem preview uses
  `FilesystemSizeChange.expected_filesystem_size_bytes`;
- LVM preview uses `SizeChange.expected_lv_size_bytes`;
- target bytes must be divisible by 512;
- argv is exactly:
  `["<exact-device>", "<sectors>s"]`;
- missing target size, zero/non-growing target, wrong device/type/mount or unsafe path fails closed.

GREEN:

- add only `NativeProgram::Resize2fs`;
- compute 512-byte sector count with checked arithmetic;
- preserve target bytes as a postcondition.

## Task 6 — Compile exact XFS argv

RED:

Whole-filesystem partial growth:

- exact filesystem block size and target bytes must be present;
- target bytes must be divisible by filesystem block size;
- argv is exactly:
  `["-D", "<block-count>", "<exact-mountpoint>"]`.

LVM growth:

- exact mountpoint and frozen final LV bytes are required;
- argv is exactly:
  `["<exact-mountpoint>"]`;
- expected final backing bytes are retained as a verification postcondition.

Reject:

- unsupported filesystem;
- unsafe mountpoint;
- missing/ambiguous filesystem identity/decision binding;
- invalid zero or non-divisible target geometry.

GREEN:

- add only `NativeProgram::XfsGrowfs`;
- no invented XFS block size for LVM plans.

## Task 7 — Prove partition compilation fails closed

RED:

- any `ExtendPartition` in the source intent returns
  `NativeArgvCompilerError::PartitionCompilerNotReady`;
- the compiler returns no partial manifest even if earlier supported commands existed;
- evidence-only `BackupPartitionTableMetadata` remains a non-command evidence disposition.

GREEN:

- explicit typed rejection;
- no sfdisk argv exists anywhere in M1B14 production code.

Do not add a filename partition-number parser.

## Task 8 — Whole-module safety review

Inspect the complete branch, not only the last diff.

Required invariants:

- `MUTATION_ENABLED=false`;
- no `std::process` in `argv_compiler.rs`;
- no `Command::new`;
- no `sh -c`, `bash -c` or shell strings;
- no arbitrary program String;
- no `Deserialize` on compiled command artifacts;
- no journal transition;
- no `ExecutionStarted` path;
- no partial compile result on any failure;
- no partition mutation argv;
- exact supported program enum is minimal.

Add a focused source/safety contract test if a static invariant is otherwise easy to regress.

## Task 9 — Documentation and continuity

Update on the feature branch:

- `README.md`;
- `docs/HANDOFF.md`;
- `docs/M1B_HANDOFF.md`;
- `docs/ROADMAP.md`;
- `docs/SAFETY.md`.

Record:

- M1B13 merged as PR #27;
- merged baseline `1ee443f1482733480a6700e7b94a610f1b3ce014`;
- M1B14 Native compiler scope;
- supported program allowlist;
- partition compilation deliberately blocked;
- mutation remains disabled;
- next gates after M1B14.

## Task 10 — Exact-head acceptance

Before PR merge:

1. run/observe branch RED evidence for each substantive TDD group;
2. exact branch head:
   - rustfmt;
   - Clippy `-D warnings`;
   - full workspace tests;
   - harness safety tests;
   - loop integration;
   - Portable Linux x86_64;
   - Portable Linux aarch64;
3. inspect PR patch for process execution, shell use, mutation flag changes and journal transitions;
4. update PR body with exact head and exact CI/Portable run numbers;
5. squash merge only with `expected_head_sha`;
6. verify resulting `master` merge commit.

## Exit state

M1B14 finishes with reviewed native argv **data**, not execution.

The project must still require separate milestones for:

- authoritative partition-number + partition-table/kernel-refresh contract;
- PV resize compilation/execution policy;
- privileged helper protocol;
- per-mutation fresh verification implementation;
- durable `Approved -> Executing` transition before a future mutation;
- crash/interruption recovery;
- disposable write matrix;
- fresh explicit owner acceptance for mutation-capable rollout.

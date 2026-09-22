# M1B14 Native semantic-to-argv compiler design

Date: 2026-09-22  
Baseline master: `1ee443f1482733480a6700e7b94a610f1b3ce014`  
Working branch: `feature/m1b14-native-argv-compiler`

## Goal

M1B14 converts the exact M1B13 frozen semantic intent into a deterministic, typed,
**non-executable** native command manifest.

This milestone narrows the future execution surface. It does not execute a program, does not
advance the durable journal, does not add an `apply` command, and does not enable mutation.

The design remains Linux-portable by using capability-selected native Linux storage utilities
with direct argv. Distribution names, package managers and shell command strings are outside the
execution model.

## Non-goals

M1B14 does **not**:

- spawn `sfdisk`, LVM, ext4, XFS or any other process;
- call a shell;
- add a privileged helper;
- advance `Approved -> Executing`;
- set `mutation_may_have_started`;
- enable `MUTATION_ENABLED`;
- rerun metadata backups already represented by M1B13 pre-execution evidence;
- implement partition-table mutation;
- implement PV growth;
- implement recovery execution;
- infer a partition number from a Linux device filename;
- accept arbitrary executable names, arbitrary environment variables or arbitrary command hooks.

## Input boundary

The compiler takes:

1. the current `LockedExecutionSession`;
2. the exact `FrozenExecutionIntentManifest` produced for that session.

Compilation is accepted only while all of these still hold:

- the live journal is exactly `Approved`;
- `mutation_may_have_started == false`;
- `MUTATION_ENABLED == false`;
- the session still has a durable journal store;
- the durable journal exactly equals the live journal;
- intent `locked_session_id`, `approved_journal_id`, `approved_journal_digest`,
  `plan_id` and `target_manifest_digest` still bind to the current session/handoff;
- intent status is `FrozenNonExecutable`;
- intent mutation flag is false;
- owner acceptance remains required;
- intent blockers are empty.

No compiler failure may change the journal.

## Output model

The output is a private-field, Serialize-only `CompiledCommandManifest`.

Required top-level state:

- `status = CompiledNonExecutable`;
- `mutation_enabled = false`;
- `owner_acceptance_required = true`;
- exact source intent manifest ID;
- exact approved journal/session/plan/target binding;
- a deterministic manifest fingerprint;
- one compiled step for every source intent step, in source order;
- no `Deserialize` implementation.

Each compiled step preserves:

- `plan_step_id`;
- exact dependency list;
- reversibility;
- source intent role;
- a closed disposition.

The disposition is one of:

- `EvidenceAlreadySatisfied` for M1B13 backup/pre-execution evidence;
- `VerificationBarrier` for read-only verification semantics;
- `NativeCommand(NativeCommandSpec)` only for reviewed supported mutation candidates.

No source step may be omitted, reordered or duplicated.

## Closed native program allowlist

M1B14 exposes a closed enum, not a string program name:

```rust
pub enum NativeProgram {
    Lvextend,
    Resize2fs,
    XfsGrowfs,
}
```

There is no generic `Other(String)`, no shell program and no externally supplied executable
path.

A future executor may map these enum variants to reviewed binaries only in a later milestone.
M1B14 itself never resolves or opens an executable.

## NativeCommandSpec

A command spec contains data only:

- `program: NativeProgram`;
- `args: Vec<String>`;
- expected storage effect classification;
- expected postcondition needed by the future verification barrier.

It does not contain:

- shell text;
- shell redirection;
- environment overrides;
- cwd;
- executable path;
- file descriptor inheritance policy;
- timeout/retry semantics.

All arguments derived from frozen topology are conservatively validated as absolute paths with no
control characters where a device or mount path is expected.

## LVM compilation

`ExtendLogicalVolume` is supported when the frozen target identity contains exactly one logical
volume with the intent's LV UUID.

The exact LV operand comes from the frozen `LvmIdentity.name`. Current identity capture stores
the canonical LV path there; the compiler must not reconstruct a path from a VG/LV name.

Command shape:

```text
lvextend --extents +<additional_extents> <exact-lv-path>
```

Rules:

- no `-r` / `--resizefs`; filesystem growth remains a separate approved intent step;
- `additional_extents > 0`;
- the operand must be an absolute `/dev/...` path with no control characters;
- the frozen LV's current size must be strictly below `expected_lv_size_bytes`;
- output records `expected_lv_size_bytes` as a postcondition.

## ext4 compilation

`GrowFilesystem { fs_type: "ext4" }` compiles only when the frozen filesystem identity and
filesystem decision identify one exact ext4 device and mountpoint.

Program:

```text
resize2fs <exact-device> <target-size-in-512-byte-sectors>s
```

The target size is derived without ambient discovery:

- if the approved plan has `FilesystemSizeChange`, use its exact
  `expected_filesystem_size_bytes`;
- otherwise, when the same approved plan has `SizeChange` for an LV, use its exact
  `expected_lv_size_bytes`;
- otherwise compilation fails closed.

The target byte size must be non-zero, divisible by 512 and larger than the frozen observed
filesystem size when that size is available.

This makes partial whole-device growth exact and also binds LVM/ext4 growth to the exact final LV
size.

## XFS compilation

`GrowFilesystem { fs_type: "xfs" }` requires the exact frozen mountpoint and device.

For a whole-device filesystem plan with `FilesystemSizeChange`, compile:

```text
xfs_growfs -D <expected-filesystem-block-count> <exact-mountpoint>
```

where the block count is exactly
`expected_filesystem_size_bytes / filesystem_block_size_bytes` and divisibility is checked.

For an LVM plan, the current M1A LVM preview freezes the exact final LV size but does not freeze an
XFS filesystem block size. M1B14 therefore compiles only the documented grow-to-current-backing
form:

```text
xfs_growfs <exact-mountpoint>
```

and binds `expected_lv_size_bytes` as the required postcondition for the future verification
barrier.

No XFS size is invented.

## Partition mutation is intentionally blocked in M1B14

`ExtendPartition` remains semantically valid M1B13 intent but is not command-compilable yet.

Reason: safe `sfdisk -N` compilation needs an exact partition number and a reviewed kernel
partition-table refresh sequence. Current M1B13 identity freezes exact partition/disk geometry but
does not freeze an explicit partition number. Deriving the number from names such as:

- `/dev/sda3`;
- `/dev/nvme0n1p3`;
- `/dev/mmcblk0p3`;
- device-mapper or unusual aliases

would add an unreviewed filename parser at the mutation boundary.

Therefore any manifest containing `ExtendPartition` fails atomically with a stable
`PartitionCompilerNotReady` error. No partial command manifest is returned.

A later milestone may add an authoritative partition number to discovery/identity, freeze it, and
define the required `sfdisk` + kernel reread/udev convergence contract under disposable write
tests.

## Pre-execution and verification steps

M1B13 backup steps are proof that backup evidence was captured and revalidated before approval.
M1B14 must not turn them back into commands.

Thus:

- `RevalidateSnapshot` -> `EvidenceAlreadySatisfied`;
- `BackupLvmMetadata` -> `EvidenceAlreadySatisfied`;
- `BackupPartitionTableMetadata` -> `EvidenceAlreadySatisfied`;
- `RediscoverAndVerify` -> `VerificationBarrier`.

The existing M1B13 per-mutation verification barrier list is also copied/bound into the compiled
manifest; it is not implemented as process execution here.

## Determinism and binding

The compiled manifest ID is a SHA-256 structural fingerprint over:

- schema version;
- source intent manifest ID;
- approved journal ID/digest;
- locked session ID;
- plan ID;
- target manifest digest;
- status/flags;
- compiled steps;
- verification barriers.

Identical exact approved inputs produce the same compiled manifest.

## Fail-closed error surface

At minimum:

- `SessionNotApproved`;
- `MutationMayHaveStarted`;
- `MutationEnabled`;
- `DurableJournalRequired`;
- `DurableJournalMismatch`;
- `IntentBindingMismatch`;
- `IntentStatusMismatch`;
- `OwnerAcceptanceInvariant`;
- `IntentBlocked`;
- `PartitionCompilerNotReady`;
- `LogicalVolumeIdentityMissing`;
- `LogicalVolumeIdentityAmbiguous`;
- `UnsafeDevicePath`;
- `UnsafeMountpoint`;
- `FilesystemIdentityMismatch`;
- `UnsupportedFilesystem`;
- `ExactFilesystemTargetSizeUnavailable`;
- `InvalidFilesystemTargetSize`;
- `Serialization`.

No error returns a partial manifest.

## TDD acceptance contract

Implementation begins with RED tests.

Positive contract:

1. exact current M1B13 session/intent compiles deterministically;
2. source step IDs, dependencies, order and reversibility are preserved exactly once;
3. LVM command uses only `NativeProgram::Lvextend`, exact frozen LV path and relative extents;
4. `lvextend` never receives `-r` or `--resizefs`;
5. ext4 command uses only `NativeProgram::Resize2fs`, exact frozen device and exact size;
6. XFS command uses only `NativeProgram::XfsGrowfs`, exact mountpoint and exact `-D` only when
   an approved filesystem block size exists;
7. evidence and verification source steps produce no executable command;
8. compiled status remains non-executable, mutation disabled and owner acceptance required;
9. live and durable journals remain exactly unchanged.

Fail-closed contract:

1. non-durable or stale durable journal;
2. journal not exactly `Approved`;
3. `mutation_may_have_started`;
4. wrong session/journal/plan/target binding;
5. blocked or mutation-enabled intent;
6. `ExtendPartition` anywhere in the source intent;
7. missing or duplicate LV UUID identity;
8. unsafe LV/device/mount path;
9. filesystem decision/type/device/mount mismatch;
10. unsupported filesystem type;
11. missing exact ext4 target size;
12. size overflow/non-divisibility;
13. source step count/order/dependency mismatch;
14. no arbitrary executable or shell can be represented.

## Safety invariant

M1B14 is complete only if the exact PR head proves:

- `MUTATION_ENABLED=false`;
- no `std::process`;
- no `Command::new`;
- no shell execution;
- no privileged helper;
- no journal transition;
- no storage write is executed;
- CI and Portable Linux are green.

The next milestone after M1B14 must still not jump directly to production mutation. Privileged
execution protocol, per-layer fresh verification, crash/recovery semantics, disposable write
matrix and fresh explicit owner acceptance remain separate gates.

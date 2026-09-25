# M1B pre-executor handoff

M1B is the safety foundation between read-only planning and any future mutation-capable
executor. It remains fail-closed and capability/topology driven.

Verified master baseline after PR #82 on 2026-09-24:

`d71acde46da9e1dda21ab161f00f82f8cd349f50`

That master contains M1B0 through exact disposable `PV -> LV -> filesystem` execution plus durable replay/recovery hardening. The executor remains feature-gated to harness-owned loop fixtures and production `MUTATION_ENABLED=false` remains unchanged. PR #83 is the current candidate for exact existing-partition `partition -> PV -> LV -> filesystem` execution.

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

Merged as PR #27.

M1B13 freezes the exact approved `PlanStep` graph into typed semantic intent plus mandatory read-only verification barriers. It adds no journal transition and keeps `MUTATION_ENABLED=false`.

### M1B14 — typed native pre-executor manifest

Complete. M1B14 adds a typed native operation allowlist, exact non-executable payloads, native step/barrier compilation, direct frozen-manifest binding, dependency-graph validation, role/operation validation, mutation-layer ordering, deterministic SHA-256 identity and immutable validated-manifest binding.

### M1B15 — exact chained LVM preview

Complete at the verified master baseline above. M1B15 adds `ResizePhysicalVolume { pv_uuid, expected_pv_size_bytes }` across planner/frozen/native layers and promotes previously advisory single-PV underlying growth routes into exact non-executable previews. Proven routes now include `PV -> LV -> filesystem` when the PV backing device is already larger, and `partition -> PV -> LV -> filesystem` when adjacent partition capacity is authoritatively verified. `--max` selects the maximum proven route. Loop integration verifies the combined preview contract without performing the resize.

### M1B16 — disposable-only executor

PR #79 established the feature-gated `ExtendLogicalVolume -> GrowFilesystem` executor. PR #80 then added create-without-replacement journal start, blocked blind replay, and proved forced pre-spawn failure enters durable `RecoveryRequired` without changing LV/filesystem/sentinel state.

PR #82, now merged at the master baseline above, executes `ResizePhysicalVolume -> ExtendLogicalVolume -> GrowFilesystem` when the backing partition/device is already larger than the PV. The PV command is bound to exact PV UUID/path and observed PE start; fresh discovery verifies exact PV size before LV mutation, exact LV size before filesystem mutation, and final filesystem growth afterward.

PR #83 extends the candidate disposable executor to an existing size-growable GPT or DOS/MBR partition. It emits exact non-shell `sfdisk -N` stdin with the same start sector and an exact larger sector count, then performs exact `partx --update --nr` kernel refresh before rediscovery. Verification requires table identity, partition start, type/UUID/name/attrs/boot metadata to remain unchanged, then continues through PE-start-aware PV, LV and filesystem boundaries. CI #790 proves GPT and DOS/MBR full chains in 3/3 repetitions; Portable Linux #669 succeeds on x86_64 and aarch64. Production `MUTATION_ENABLED=false` remains unchanged.

PR #85 hardens the post-write/pre-kernel-refresh recovery boundary. The owned-loop fault drill lets the exact approved `sfdisk` write complete, deliberately blocks `partx`, requires durable `RecoveryRequired`, retains journal/backup evidence, proves PV/VG/LV/filesystem state and sentinel data unchanged, blocks a second executor launch, then explicitly reconciles only the owned test partition before cleanup. GPT and DOS/MBR are both covered.

The next recovery boundary applies the same model after a real `pvresize`: the PV reaches the exact approved new size and is freshly rediscovered, `lvextend` is deliberately blocked before spawn, the durable journal must enter `RecoveryRequired`, the resized PV identity must reconcile exactly, LV/filesystem/sentinel state must remain unchanged, and blind replay must stay blocked until evidence is explicitly cleared in the owned fixture.

The following boundary applies the same fail-closed model after a real `lvextend`: the LV reaches the exact approved new size and its verified continuation is durably recorded, filesystem growth is deliberately blocked before spawn, the journal must enter `RecoveryRequired`, the resized LV must reconcile exactly, filesystem capacity and sentinel data must remain unchanged, and replay must stay blocked until explicit owned-fixture reconciliation.

The final ext4 inter-layer recovery drill executes the real `resize2fs` and injects failure before terminal verification. The durable journal must enter `RecoveryRequired` while retaining the prior verified LV boundary without a terminal step, fresh reconciliation must prove both the exact resized LV and an increased filesystem capacity, sentinel data must remain intact, and a new execution must remain blocked until owned-fixture evidence is explicitly cleared.

Offline ext4 is now executable only in the disposable owned-loop profile and remains separate from the mounted online path. The planner emits `GrowFilesystem { mountpoint: None }` only for exact unmounted ext4; XFS still requires a unique read-write mount. Preconditions promote to `ReadyOfflineGrow` only after an exact session-bound `e2fsck -f -n <device>` no-modify receipt on a freshly unmounted target. Frozen/native manifests preserve the absent mount identity, `resize2fs` receives only the verified device, the post-`lvextend` boundary requires the exact expected LV/backing size, terminal verification requires the filesystem to remain unmounted, and integration remounts only after completion to prove capacity growth plus sentinel preservation. CI acceptance requires 3/3 `EXT4_OFFLINE_EXECUTOR_OK=e2fsck-no-modify-lv-resize2fs`.

XFS online growth now uses the portable executor gate: exact fresh mounted read-write identity plus successful `xfs_growfs -n` evidence promotes directly to `ReadyOnlineGrow`. `xfs_scrub -n -k` is no longer mandatory because Ubuntu and other otherwise-supported kernels can omit the online metadata scrub facility. The mutation path remains exact non-shell `xfs_growfs -d <mountpoint>` after the verified LV boundary, followed by terminal rediscovery, filesystem-capacity increase and sentinel preservation. The owned-loop acceptance marker is `XFS_ONLINE_EXECUTOR_OK=xfs-growfs-mounted-rw`.

The current multi-target hardening layer keeps selection explicit after those recovery gates. Two mounted ext4 LVs in one disposable VG are independently discoverable and plannable; executing growth against one must preserve the sibling LV UUID, size, filesystem capacity and sentinel bytes. A separate two-partition fixture proves both mounted filesystems remain in the target catalog even when the non-tail partition is blocked by its neighbor while the tail partition stays growable.

Blocked target visibility is now structured as well: every catalog entry carries the planner's blocker `code` and `message` when blocked/advisory. The JSON catalog can therefore drive TUI/GUI explanations without parsing prose, while the text CLI renders the same exact evidence. Integration checks the non-tail partition catalog blocker against the blocker returned by its direct `plan extend`.

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

M1B17 privileged-helper protocol now defines the first production-side transport contract without enabling writes. One request is bound to the exact durable execution ID, source/native/fresh-identity digests and one validated native mutation step. The protocol is versioned and self-digested, rejects foreign bindings, non-mutation steps, unsafe partition geometry/device paths, unsupported filesystem modes and any tampering. It deliberately carries semantic typed operations rather than arbitrary shell text or argv. `MUTATION_ENABLED=false` remains unchanged; no privileged process is spawned yet.

M1B18 adds the first feature-gated helper process boundary around that contract. `lsm-privileged-helper-protocol` accepts one bounded JSON request on stdin, decodes and round-trips the typed wire shape, revalidates the digest and operation safety rules, and emits only a validation receipt with `mutation_enabled=false` and `execution_started=false`. It has no storage-tool spawning path and cannot advance the journal. CI separately compiles/clippy-checks this binary. Actual privileged argv compilation, root authorization and writes remain later gates.

M1B19 upgrades that boundary to protocol schema v2 and binds each request to the exact target selector and resolved device in addition to the existing execution/native/fresh-identity digests. The helper now performs its own read-only discovery, captures the live target identity, and requires target, resolved device and manifest digest to match exactly before returning `identity_revalidated`. Any drift fails closed. The helper still does not compile mutation argv, spawn storage tools, advance the journal or enable production mutation.

M1B20 adds exact command compilation after helper-side live identity revalidation. One authorized mutation request compiles to one typed non-shell command spec: exact `sfdisk` plus `partx` refresh geometry, exact `pvresize`, exact `lvextend`, `resize2fs`, or mounted `xfs_growfs`. Compilation rechecks live partition/LVM/filesystem/mount identity and emits a deterministic SHA-256 command digest. The helper response remains validation-only: `mutation_enabled=false`, `execution_started=false`; no storage tool is spawned and the durable journal is not advanced.

M1B21 binds the compiled command to trusted executable provenance before any future spawn. The helper searches only fixed system directories, requires root-owned executable files and root-owned/non-writable directory chains, permits only root-owned symlink aliases to a root-owned canonical executable, rejects multiple distinct executable identities for the same program, and records canonical path, device/inode, uid/mode, size and SHA-256 for both the primary tool and any `partx` kernel-refresh tool. A deterministic tool-resolution digest also binds the exact M1B20 command digest. The response remains non-mutating: no command is spawned and the journal is unchanged.

M1B22 freezes the helper-side pre-spawn state into a deterministic `PreparedPrivilegedInvocation`. The prepared receipt binds the exact request/execution/step, helper-side live identity digest, M1B20 command digest and M1B21 trusted-tool-resolution digest. Preparation revalidates protocol/live identity and rejects command-step, command/tool, primary-program or kernel-refresh mismatches. The helper returns `status=invocation_prepared` while `mutation_enabled=false` and `execution_started=false`; no storage command is spawned and the durable journal remains unchanged.\n\nOwner acceptance for continuing the production-gate rollout was recorded on 2026-09-25. That acceptance removes the conversational approval stop for this project, but it does not weaken any technical safety invariant: production mutation remains disabled until the remaining helper/runtime/verification gates are implemented and tested.

M1B23 closes the durable pre-spawn crash window. The orchestrator may persist `Approved -> Executing` only while the host lock is still held and only when the exact `ExecutionStartBinding`, first-step helper request and tamper-evident M1B22 prepared invocation all agree on execution/source/native/fresh-identity IDs. The durable transition is written before any future process creation and conservatively sets `mutation_may_have_started=true`; a deterministic start receipt binds the resulting executing-journal digest. This gate still spawns no storage tool, so production writes remain disabled while the journal/lock semantics are now wired to the production-side path.\n\nBefore any production path can enter `Executing`, separately review:

M1B24 closes the post-journal/pre-spawn provenance window. After `Approved -> Executing` has been persisted, the executor re-resolves the exact M1B20 command against fixed trusted system directories and re-hashes the selected primary and optional kernel-refresh executables. The fresh command digest and tool-resolution digest must exactly match the M1B22 prepared invocation; any executable replacement, inode/path/provenance drift, command mutation or prepared/start-receipt mismatch fails closed. A deterministic spawn-authorization receipt binds the execution-start receipt, prepared invocation, step, command and tool digests. This gate deliberately still performs no process creation.\n\n- explicit owner acceptance for mutation-capable rollout;
- privileged-helper architecture;
- minimal command allowlist;
- exact executable argv specs;
- post-each-layer rediscovery;
- per-layer verification;
- crash/interruption semantics;
- recovery UX;
- disposable integration matrix.

M1B25 removes the remaining path-replacement window between provenance verification and a future exec. After M1B24 authorization, the helper re-resolves the trusted tool set, opens each canonical executable with `O_NOFOLLOW|O_CLOEXEC`, and verifies the opened file object itself against the trusted device/inode/uid/mode/size/SHA-256 identity. The resulting `PinnedPrivilegedTools` retains the open file descriptors plus a tamper-evident pin receipt; replacing `/usr/sbin/lvextend` or another path after pinning cannot redirect the already-open executable object. This gate still performs no process creation and leaves production mutation disabled.\n\nBackups and approval are defense-in-depth. Neither permits bypassing topology proof.


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

Filesystem growth intent is additionally bound to the exact frozen filesystem decision target
and device, not only its filesystem type and mountpoint. CI #547 and #549 are the retained RED
proofs for the device- and target-drift guards. Final completion evidence must be read live from
the exact PR #27 head.

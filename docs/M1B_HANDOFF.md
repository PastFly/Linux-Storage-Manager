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

M1B26 freezes the exact descriptor launch surface without spawning. The pinned primary and optional refresh files must be native ELF images; scripts fail closed so the future `fexecve` path can keep `O_CLOEXEC` without interpreter-FD leakage. The launch receipt binds the M1B25 pin, exact argv, optional stdin length/SHA-256, fixed non-inherited `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, primary/refresh ELF identities and `process_spawned=false`. Embedded NULs are rejected before any future C argv construction.\n\n
## M1B13 frozen execution intent contract

M1B27 seals the complete pre-spawn authorization chain into one deterministic launch permit. The durable execution-start receipt, M1B24 spawn authorization and M1B26 descriptor launch receipt must agree on execution ID, start receipt, authorization ID, first mutation step and command digest. Tampering at any layer fails closed. The permit explicitly retains `mutation_enabled=false` and `process_spawned=false`; it is the final non-executing authorization object before a future descriptor-based spawn primitive.\n\nM1B13 freezes the exact M1B12-approved plan into `FrozenExecutionIntentManifest`.

M1B28 implements the descriptor execution primitive itself using `fork` + `fexecve` on an already-open executable file descriptor, fixed `PATH`/`LC_ALL` and exact argv. Unit tests execute only benign `/usr/bin/true` and `/usr/bin/false` descriptors and verify exit-status handling plus pre-fork argv/program mismatch rejection. The production wrapper revalidates the M1B27 permit, M1B26 launch spec and M1B25 pinned descriptor chain, but deliberately returns `ProductionMutationDisabled` while `MUTATION_ENABLED=false`; no storage tool can yet be spawned by production code.

M1B29 extends the descriptor runtime contract to exact stdin and ordered refresh semantics. Commands without stdin receive `/dev/null`; an exact payload such as the frozen `sfdisk` line is delivered through a close-on-exec pipe and remains bound to the M1B26 length/SHA-256 receipt. The optional kernel-refresh stage must match program/argv exactly and may run only after a zero primary exit; a nonzero primary result suppresses refresh. Benign unit tests prove descriptor stdin delivery and EOF behavior. The production wrapper still stops at `ProductionMutationDisabled`, so these semantics are implemented without enabling storage writes.

M1B30 isolates and bounds child diagnostics before production enablement. Each descriptor child gets dedicated close-on-exec stdout/stderr pipes; the parent drains both concurrently so a verbose tool cannot deadlock on a full pipe, retains at most 64 KiB per stream, and records truncation flags while discarding overflow. Unit tests prove stdout capture and failed-child stderr capture with benign ELF utilities. No production storage process can cross the existing `ProductionMutationDisabled` gate yet.

M1B31 defines the first post-spawn runtime receipt without yet enabling production storage execution. A child exit code of zero is never interpreted as completion: it yields `RediscoveryRequired` only when the primary and any required kernel-refresh stage both exited successfully. Any nonzero primary/refresh or a missing expected refresh yields `RecoveryRequired`, because the durable journal already assumes mutation may have started. The receipt binds execution/permit/launch/step/command IDs plus SHA-256/truncation evidence for bounded stdout/stderr, and remains a pure classification layer until production rediscovery/per-layer verification is wired.\n\nThe manifest binds approval ID, approved journal ID/digest, plan ID, evidence bundle ID, target
manifest digest and locked-session ID. Every source `PlanStep` is represented exactly once,
dependency lists are preserved, and malformed/cyclic graphs fail closed.

M1B32 adds exact live per-layer post-state verification after a `RediscoveryRequired` process receipt. The fresh target must preserve target/resolved-device binding; partition growth must retain start/table/record identity while reaching the exact approved sector count; PV/LV growth resolves the exact UUID and expected byte size; filesystem growth preserves filesystem UUID/type/version and mount identity while proving observed capacity increased without exceeding backing capacity. The resulting verification receipt binds before/fresh identity digests and process/request IDs. This layer is read-only and journal-neutral; production mutation remains disabled until the verified receipt is wired into durable continuation/recovery transitions.

M1B33 binds those runtime and live-verification receipts to the durable journal. The next privileged request must use the exact latest verified identity boundary, preventing later steps from reusing the original pre-mutation digest. A recovery-required process is durably forced to RecoveryRequired; a successful process is first persisted as Verifying and can return to Executing only for the exact adjacent mutation step, or reach Completed only at the final verified step. Any receipt, execution, sequence, or identity-chain mismatch fails closed and is reconciled as recovery-required. Production MUTATION_ENABLED remains false.

M1B34 extends that verified continuation boundary through the existing pre-spawn chain. A later prepared invocation is bound to the exact durable verified boundary ID, current executing-journal digest, next plan-step ID and rolling live-identity digest. Spawn authorization re-resolves trusted tool provenance for that continuation receipt, and the descriptor launch permit accepts the continuation receipt without weakening the existing FD-pinning or launch-integrity checks. The continuation-start receipt is journal-read-only: it proves the current durable Executing boundary but does not create a second execution-start transition. This closes the first-step-only pre-spawn gap while production mutation remains disabled.

M1B35 introduces the first explicit production-activation contract without enabling storage writes. Activation requires a separate `production-mutation-activation` compile feature and is deliberately limited to an already-created, verified single-PV LVM chain using existing VG free extents: exactly `ExtendLogicalVolume -> GrowFilesystem` for ext4 or XFS. Partition and PV mutation are excluded from this first production scope. The readiness object reports compile/profile/execution/identity blockers; the sealed activation intent binds the exact execution/native-manifest/identity/target and still records `execution_enabled=false`, so a later reviewed gate is required before `MUTATION_ENABLED` can change.

M1B36 adds an independent runtime-consent boundary on top of the M1B35 activation intent. A future production build must read one fixed `/etc/linux-storage-manager/production-mutation-consent.json` document through `O_NOFOLLOW|O_CLOEXEC`; the parent must be root-owned and not group/world-writable, while the file must be a one-link root-owned regular file with mode 0600. Its exact activation ID, execution ID, target, resolved device and destructive-action phrase are validated and bound together with file device/inode/mode/size/SHA-256 into a receipt. The consent receipt still records `execution_enabled=false`, so compile-time activation plus filesystem consent are necessary but not sufficient to spawn a storage command.

M1B37 seals the M1B35 activation intent, M1B36 root-consent receipt and one exact M1B27/M1B34 descriptor launch permit into a final non-spawning production execution permit. The three layers must agree on execution ID, activation ID, target/device and the launch must be one of the two explicitly activated mutation steps. Upstream objects that already claim execution/mutation or process spawn are rejected. The new feature depends on the consent feature, but the resulting permit still records `mutation_enabled=false` and `process_spawned=false`; descriptor execution remains blocked until a separately reviewed crossing gate consumes this exact permit.

M1B38 introduces the first actual production descriptor-exec crossing, but only behind the separate `production-mutation-execution` compile feature. The gate requires the current durable journal to still authorize the exact step, consumes the rolling identity boundary for continuation steps, re-reads and validates the fixed root-owned consent file immediately before spawn, requires the sealed M1B37 production execution permit to match the activation/request/launch/command/pinned chain, and then calls the crate-private descriptor runner. Any authorization drift or descriptor failure durably enters RecoveryRequired. A successful child result is still not completion and must flow through M1B31/M1B32/M1B33 classification, rediscovery, verification and durable continuation. Default builds remain unable to cross this boundary.

M1B39 narrows the runtime-consent TOCTOU window further. After M1B36 verifies the fixed root-owned consent document, the executor reopens that exact file with `O_NOFOLLOW|O_CLOEXEC`, requires its device/inode/uid/mode/link-count/size/SHA-256 identity to match the verified receipt, and retains the open descriptor. Immediately before the M1B38 descriptor crossing it verifies that the current fixed pathname still produces the same consent receipt and independently re-hashes/rechecks the pinned file object. Path replacement/removal, metadata drift, or in-place content changes therefore fail closed into recovery rather than allowing a stale consent receipt to authorize spawn.

M1B40 removes raw child exit status from the public production API. The M1B38/M1B39 crossing is crate-private; the exported production call immediately classifies its descriptor sequence through M1B31 and returns only the tamper-evident `PrivilegedProcessReceipt`. A zero primary/refresh result therefore means only `RediscoveryRequired`, never completion. A `RecoveryRequired` process receipt is durably persisted through M1B33 before return, while any inability to bind the raw outcome to the exact launch permit/launch contract also forces the journal into recovery. Successful rediscovery-required receipts still require M1B32 live verification and M1B33 continuation.

M1B41 closes the successful production mutation boundary synchronously. The classify-only M1B40 call becomes crate-private; the exported production API now requires the exact pre-spawn live identity, executes the descriptor sequence, rediscoveries a fresh full host snapshot, requires the capability inventory to remain identical to the frozen handoff, captures the fresh target identity, proves the exact M1B32 layer transition, and persists the M1B33 verified continuation/completion before returning. Rediscovery, capability, identity or verification failure durably enters RecoveryRequired. The `production-mutation-execution` feature now explicitly carries the discovery dependency needed for this mandatory post-state gate.

M1B42 hardens that synchronous close against bounded Linux rediscovery lag. After a successful production process receipt, the executor retries full snapshot/target capture and only the expected partition/PV/LV/filesystem post-state mismatches for up to 20 attempts at 50 ms intervals. Capability drift, target-identity drift, receipt/binding failures and unsupported operations remain immediate fail-closed conditions. Exhausting the bounded convergence window durably enters RecoveryRequired instead of silently accepting stale state.

M1B43 collapses the remaining pre-spawn integration surface into typed first-step and continuation builders. The first builder resolves request/command/tool provenance before the durable Executing transition, then binds authorization, pinned executable descriptors, descriptor launch, launch permit and production permit; any failure after Executing is persisted as RecoveryRequired. The continuation builder consumes only the latest M1B33 verified boundary and applies the same fail-closed construction for the exact filesystem step. Callers no longer need to manually assemble the production descriptor chain.

M1B44 proves the narrow production path end to end on a harness-owned Linux loop fixture. The test creates a single-PV LVM ext4 target with existing VG free extents, builds the exact production activation and root-owned runtime consent, prepares the typed first LV step, crosses the real production descriptor-exec gate, requires bounded live rediscovery and durable verified continuation, prepares the filesystem continuation from the rolling identity boundary, and requires terminal Completed with the sentinel preserved. CI runs this only in the disposable root loop matrix and removes the exact temporary consent file afterward.

M1B45 defines the next production scope as a separate non-executing activation contract for an exact single-PV partition-backed chain: `ExtendPartition -> ResizePhysicalVolume -> ExtendLogicalVolume -> GrowFilesystem`. The frozen execution order and dependencies must be exact; fresh identity must still show the authorized partition start/old size/sector size, the exact PV and LV UUIDs below their approved target sizes, one-PV VG topology, and the same ext4/XFS filesystem/mount identity. The sealed chained intent remains `execution_enabled=false` and is a different type from the M1B35 activation intent, so M1B37-M1B44 cannot consume it yet. Production partition/PV execution therefore remains impossible until a later reviewed permit/execution gate explicitly adopts this contract.

M1B46 extends the existing M1B36/M1B39 root-consent boundary to that chained activation without making it executable. The same fixed root-owned one-link mode-0600 consent document is validated against the exact chained activation/execution/target/device binding, and the same opened-file lease model can pin and revalidate the consent object against path replacement, metadata drift or in-place content changes. The receipt format remains shared and still records `execution_enabled=false`; M1B37-M1B44 still cannot consume the chained activation or cross descriptor execution for partition/PV steps.

M1B47 adds a separate compile-time-gated, non-spawning execution-permit type for the chained activation. It binds one exact root-consent receipt and one exact privileged launch permit to the chained activation, allows only the four frozen partition/PV/LV/filesystem mutation step IDs, and retains `mutation_enabled=false` plus `process_spawned=false` in the permit digest. The existing M1B38 descriptor-execution chain accepts only the narrow M1B37 permit type, so merely compiling M1B47 still cannot execute partition or PV mutations.

M1B48 adds the first separately gated descriptor-execution crossing for the exact M1B45/M1B46 chained activation. The chained runtime path accepts only the M1B47 chained permit, revalidates the pinned root-owned chained consent lease immediately before spawn, requires the current durable rolling-identity boundary to authorize the exact step, and binds launch/command digests to one of the four activation step IDs. Raw child exit status is not exposed: the result is immediately classified into the existing tamper-evident process receipt, and recovery outcomes are durably forced to RecoveryRequired. Successful outcomes still stop at rediscovery_required; synchronous live post-state verification for the chained profile remains the next gate.

M1B49 closes each successful chained production mutation synchronously before returning. A zero descriptor exit is treated only as rediscovery_required; the executor performs bounded fresh snapshot/identity convergence, rechecks the frozen capability inventory, applies exact M1B32 partition/PV/LV/filesystem post-state verification, and then persists M1B33 continuation or terminal completion. Only transient discovery and expected layer-state convergence mismatches are retried (20 x 50 ms); target drift, capability drift and receipt/binding failures fail immediately into durable recovery. This gives the chained profile the same no-unverified-success invariant as the narrow production path.

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


M1B50 adds typed chained production preparation on top of the M1B45-M1B49 execution stack. The first builder resolves the exact partition request/command/tool provenance before entering durable Executing, then seals the pinned launch and chained production permit. Continuations never accept a caller-selected step ID: they consume the latest verified durable boundary and admit only the exact PV, LV or filesystem successor. Any failure after the mutation boundary is durably forced to RecoveryRequired. This removes manual low-level pre-spawn wiring from the future chained production E2E harness. M1B50 is restacked on the merged M1B49 master baseline.


M1B51 proves the full chained production path on a root-owned disposable loop fixture. The production loop harness now selects either the existing two-step LV -> filesystem profile or the exact four-step partition -> PV -> LV -> filesystem profile from the frozen mutation graph. The chained fixture forces backing growth beyond current VG free extents, executes every step through the M1B50 typed builders plus M1B49 synchronous live verification, requires durable Completed, verifies partition/PV/LV/filesystem growth and sentinel preservation, removes owned journal/backup evidence and runtime consent, and is invoked by the CI loop matrix.


M1B52 starts the tail-swap migration path without enabling any swap or partition mutation. Discovery reads only the resume-related kernel command-line parameters plus `/sys/power/resume{,_offset}` into a separate boot-policy evidence object, keeping the storage snapshot schema stable. The planner combines that evidence with the existing exact DOS extended/logical active-swap layout proof and an exact fstab binding. Any configured resume target/offset, missing/ambiguous persistent swap entry, or unproven tail layout blocks migration planning. `storagemgr plan swap-migration TARGET [--json]` exposes the result. Swapfile placement/capacity, safe swapoff, fstab rewrite and rollback remain future gates, so the parent migration roadmap item stays incomplete.


M1B53 proves a concrete replacement swapfile destination without creating a file or changing swap state. Read-only `statvfs` evidence is bound to the selected mount, the planner requires currently available bytes at least equal to the exact retiring swap-partition size, a unique read-write ext4 mount, and unambiguous `mkswap`/`swapon`/`swapoff` capabilities. `plan swap-migration TARGET --swapfile-on MOUNT` exposes this readiness and freezes the future ordering: create and activate the replacement first, verify it, then attempt old-partition swapoff, aborting partition changes if swapoff fails. Persistent rewrite and mutation/recovery implementation remain disabled.


M1B54 freezes the replacement-swap path without authorizing execution. The fixed swapfile pathname is inspected with symlink-aware `symlink_metadata`; any pre-existing regular file, symlink, directory or other object blocks the route. The planner rebinds the exact active retiring swap entry, size/usage/priority, exact persistent fstab source/options/dump/pass and the M1B53 destination evidence into a deterministic intent ID. `storagemgr plan swap-migration TARGET --swapfile-on MOUNT --freeze-intent` exposes this non-executable contract. Runtime file creation, `mkswap`, `swapon`, old-partition `swapoff`, fstab mutation and partition removal remain disabled.


M1B55 proves the runtime replacement ordering only on an explicitly owned disposable loop fixture. A separate feature-gated harness verifies loop/backing ownership, an exact logical swap partition, a unique read-write ext4 mount and fixed root-owned `mkswap`/`swapon`/`swapoff` paths. It creates the fixed replacement file with create-new + no-follow semantics, mode 0600 and full `posix_fallocate`, activates it at the retiring swap priority, and requires old/new reported swap capacities to match. CI exercises an injected boundary after replacement activation where both swaps remain active and the partition table is unchanged, then a success path where only the old swap is deactivated and the replacement remains active. The harness contains no partition mutation path and reports `production_enabled=false`. Production binding to M1B54, persistent fstab rewrite and old partition removal remain later gates.


M1B56 introduces a separate production activation contract for the swap-migration path without opening execution. The M1B54 intent now exposes deterministic integrity verification, and the executor admits only the exact preview-ready ext4 profile: absolute target/disk/swap paths, nonzero retiring swap size, bounded used bytes, exact persistent fstab binding, sufficient destination capacity, fixed 0600 swapfile path and no blockers. A dedicated `production-swap-replacement-activation` compile feature is required to seal the activation. The resulting activation is independently digested but always records `execution_enabled=false`; it has no `mkswap`, `swapon`, `swapoff`, fstab-write or partition-removal crossing.


M1B57 adds a dedicated root-owned runtime consent for the M1B56 swap-replacement production activation. The fixed `/etc/linux-storage-manager/production-swap-replacement-consent.json` file must be a one-link root-owned mode-0600 regular file under a non-group/world-writable root-owned directory, opened with `O_NOFOLLOW`. Its canonical JSON binds the exact activation ID, frozen replacement-intent ID, target, retiring swap device and replacement swapfile path plus the exact phrase `I UNDERSTAND THIS WILL REPLACE ACTIVE SWAP`. The returned receipt is integrity-digested and remains `execution_enabled=false`; no swapfile creation, swapon/swapoff, fstab mutation or partition removal is enabled by this layer.


M1B58 seals the M1B56 activation and M1B57 consent receipt into a separate non-spawning production swap execution permit. The permit rebinds the exact frozen replacement-intent ID, target, disk, retiring swap device/size/priority, swapfile path/mode and consent receipt ID. Both upstream objects must pass integrity checks and report execution disabled. The permit itself keeps `mutation_enabled=false` and `process_spawned=false` in its digest. No process launch or storage mutation is reachable from this feature; the later runtime crossing remains separately gated.


M1B59 pins the M1B57 swap consent by retaining the exact opened file descriptor after verification and revalidating both the live fixed pathname and the still-open file immediately before a later runtime crossing. Device/inode/uid/mode/link-count/size/content hash must remain identical; pathname replacement, in-place edits, growth/truncation or metadata drift fail closed. This closes the consent TOCTOU gap but does not enable swapfile creation, mkswap, swapon/swapoff, persistent-config writes or partition removal. M1B59 is based directly on the merged M1B58 master baseline.


M1B60 adds the final fresh read-only runtime preflight before any production swap process crossing. It revalidates the pinned M1B59 consent lease against the M1B58 non-spawning permit, re-reads hibernation/resume state, active retiring-swap size/priority, exact fstab entry, RW ext4 destination, live capacity and swapfile-path vacancy, then resolves root-owned non-writable trusted identities for mkswap/swapon/swapoff. The resulting receipt is independently digested and remains mutation_enabled=false/process_spawned=false. No swapfile creation, mkswap, swapon, swapoff, fstab edit or partition mutation is enabled.


M1B61 pins the M1B60 trusted swap runtime executables by open descriptor without spawning them. Each canonical mkswap/swapon/swapoff file is opened O_NOFOLLOW/O_CLOEXEC and must still match the frozen device/inode/uid/mode/size/content hash; in-place edits and pathname replacement fail closed. The descriptors are held privately only to stabilize the future runtime crossing. No swapfile creation, process execution, swap-state change, persistent-config edit or partition mutation occurs.


M1B62 freezes the exact future swap runtime descriptor launch without crossing it. The already-open M1B61 mkswap/swapon/swapoff descriptors are revalidated again against the M1B60 trusted device/inode/uid/mode/size/SHA-256 identities immediately before use, closing in-place modification between pin and launch construction. The launch contract accepts native ELF descriptors only, fixes PATH/LC_ALL, freezes exact argv for mkswap --force, swapon --priority and swapoff, binds create-new/no-follow/full-allocation swapfile semantics, and requires explicit dual-active verification before swapoff. The resulting launch remains mutation_enabled=false, process_spawned=false and swapfile_created=false. The production runtime crossing itself remains the next separately gated layer.


M1B63 adds the durable state machine that must exist before any future production swap runtime crossing. A deterministic journal binds the exact M1B56 activation, M1B58 permit, M1B60 preflight, M1B62 launch and frozen replacement intent. The record is persisted as a mode-0600 JSON file beneath /var/lib/linux-storage-manager/swap-runtime using create-new/rename plus file and directory fsync. Every mutation-capable action has a durable intent-before-mutation phase: Prepared -> CreatingSwapfile -> SwapfileCreated -> FormattingReplacement -> ReplacementFormatted -> ActivatingReplacement -> ReplacementActive -> DeactivatingOldSwap -> OldSwapDeactivated -> UpdatingPersistentConfig -> PersistentConfigUpdated -> RemovingPartitions -> PartitionsRemoved -> Completed. RecoveryRequired is available from every started/mutated phase, so a crash after a syscall but before post-state verification cannot leave the journal claiming that mutation never began. Mutation, persistent-config and partition-table risk flags are derived from the durable event chain and cannot be cleared by later transitions. M1B63 still performs no swapfile creation, process spawn, fstab write or partition mutation.


M1B64 crosses the production swap runtime boundary only through the runtime replacement stage. The feature-gated executor requires root plus a held HostStorageLock, the exact persisted M1B63 Prepared journal, revalidated M1B59 consent and revalidated M1B61 executable descriptors. Before each mutation-capable action it fsync-persists the corresponding M1B63 started phase. It creates the fixed swapfile with O_NOFOLLOW/create-new, exact 0600 mode, full posix_fallocate and parent-directory fsync; executes the pinned mkswap descriptor and verifies the on-disk SWAPSPACE signature; executes pinned swapon and requires both the retiring partition and replacement file to be active at the frozen priority; only then executes pinned swapoff and verifies the old swap is absent while the replacement remains active. Any runtime ambiguity after crossing starts is forced into durable RecoveryRequired. The executor stops at OldSwapDeactivated: no fstab edit, persistent-config transition, partition-table mutation or journal completion is performed by M1B64.


M1B65 atomically crosses the persistent-config boundary but still performs no partition-table mutation. It requires a held HostStorageLock, the exact M1B64 execution receipt, fresh runtime proof that the old swap is absent and the replacement remains active at the frozen priority/size, and a revalidated pinned production swap consent. The current root-owned, non-writable, single-link /etc/fstab is read via O_NOFOLLOW and the exact retiring swap entry must occur once. Before the journal enters UpdatingPersistentConfig, the complete original fstab bytes are stored as a deterministic 0600 fsynced recovery backup beside the M1B63 journal. The replacement is written to a same-directory create-new temp file, fsynced, and the original fstab inode/metadata is rechecked immediately before atomic rename; the /etc directory is then fsynced. The installed file is reread and parsed, requiring the old binding to be absent and exactly one replacement swapfile binding to match the frozen target/options/dump/pass before the journal advances to PersistentConfigUpdated. Any ambiguity after the started phase persists RecoveryRequired. Partition removal and journal completion remain outside M1B65.


M1B65 is restacked on the merged M1B64 master baseline.


M1B66 freezes the final partition-removal boundary without changing the partition table. It requires the exact M1B65 PersistentConfigUpdated journal and receipt, revalidates pinned production swap consent and live replacement-swap state, then discovers exactly one DOS type-82 retiring logical partition inside exactly one containing extended partition with no sibling logical partitions. The swap size must still equal the frozen activation size. A fresh root-owned 0600 fsynced sfdisk dump is captured under the swap-runtime journal root and its digest plus exact partition numbers/geometry are sealed into a non-mutating preflight receipt. The journal remains PersistentConfigUpdated; actual sfdisk deletion and Completed transition remain separately gated.


M1B66 is restacked on the merged M1B65 master baseline.


M1B67 pins the final partition-removal executables without spawning anything. After an integrity-valid M1B66 preflight, trusted fixed-system `sfdisk` and `partx` identities are resolved, opened with `O_NOFOLLOW`, and retained by descriptor. Revalidation hashes the already-open executable objects and requires the same device/inode/uid/mode/size/content before the future removal crossing, preventing pathname replacement or in-place binary mutation. No partition-table or kernel partition state changes occur in this layer.


M1B68 freezes the final partition-removal command sequence without spawning it. After the M1B66 geometry/backup preflight and M1B67 descriptor-pinned tools are revalidated, the executor seals one exact `sfdisk --lock=yes --delete DISK LOGICAL_SWAP EXTENDED` stage followed by one exact `partx --update DISK` stage. The logical swap partition number is ordered before its containing extended partition, trusted executable identities and fixed environment are part of the launch digest, and the contract records `process_spawned=false` / `partition_table_changed=false`. A later M1B69 layer must durably enter RemovingPartitions before executing this launch and must verify both partitions absent plus the replacement swap/persistent configuration intact before Completed.


M1B69 crosses the final partition-removal boundary behind its own compile-time feature. Before the first descriptor spawn it revalidates the complete M1B65 runtime/persistent chain, exact persisted journal, pinned consent, M1B66 fresh geometry/backup preflight, M1B67 pinned executables and M1B68 launch digest, then fsync-persists `RemovingPartitions`. Only the frozen `sfdisk --delete` and `partx --update` descriptor stages may run. Any child failure or ambiguous post-state is durably forced to `RecoveryRequired`. Success requires the old logical swap and extended container absent from fresh partition discovery, old swap inactive, replacement swap still active at the frozen priority/size, and the replacement fstab entry still exact with the retiring entry absent. Only then may the journal persist `PartitionsRemoved` and `Completed`.

M1B69 restacked on the merged M1B68 master baseline.


M1B70 adds the first complete production swap-tail E2E over one harness-owned DOS loop fixture. The harness reuses the real M1B56-M1B69 production APIs while injecting only owned consent/fstab/evidence paths under a dedicated test-only feature; production defaults remain unchanged. It must prove replacement swap activation at the frozen priority, old-partition swapoff, atomic persistent-config replacement, removal of logical p5 plus extended p2, durable journal Completed, continued replacement swap service through final removal, filesystem sentinel preservation, and exact cleanup. Any failure retains the owned fixture as uncertain rather than broadening mutation scope.


M2A1 begins provisioning after the M1B safety architecture. A successful advisory Create preview for an exact blank disk can now be frozen into a deterministic, explicitly non-executable intent covering the disk identity, logical sector size, GPT/DOS policy, exact partition start/count/bytes and ext4/XFS filesystem choice. Fresh partition-table collector evidence and blank/unmounted/non-swap state are required again at freeze time. The first M2 profile intentionally rejects mount/fstab intent; execution, consent, tool pinning, partition writes and mkfs remain future gates.


M2A2 adds a separate compile-time provisioning activation around the M2A1 frozen blank-disk intent. The activation rechecks intent readiness, its digest, exact /dev path and disk geometry, GPT/DOS policy, partition range and ext4/XFS/no-mount profile before sealing another deterministic ID. Even when the feature is compiled, the activation records execution_enabled=false, partition_table_changed=false and filesystem_formatted=false. No consent, process spawn, partition write or mkfs path is introduced yet.


M2A3 requires explicit root-owned provisioning consent for exactly one M2A2 activation. The canonical document lives at `/etc/linux-storage-manager/production-create-consent.json`, must be a single-link root-owned mode-0600 regular file opened with `O_NOFOLLOW`, and must repeat the exact activation ID, create-intent ID, disk, filesystem and phrase `I UNDERSTAND THIS WILL PARTITION AND FORMAT THE DISK`. A digest-bound receipt is produced with execution_enabled=false. The layer still cannot spawn tools or mutate storage.


M2A3 is restacked on the merged M2A2 master baseline.



M2A4 pins the verified provisioning consent by retaining the exact opened file descriptor after M2A3 verification. Both the live pathname and the pinned fd must continue to match device/inode/uid/mode/link-count/size/SHA-256 before later authorization. In-place edits and pathname replacement fail closed. This still carries no execution permit and cannot mutate storage.



M2A5 seals the exact create activation only after revalidating the still-open M2A4 pinned consent lease against the live canonical consent path. The permit binds activation ID, consent receipt, frozen create-intent/plan/source IDs, disk geometry, GPT/DOS policy, exact partition range/bytes and ext4/XFS choice into a deterministic digest. It explicitly records mutation_enabled=false, process_spawned=false, partition_table_changed=false and filesystem_formatted=false. No partition-table write, mkfs execution, mount or fstab mutation is introduced; fresh runtime preflight and trusted-tool pinning remain the next gates.


M2A6 performs the final fresh read-only blank-disk preflight before any future provisioning crossing. It verifies the exact M2A2/M2A5 authorization chain, revalidates the still-open M2A4 consent lease, re-discovers a unique blank Disk/Loop with unchanged size/sector/model/serial and no children/filesystem/table/mount/fstab/swap use, and rechecks the frozen partition geometry. It then resolves root-owned non-writable trusted sfdisk, partx and exact mkfs.ext4/mkfs.xfs identities. The resulting receipt remains mutation_enabled=false/process_spawned=false/partition_table_changed=false/filesystem_formatted=false. Tool descriptor pinning, launch construction, durable journal and execution remain separate later gates.


M2A7 pins the exact M2A6 create executables by open descriptor. The sfdisk, partx and selected mkfs.ext4/mkfs.xfs objects are opened with O_NOFOLLOW/O_CLOEXEC, then device/inode/uid/mode/size/SHA-256 are revalidated against the fresh preflight identities. Revalidation hashes the already-open descriptors so pathname replacement and in-place binary mutation both fail closed. This layer still spawns no process and changes no partition table or filesystem.


M2A8 freezes the exact blank-disk create launch after M2A7 pins sfdisk/partx/mkfs by descriptor. The non-spawning contract binds one exact GPT/DOS sfdisk script and argv, one exact partx mapping-add for partition 1, and one exact ext4/XFS mkfs argv against the derived partition device. Native ELF identity, fixed PATH/locale, pinned tool identities and the full M2A2/M2A5/M2A6 authorization chain are included in the launch digest. The contract explicitly requires fresh partition rediscovery after sfdisk/partx and before any future mkfs crossing. No process is spawned and all mutation/result flags remain false. Durable create journaling and execution remain disabled.


M2A9 adds the durable create runtime state machine before any production Create process can be spawned. The journal starts in Prepared with all mutation flags false. Before sfdisk, the executor must durably cross BeginPartitionTableWrite, which conservatively marks partition-table mutation as possible. A successful table write still cannot authorize mkfs: the journal remains PartitionTableWrittenAwaitingRediscovery until fresh exact partition geometry is durably verified. Filesystem formatting has its own pre-write boundary and cannot reach Completed until fresh filesystem rediscovery succeeds. Any failure after a mutation boundary can be persisted as RecoveryRequired. Records are root/current-user-owned 0600 files in a 0700 directory with fsync-backed atomic replacement. M2A9 itself remains non-spawning.


M2A10 crosses only the first irreversible Create boundary. Under the host storage lock and root, the complete M2A2-M2A9 authorization chain, live pinned consent, persisted Prepared journal and descriptor-pinned tools are revalidated. The journal is fsync-persisted as WritingPartitionTable before the exact frozen sfdisk script may run; the exact pinned partx mapping-add follows without shell resolution. Any runtime ambiguity enters durable RecoveryRequired. Success is not accepted from process exit alone: bounded fresh discovery must show the exact GPT/DOS table, one exact partition node/start/count/type/bytes, unchanged disk identity, no filesystem/mount/fstab/swap use, and the kernel mapping. Only then is PartitionRediscoveryVerified persisted and a receipt returned. The pinned mkfs descriptor is deliberately unreachable from M2A10.


M2A11 crosses only the filesystem-format boundary after the exact M2A10 receipt and persisted PartitionMappedVerified journal are revalidated under root plus the held HostStorageLock. The immutable M2A2-M2A10 authorization, consent and descriptor-pinned tool chain is checked again, including the frozen mkfs program/argv and a fresh pre-format rediscovery proving the partition geometry is still exact and unused. The journal must fsync-persist BeginFilesystemFormat before the pinned mkfs.ext4/mkfs.xfs descriptor can execute. Child failure or any ambiguous rediscovery enters durable RecoveryRequired. Success requires bounded fresh discovery to prove the exact requested ext4/XFS filesystem on the same partition while mount, fstab and swap use remain absent; only then may FilesystemRediscoveryVerified advance the journal to Completed and produce the M2A11 receipt. Mount activation and persistent configuration remain a separate later gate.


M2A12 seals the first post-format mount/persistence contract without executing it. It accepts only the integrity-valid M2A11 filesystem receipt bound to the exact Completed create journal and original activation, then rechecks a fresh storage snapshot for the same disk/partition/filesystem and requires a canonical filesystem UUID. The target mountpoint must already exist as an empty root-owned directory, every path component must be a real non-group/world-writable directory, and critical top-level system directories are rejected as direct targets. Existing mount, swap or fstab bindings for either the partition/UUID or mountpoint block activation. The sealed intent freezes the mountpoint device/inode/uid/mode, UUID-based fstab source, portable defaults+nofail options and fsck pass policy while recording execution_enabled=false, mount_performed=false and fstab_changed=false. M2A12 creates no directory, spawns no mount tool and writes no persistent configuration.


M2A13 closes the non-spawning runtime preparation boundary for the M2A12 mount intent. A fresh snapshot now requires complete lsblk/partition-table/mount/fstab/swap collectors and re-proves the exact single-partition geometry, filesystem type and UUID before activation can continue. The mountpoint path is revalidated as a root-owned non-writable directory chain and the exact frozen final device/inode/uid/mode must still be empty. The trusted mount executable is resolved and pinned by open descriptor with inode/metadata/content hashing, then revalidated again while sealing an exact fexecve launch contract. The frozen argv uses mount -n with explicit filesystem, rw options, UUID source and target so no /etc/mtab write or fstab lookup is authorized. No mount process or persistent configuration write is reachable in M2A13.


M2A14 adds the first guarded live mount crossing without opening persistent configuration. A dedicated fsync-persisted mount journal is Prepared before execution and moves to Mounting before the descriptor crossing, so any interruption after that point is recoverable rather than replayed blindly. Immediately before crossing, the implementation recomputes the full M2A13 fresh snapshot preflight and exact launch spec and requires byte-for-byte equality, which revalidates filesystem UUID/conflicts, mountpoint identity and the pinned mount executable again. Only the sealed `mount -n -t <fs> -o rw UUID=<uuid> <target>` descriptor is executed. Zero exit remains non-terminal until bounded fresh rediscovery proves the original disk/partition geometry, filesystem UUID/type, exact single mount target, RW state, absence of swap conflicts and unchanged fstab. Failures after BeginMount are durably forced to RecoveryRequired; fstab writes remain unreachable.\n\n\nM2A14b proves that complete production Create path on a root-owned disposable loop fixture before persistent configuration is opened. The accepted CI run executes the exact production partition-table crossing, ext4 format crossing and descriptor-pinned mount crossing, reloads the durable create/mount journals in a second process, proves a deliberately wrong restart mountpoint fails closed, proves the exact restart chain succeeds, then performs an explicit owned unmount and cleanup. The partx mapping-add boundary also reconciles a non-zero idempotent result only when complete fresh rediscovery independently proves the exact frozen partition mapping is already present and unused; a partx error is never accepted on exit status alone. Acceptance on PR #166 produced three independent `PRODUCTION_CREATE_MOUNT_E2E_OK=create-format-mount-restart-unmount` markers and three complete loop-matrix passes.

M2A15 opens persistent configuration only after the exact M2A14 live-mount receipt and immutable mount journal are completed. A separate fsync-durable journal is persisted before the fstab mutation boundary. The implementation backs up the exact original /etc/fstab, appends only the sealed UUID-based entry, rechecks the original inode/metadata/content, writes a same-directory create-new temporary file, fsyncs it, atomically renames it, fsyncs the parent directory, then requires parse/readback plus fresh full storage rediscovery before Completed. Any ambiguous failure after UpdatingFstab is forced to RecoveryRequired; the completed M2A14 mount journal remains immutable.

M2A15b is the destructive acceptance gate for that persistence crossing. The production Create loop harness now carries the same blank-disk -> partition -> ext4 -> live mount path into the real M2A15 persistent-config API on the disposable CI host, requires the durable fstab backup and Completed persistent journal, reloads the create/mount/persistent journal chain in a second process, rejects a deliberately wrong restart target, and re-proves exactly one sealed persistent binding. The outer root-owned fixture restores the original /etc/fstab bytes and metadata with fsync-backed atomic replacement before explicit unmount and exact journal cleanup. Acceptance on PR #168 at head `3d0664fe0476d3dada64d5a91bdd096a47eab192` produced three independent `PRODUCTION_CREATE_PERSISTENT_E2E_OK=create-format-mount-fstab-restart-restore-unmount` markers across Integration repetitions 1/3, 2/3 and 3/3, with the complete Loop integration job succeeding and no suspicious failure lines.

M2A16 generalizes the destructive Create acceptance from the single GPT/ext4 proof to the complete blank-disk profile matrix currently admitted by the production contracts. The loop harness requires explicit partition-table and filesystem selectors and binds them into the plan, activation, durable create journal, mount journal, persistent journal and restart verification. The integration matrix exercises GPT/ext4, DOS/ext4, GPT/XFS and DOS/XFS on independent owned loop devices; every profile crosses the same production partition/mkfs/mount/fstab code, rejects a wrong restart mountpoint, reloads all journals, restores the original /etc/fstab exactly and explicitly unmounts before cleanup. Acceptance on PR #169 at code head `ab25ecb0500e21049f7cf4b75db05d71940cb766` completed all three Integration repetitions with exactly three success markers for each of `gpt-ext4`, `dos-ext4`, `gpt-xfs` and `dos-xfs` (`12/12` profile proofs total), while the complete Loop integration job finished successfully.

M2B1 opens the next Create source class without opening a write boundary. A successful existing-disk GPT tail preview can be frozen only when lsblk and authoritative partition-table discovery are complete, the disk/table identity is unique, the GPT disk identifier and canonicalized table digest are stable, all existing partition records are non-overlapping and in-range, and the selected tail/allocation sector geometry is exact and 1 MiB aligned. The intent binds the disk identity, GPT first/last LBA, sector size, table digest, existing partition count, full tail range, requested partition extent and ext4/XFS profile. It explicitly records partition-slot selection as deferred and keeps both partition-table-write and filesystem-format authorization false. A later M2B runtime gate must re-prove the same table and tail, capture a durable table backup, resolve one unused GPT slot from fresh trusted tooling, and preserve every pre-existing entry before any partition addition can become executable.

M2B2 adds the first production-side gate for existing-GPT-tail provisioning without making the intent executable. The activation accepts only an integrity-valid Ready M2B1 intent and reasserts the exact /dev disk path, disk size/logical-sector geometry, GPT disk identifier/first-last LBA/sector size/canonical table SHA-256, full frozen tail range, requested partition extent, 1 MiB alignment and ext4/XFS/no-mount profile. The activation digest binds all of those values plus the existing partition count while retaining partition_slot_deferred=true and execution_enabled=false/partition_table_changed=false/filesystem_formatted=false. No consent file, runtime discovery, partition-slot selection, tool resolution, command construction, process spawn or disk write is reachable in M2B2; those remain separate later gates.

M2B3 requires explicit root-owned consent before the existing-GPT-tail activation can advance toward runtime authorization. The canonical document is a single-link mode-0600 regular file opened with O_NOFOLLOW and is bound not only to the M2B2 activation/create-intent IDs, disk and filesystem, but also to the exact GPT disk identifier, canonical pre-mutation table SHA-256 and frozen partition start/count. The phrase explicitly acknowledges modifying an existing GPT disk and formatting a new partition. Verification produces a digest-bound receipt with execution_enabled=false; no partition slot, tool, launch, journal or write boundary is introduced.

M2B3 restacked directly on the merged M2B2 master baseline.

M2B4 pins the verified M2B3 consent object before any later execution authorization. The exact root-owned consent file is retained by O_NOFOLLOW/O_CLOEXEC descriptor and its device/inode/uid/mode/link-count/size/SHA-256 are revalidated from the open object. Revalidation also re-runs canonical consent verification through the live pathname and requires the resulting receipt/file identity to remain byte-for-byte equal to the pinned receipt. Path replacement and in-place content mutation therefore fail closed. M2B4 still selects no GPT slot, spawns no process and changes no storage state.

M2B4 restacked on the current M2B3 head.

M2B4 restacked directly on the merged M2B3 master baseline.

M2B5 seals the exact existing-GPT-tail authorization only after revalidating the still-open M2B4 consent lease. The deterministic permit binds activation and consent receipt IDs, disk identity, GPT disk ID/first-last LBA/sector size/canonical table SHA-256, existing partition count, full frozen tail range, requested partition start/count/bytes and ext4/XFS profile. It explicitly retains partition_slot_deferred=true and mutation_enabled=false/process_spawned=false/partition_table_changed=false/filesystem_formatted=false. Fresh runtime rediscovery, GPT backup, partition-slot selection and trusted-tool preparation remain separate later gates.

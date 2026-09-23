# M1B16 — disposable-only mutation executor design

M1B16 is the first stage allowed to perform real storage mutation, but only inside the
owned disposable loop-device integration harness. It does **not** enable production
mutation and does not change `MUTATION_ENABLED=false`.

## Scope

The first executable profile is intentionally narrow:

1. existing verified VG free extents;
2. exact LV growth;
3. ext4 or XFS filesystem growth;
4. rediscovery and exact expected-state verification.

The partition -> PV -> LV -> filesystem chain remains non-executable until the simpler
profile is proven repeatedly.

## Required inputs

A disposable execution attempt must bind all of the following:

- `ValidatedNativeManifest` and its deterministic digest;
- current `LockedExecutionSession`;
- exact approved/frozen source manifest ID;
- fresh target identity/capability revalidation;
- durable journal state;
- verified metadata-backup receipt;
- owned loop-device fixture identity supplied by the integration harness.

## Disposable ownership boundary

Mutation is allowed only when every block device involved resolves to an owned
`/dev/loopN` whose backing file is a regular file created inside the current integration
test root.

The harness must prove, immediately before each mutation boundary:

- loop path matches `^/dev/loop[0-9]+$`;
- loop major number is 7;
- backing file is the exact tracked inode;
- backing file remains inside the owned temporary root;
- all partition/PV/LV targets descend from that loop;
- the target VG name is a harness-generated disposable name;
- no unrelated host block device participates in the route.

Any ambiguity fails closed.

## Execution model

Production code must never receive a generic shell string.

The disposable executor uses typed command specifications and
`std::process::Command` with separate arguments. Only the exact operation classes needed
by the current disposable profile may compile to executable argv.

For the first profile:

- `ExtendLogicalVolume` resolves the approved LV UUID against the freshly revalidated
  target identity and compiles an exact LV growth command;
- `GrowFilesystem` resolves the exact fresh filesystem device/mountpoint;
- ext4 and XFS use separate typed adapters;
- every subprocess exit status and stderr is captured;
- an unexpected tool/path/argument/state is a hard stop.

## Journal boundary

A disposable executor must not reuse the production `MUTATION_ENABLED` gate.

Instead it receives a test-only/disposable capability that is constructible only by the
integration harness after ownership proof. Production callers cannot construct this token.

Before the first mutation:

- durable journal must equal the current in-memory approved state;
- exact validated native-manifest digest must be recorded;
- mutation-start intent must be persisted atomically.

After mutation may have started, interruption must never silently replay the operation.
The state becomes recovery/reconciliation-required until fresh discovery proves the result.

## Verification

After every destructive layer:

1. rediscover;
2. verify exact target identity;
3. verify capabilities;
4. verify the expected new size/state;
5. stop before the next mutation on any mismatch.

The first LV/filesystem profile therefore verifies LV size before filesystem growth and
filesystem size after growth.

## Integration acceptance

The disposable matrix must cover at least:

- LVM/ext4 using existing VG free extents;
- LVM/XFS using existing VG free extents;
- repeated execution attempts proving an already-applied manifest cannot be blindly replayed;
- forced command failure before mutation;
- forced interruption/failure after mutation-start journaling;
- sentinel data preservation;
- exact before/after storage facts;
- complete cleanup only when harness ownership remains certain.

## Explicitly out of scope

M1B16 does not expose:

- `storagemgr apply`;
- production privileged helper;
- arbitrary device paths;
- shrink;
- partition mutation;
- PV resize;
- mount/fstab/swap mutation;
- LUKS/RAID/Btrfs/ZFS writes.

Those remain later, separately reviewed gates.

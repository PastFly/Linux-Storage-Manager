# M1B16 — disposable-only mutation executor design

M1B16 is the first stage allowed to perform real storage mutation, but only inside the
owned disposable loop-device integration harness. It does **not** enable production
mutation and does not change `MUTATION_ENABLED=false`.

## Scope

The executable surface remains intentionally narrow and disposable-only.

The first profile uses existing verified VG free extents:

1. exact LV growth;
2. ext4 or XFS filesystem growth;
3. rediscovery and exact expected-state verification.

The second profile starts only when the already-existing PV backing partition/device is
authoritatively larger than the current PV:

1. exact PV resize;
2. rediscover and verify the expected PV size;
3. exact LV growth using the newly exposed extents;
4. rediscover and verify the expected LV size;
5. ext4 or XFS filesystem growth;
6. terminal rediscovery and verification.

A third disposable profile permits only size growth of one already-existing GPT or DOS/MBR partition when authoritative adjacent capacity is proven. It never moves the partition start and does not create, delete, reorder or shrink partitions.

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

For the approved disposable profiles:

- `ExtendPartition` resolves the exact frozen partition/disk geometry, emits only a size-grow `sfdisk -N` payload with the same start sector, uses explicit locking and suppressed implicit kernel reread, then performs an exact `partx --update --nr` refresh;
- `ResizePhysicalVolume` resolves the approved PV UUID/path against fresh identity,
  requires exact observed PE start, and converts the expected usable PV size into the exact
  raw `pvresize --setphysicalvolumesize` limit;
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

The LV/filesystem profile verifies LV size before filesystem growth and filesystem size
after growth. The PV/LV/filesystem profile additionally verifies the exact PV UUID and
usable PV size before minting the one-shot permit for LV growth. The partition/PV/LV/filesystem
profile first requires the fresh partition to keep the exact disk/table identity, start sector,
type, UUID and other recorded metadata while changing only to the exact approved size; its
kernel block-device size must also match before a PV permit can be minted.

## Integration acceptance

The disposable matrix must cover at least:

- LVM/ext4 using existing VG free extents;
- LVM/XFS using existing VG free extents;
- LVM/ext4 with a backing partition larger than the PV, proving exact
  `pvresize -> verify PV -> lvextend -> verify LV -> resize2fs -> verify filesystem`;
- GPT and DOS/MBR LVM/ext4 disk-tail growth, proving exact
  `sfdisk size-only -> partx -> verify partition -> pvresize -> verify PV -> lvextend -> verify LV -> resize2fs -> verify filesystem`;
- repeated execution attempts proving an already-applied manifest cannot be blindly replayed;
- forced command failure before mutation;
- forced interruption/failure after mutation-start journaling;
- GPT and DOS/MBR post-write failure after exact `sfdisk` success but before kernel refresh, requiring durable `RecoveryRequired`, retained evidence, blocked replay, unchanged LVM/filesystem state and explicit reconciliation;
- post-`pvresize` failure before `lvextend`, requiring durable `RecoveryRequired`, exact resized-PV reconciliation, retained evidence, blocked replay and unchanged LV/filesystem/sentinel state;
- post-`lvextend` failure before filesystem growth, requiring durable `RecoveryRequired`, preserved verified-boundary evidence, exact resized-LV reconciliation, retained evidence, blocked replay and unchanged filesystem/sentinel state;
- post-ext4-`resize2fs` failure before terminal verification, requiring durable `RecoveryRequired`, preserved pre-terminal boundary evidence, proof that filesystem capacity actually grew, retained evidence, blocked replay and intact sentinel data;
- sentinel data preservation;
- exact before/after storage facts;
- complete cleanup only when harness ownership remains certain.

## Explicitly out of scope

M1B16 does not expose:

- `storagemgr apply`;
- production privileged helper;
- arbitrary device paths;
- shrink;
- partition creation/deletion/reordering, partition-start movement, shrink or arbitrary partition edits;
- mount/fstab/swap mutation;
- LUKS/RAID/Btrfs/ZFS writes.

Those remain later, separately reviewed gates.

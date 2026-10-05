# Pre-Production Test Plan

This document defines manual/disposable-VM acceptance for Linux Storage Manager.
It complements CI; it does not replace the existing unit, safety-gate, portability,
and destructive loop tests.

## Safety boundary

Run pre-production destructive tests only on a disposable VM or a VM snapshot that
can be discarded. Do not run the destructive matrix on a production host.

The test harness is restricted to backing files and loop devices that it creates
and owns. The operator must still verify that the VM contains no production data
before enabling destructive tests.

## Wave 1 — active now

Wave 1 covers production paths that already have completed guarded executors and
destructive loop E2E coverage:

1. Read-only discovery, target selection, diagnostics, Extend and Create previews.
2. Existing-VG-free LV -> filesystem growth.
3. Chained partition -> PV -> LV -> filesystem growth on a single-PV LVM stack.
4. ext4 online growth.
5. ext4 offline health-check/growth/remount path.
6. XFS online growth.
7. Multiple target isolation: changing one selected partition/LV must not alter siblings.
8. DOS tail swap-partition -> swapfile migration, persistent configuration rewrite,
   old logical/extended partition removal and recovery behavior.
9. Blank-disk Create across GPT/DOS x ext4/XFS, including mount, atomic fstab
   persistence, restart verification, exact fstab restoration and explicit unmount.
10. Failure/recovery boundaries already injected by the loop matrix.

### Initial VM matrix

Required first-pass manual environments:

- Ubuntu 24.04 LTS x86_64
- Debian 12 x86_64
- Rocky Linux 9 x86_64

After the first pass, repeat on at least one aarch64 VM and extend to the additional
portable targets already covered by artifact CI.

### Required evidence

For every VM record:

- exact repository commit SHA;
- distribution and kernel version;
- CPU architecture;
- versions/paths of sfdisk, partx, LVM, e2fsprogs and xfsprogs tools;
- complete stdout/stderr from the test run;
- final mount, swap and partition state;
- whether /etc/fstab returned to its exact original bytes after fixture cleanup;
- whether all sentinel files survived;
- whether any loop device, mount, swapfile or journal artifact leaked after cleanup.

### Build and run

From a clean checkout of the exact candidate commit:

```bash
cargo build --locked --release --workspace
cargo build --locked --release -p lsm-executor \
  --features disposable-loop-harness --bin lsm-disposable-loop-harness
cargo build --locked --release -p lsm-executor \
  --features disposable-swap-migration-harness --bin lsm-disposable-swap-loop-harness
cargo build --locked --release -p lsm-executor \
  --features production-loop-harness --bin lsm-production-loop-harness
cargo build --locked --release -p lsm-executor \
  --features production-swap-loop-harness --bin lsm-production-swap-loop-harness
cargo build --locked --release -p lsm-executor \
  --features production-create-loop-harness --bin lsm-production-create-loop-harness

ROOT="$(pwd)"
for attempt in 1 2 3; do
  echo "Pre-production repetition ${attempt}/3"
  sudo python3 -I tests/integration/loop_matrix.py \
    --allow-disposable-loop-tests \
    "${ROOT}/target/release/storagemgr" \
    "${ROOT}/target/release/lsm-disposable-loop-harness" \
    --swap-executor-binary "${ROOT}/target/release/lsm-disposable-swap-loop-harness" \
    --production-executor-binary "${ROOT}/target/release/lsm-production-loop-harness" \
    --production-swap-executor-binary "${ROOT}/target/release/lsm-production-swap-loop-harness" \
    --production-create-executor-binary "${ROOT}/target/release/lsm-production-create-loop-harness"
done
```

The distribution must provide the required storage utilities before the run. Missing
tools are a failed prerequisite, not permission to substitute an unverified binary.

### Wave 1 acceptance

Wave 1 passes on a VM only when all three repetitions succeed and:

- every destructive step is followed by exact rediscovery/verification;
- no non-target storage object changes;
- sentinel data is unchanged;
- injected ambiguous/fault states enter the expected recovery state and do not replay blindly;
- swap replacement leaves no unintended active swap or partition artifacts;
- Create profile markers pass for GPT/ext4, DOS/ext4, GPT/XFS and DOS/XFS;
- fixture cleanup restores /etc/fstab exactly and leaves no owned mounts/loops behind.

A distribution is not promoted from pre-production evidence on a partial pass.

## Wave 2 — existing GPT-tail Create

Wave 2 adds the M2B path: create a new filesystem partition in the verified free
tail of an existing GPT disk without modifying existing partition starts or payloads.

Wave 2 begins only after the M2B runtime chain has all of the following:

1. fresh exact table/tail preflight;
2. pinned trusted storage tools;
3. fsynced pre-mutation GPT backup;
4. exact partition-slot/launch contract;
5. durable pre-write journal;
6. guarded partition-add crossing with fresh post-write geometry proof;
7. guarded ext4/XFS format crossing;
8. destructive disposable-loop E2E proving existing partitions and sentinel data unchanged.

After that automated acceptance, the same path is added to this manual VM matrix.

## Real extra virtual disk test

After loop-based Wave 1 passes on a disposable VM, one additional test may use a
dedicated empty virtual disk attached only for Linux Storage Manager validation.
The disk must be independently identifiable and contain no production data.

This stage validates operator-facing target selection and real kernel/udev behavior.
It must not use the VM boot/root disk as the destructive target.

## Result record

Use one result block per VM:

```text
SOURCE_SHA=
DISTRO=
KERNEL=
ARCH=
WAVE1_REPETITIONS=0/3
PORTABLE_BINARY_SMOKE=
EXTEND_PROFILES=
SWAP_MIGRATION=
CREATE_GPT_EXT4=
CREATE_DOS_EXT4=
CREATE_GPT_XFS=
CREATE_DOS_XFS=
FSTAB_EXACT_RESTORE=
SENTINEL_PRESERVED=
LEAKED_RESOURCES=
RECOVERY_DRILLS=
RESULT=PASS|FAIL
NOTES=
```

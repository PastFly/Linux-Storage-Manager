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

### Prerequisites

Use a clean checkout of the exact candidate. The repository pins Rust **1.88.0**;
Python **3.10 or newer** is required by the runner and matrix. A Git checkout, native
C compiler/linker and the host storage utilities must be available. On Ubuntu
24.04 or Debian 12 the storage/build prerequisites can be installed with:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential git python3 lvm2 e2fsprogs xfsprogs util-linux fdisk udev
```

Install the repository's Rust toolchain before building. On Rocky Linux 9, use an
installed Python 3.10+ interpreter explicitly (for example `python3.11`), including
in the `sudo` command; do not assume the distribution's default `python3` is new
enough. Its storage packages must provide the same capabilities listed by `check`.
The runner never installs packages or substitutes missing storage tools.

Allow space for native Rust builds and the loop fixture images, and run on a quiet
VM without unrelated storage administration. The before/after comparison rejects
unexplained resource changes, including changes made by another process.

### Build and run

Build as the checkout owner. The build command reuses the separately gated native
Cargo profiles and writes a manifest binding the clean source SHA, harness script
and all six binary digests. A stale or changed executable fails validation.

```bash
python3 -I tools/preprod.py build
python3 -I tools/preprod.py check --expected-source "$(git rev-parse HEAD)"

sudo python3 -I tools/preprod.py run \
  --expected-source "$(git rev-parse HEAD)" \
  --allow-disposable-vm-tests \
  --output /var/tmp/lsm-wave1-first-run
```

`check` is also the default mode. It never runs the matrix. `run` requires Linux,
root, the exact source SHA and explicit disposable-VM acknowledgement. It supplies
all five executor paths to the existing matrix and requires **three complete
repetitions**. The first failure stops the remaining repetitions.

Choose a new output directory for every run. The runner refuses to overwrite old
evidence. Expected output:

| File | Evidence |
| --- | --- |
| `report.json` | Exact source/build identities, host/tool information, per-attempt command, exit status, profile coverage and before/after snapshots |
| `SUMMARY.txt` | Human-readable terminal result and repetition count |
| `attempt-1.log` through `attempt-3.log` | All emitted stdout/stderr from each attempted matrix run |

The report starts incomplete and is updated after each attempt. Only `PASS` with
three completed repetitions is acceptance. Prerequisite failures, missing markers,
nonzero child exits, interruptions or missing final evidence cannot pass. A zero
exit alone is insufficient because omitting an optional harness would omit profiles.

The runner checks exact fstab bytes/owner/mode and stable loop, mount, swap and LVM
identities, while retaining raw discovery snapshots. It also checks retained
matrix fixture directories. Changing usage counters or report row ordering are not
resource leaks. Sentinel preservation and per-boundary verification are asserted
by the matrix and required through its scenario markers.

On interruption, allow the matrix to finish its own cleanup. If it reports
`CLEANUP_INCOMPLETE`, keep the VM and evidence for inspection or discard the VM.
The outer runner does not remove storage resources, overwrite fstab or retry an
ambiguous operation. Do not issue broad cleanup commands to make the report pass.

The logs contain the output emitted by the harness, including command details on
failure. Successful low-level tool output captured internally by the matrix is not
claimed as a full command transcript.

### CI evidence

The `Loop integration` job runs the same build/run commands on a disposable Ubuntu
24.04 x86_64 runner. Its `wave1-ubuntu24-x86_64-<run>-<attempt>` artifact preserves
reports and logs for 14 days, including failed acceptance attempts when evidence
was created. Consult the workflow log if a prerequisite failed before report setup.

A successful Ubuntu CI report does not establish Debian, Rocky, ARM, a manually
operated external VM or a real extra virtual disk as tested. Portable Linux CI is a
separate static-linkage/userland smoke check; its prototype download omits the
mutation harnesses and cannot be used as a Wave 1 test bundle.

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

After loop-based Wave 1 passes on a disposable VM, attach a dedicated empty virtual
disk to inspect operator-facing discovery, target selection and previews. Keep its
identity explicit and use the read-only CLI/TUI. The current operator interface has
no general `apply` command; do not describe this inspection as a destructive real-disk
acceptance test. A later real-disk execution test needs its own supported guarded
entry point and evidence. Never use the VM boot/root disk as a destructive target.

## Result record

Keep the runner output as the authoritative record. For a manual test summary,
use one block per VM and link its report; do not fill unexecuted fields with PASS:

```text
SOURCE_SHA=
DISTRO=
KERNEL=
ARCH=
WAVE1_REPETITIONS=0/3
PORTABLE_BINARY_SMOKE=NOT_RUN|<separate evidence>
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

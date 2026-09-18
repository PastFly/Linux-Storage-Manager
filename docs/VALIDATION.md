# Validation and disposable storage tests

This document separates three kinds of evidence. Passing a weaker check never
implies that a stronger check passed. The application remains Rust; Python is
used only for test infrastructure, not as a runtime dependency of storagemgr.

## 1. Harness tests without storage access

From the repository root, as an ordinary user:

```sh
bash tools/validate.sh --source-only
```

Requires Bash and Python 3.10+. Runs 24 standard-library unit tests with mocked
command execution and temporary regular files. No real loop device, LVM group,
mount or filesystem is created. Exercises cleanup failures, ownership changes,
unknown state, delayed detach, preview JSON/exit-code contracts and detection
of geometry drift. The success marker explicitly says Rust and real storage
integration did not run.

Locally executed for this change: all 24 tests passed; Bash syntax checks and
Python syntax compilation passed. This is NOT Rust compiler, kernel, filesystem
or real LVM evidence.

## 2. Compile and test M0 + M1A

On a build machine with the repository's Rust 1.88.0 toolchain:

```sh
bash tools/validate.sh
```

Runs harness tests, rustfmt check, Clippy with warnings denied, workspace tests
and a workspace build. Never invokes the root integration harness automatically.
Missing Cargo/rustc causes exit 2 with VALIDATION_INCOMPLETE, not a success marker.
The local attempted full validation stopped here because Cargo is unavailable;
external toolchain retrieval also failed due unavailable DNS.

Dependencies still need to be resolved and a Cargo.lock generated/committed from
a real Cargo build. No fully reproducible dependency lock is claimed yet.

## 3. Real Linux storage integration: disposable VM only

Do not run on production, on a shared admin host or on a long-lived CI runner.
The HARNESS creates partitions, filesystems and LVM fixtures. The application
under test must only inspect and produce non-executable plan previews.
The acknowledgement flag does not detect whether the machine is disposable;
that is an operator prerequisite. Do not run concurrent storage administration.

After a real build, in a dedicated Linux VM that may be discarded:

```sh
sudo python3 -I tests/integration/loop_matrix.py \
  --allow-disposable-loop-tests "$PWD/target/debug/storagemgr"
```

The old Bash entry point remains a thin wrapper with the same arguments.
Without the explicit acknowledgement, argument validation exits before creating
resources or invoking storage tools. Root and Linux are also required.

Implemented cases (NOT executed or accepted locally yet):

- GPT -> ext4 partition: M1A planning must refuse this unsupported target.
- GPT -> PV -> single-PV VG -> linear LV -> ext4.
- GPT -> PV -> single-PV VG -> linear LV -> XFS.

For LVM cases test --by 8MiB, --max, an oversized 1TiB request and rejection of
--apply. Check JSON dry_run=true / executable=false, empty operations for blocked
plans, positive extent-aligned previews, expected CLI exit codes (0 preview,
2 blocked/invalid arguments), before/after owned partition-table and block-tree
facts, LVM identity/capacity facts and a sentinel file's contents. This is targeted
nonmutation evidence, not proof that every byte on the host stayed unchanged.

## Cleanup policy

The previous Bash cleanup ignored umount/vgremove failures and used recursive
removal of the temporary directory. It has been replaced, not supplemented.

Track generated loops, backing file device/inode identities, VGs and their UUIDs,
exact PV membership and mounts. Refuse non-loop paths, changed backing files,
changed VG UUIDs and unexpected PV membership. Check exact mount source/target
before unmounting, then check no mounts remain under the owned directory. Stop
cleanup on uncertainty instead of continuing down the dependency chain.

Remove VGs before detaching their loops. losetup --detach may complete lazily:
re-query associations before unlinking images. Use only rmdir on known empty
directories and unlink on owned images. Never recursively delete mount trees.
CLEANUP_INCOMPLETE produces failure and reports retained paths. An ambiguous
creation failure also preserves resources. Inspect/discard the VM instead of
blindly forcing cleanup. SIGTERM/SIGHUP request the same cleanup path; SIGKILL,
host crashes and CI hard termination cannot guarantee cleanup.

These checks are not protection against a malicious or concurrently changing
root environment. Disposable, exclusively used VMs remain mandatory.

## CI

PR-triggered validation plus push validation of master, rather than duplicate
feature push and PR runs. Manual dispatch is also defined. Workflow concurrency
cancels superseded runs; jobs are time-limited. Gates are harness tests -> Rust
checks -> privileged disposable-VM integration. No continue-on-error or bypass
for billing-blocked jobs is used. No runner, billing or repository visibility
setting is changed by this work.

The last observed pre-change workflow was run 35128772184 (CI #113) at
6f2b5ad3737eeb5b768cc91339ec444a6ac5c486. It failed before a runner was assigned
and storage integration was skipped; the owner supplied GitHub's payment/limit
message. Check live statuses for the new head rather than treating this as a
permanent diagnosis. Do not merge until actual green CI and owner approval.

Upstream semantics used by the harness: util-linux losetup(8) documents lazy
detach and non-atomic --find; findmnt(8) documents exact --mountpoint lookup and
explicit output columns. See their manual pages and GitHub workflow syntax
reference for concurrency/event rules.

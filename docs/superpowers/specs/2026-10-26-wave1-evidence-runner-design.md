# Wave 1 evidence runner

## Intent

Make the already implemented Extend, swap migration and blank-disk Create paths
straightforward to test on a disposable Linux VM, with a complete, inspectable
three-run result. Existing-GPT-tail Create remains outside Wave 1.

The owner has requested autonomous continuation, fewer small checkpoints and
actual testing. This work follows the existing PREPROD_TEST_PLAN rather than
adding another production storage authorization stage.

## Approach

Use a Python 3.10+ standard-library runner around the existing loop matrix. Keep
all storage mutation and ownership-aware cleanup in that matrix. The final cleanup
boundary defers SIGINT/SIGTERM/SIGHUP until cleanup finishes and records failure,
so an interrupt during cleanup cannot abort the existing cleanup sequence. A new production
CLI apply path would expand the storage boundary; a documentation-only command
loop would still leave evidence collection and coverage checking to the operator.
The evidence runner is the implementation choice for this change.

## Interface

- `python3 -I tools/preprod.py build`: require a clean source tree, build the
  read-only binary and all five native harnesses with the existing separate
  feature combinations, and record source SHA, toolchain and file SHA-256 values
  in `target/preprod/build.json`. Use an explicit target directory so stale
  unrelated build output cannot be accepted accidentally.
- `python3 -I tools/preprod.py check --expected-source <SHA>`: inspect the pinned
  source, manifest, executable hashes and installed tools; never launch a storage
  test. Missing prerequisites mean nonzero exit, not partial acceptance.
- `sudo python3 -I tools/preprod.py run --expected-source <SHA>
  --allow-disposable-vm-tests [--output <new-directory>]`: root and Linux only,
  explicit opt-in, all six binaries required, exactly three complete matrix runs.

`check` is the default mode. No package installation, elevation, network access or
automatic cleanup is performed by the runner. Build uses the existing locked
Cargo dependency graph and Rust 1.88.0.

## Evidence and acceptance

Create a fresh mode-0700 output directory; refuse overwrites and symlink output.
Preserve all emitted matrix stdout/stderr in per-run logs and stream it to the
terminal. Write an atomic JSON report and readable summary, including source SHA,
binary and harness digests, OS/kernel/architecture, resolved tool paths/versions,
raw before/after storage snapshots and the exact command for each repetition.

Each repetition must have zero exit status, every required profile/recovery marker,
the final successful-cleanup marker, unchanged fstab bytes/ownership/mode and
unchanged stable loop/mount/swap/LVM resource identities. Keep raw lsblk data for
inspection. Compare stable identities, not usage counters or row ordering. Check
retained `lsm-loop-matrix-*` fixture directories without deleting them. Failure to
capture evidence is a failure. Stop after the first failed repetition.

Only three complete repetitions permit `PASS`. Missing markers, interruption,
changed source/binaries or failed final collection cannot pass. The report should
be written before starting and updated after each attempt so an incomplete run is
visible. The runner must let the child handle interruption and finish its own
cleanup; it must not kill a process group or remove uncertain storage resources.

The report records harness assertions and before/after observations. It does not
claim to capture successful low-level command output hidden by the harness, prove
all Linux distributions, or prove a manually operated physical-disk scenario.

## Verification and delivery

Rootless tests exercise real validation and orchestration with temporary files and
fake external command/process boundaries. Test missing opt-in, source/hash drift,
missing tools, incomplete markers, nonzero child exit, interrupted child, changed
fstab/resources, unavailable final evidence, ordering normalization and refusal to
overwrite evidence. CI runs the same runner for the actual destructive Ubuntu
loop matrix and uploads evidence even on failure. Debian, Rocky and ARM VM
acceptance remains pending until their own complete reports exist.

# Linux Storage Manager — current engineering handoff

Updated: **2026-11-06**. Repository: `PastFly/Linux-Storage-Manager`; verify live
`master`, PR heads and CI before continuing. `AGENTS.md` governs development.
The owner authorizes autonomous feature branches, PRs and squash merges after the
exact candidate has passed CI. Do not test on `srv-phpIPAM`.

## Operator support

`storagemgr apply extend TARGET --by SIZE` and `--max` support the narrow
existing-free-extents → LV → ext4/XFS profile for a single-PV VG. `--max` is
limited to existing VG free extents. XFS must be mounted; the planner and health
checks decide whether the exact ext4 state is admissible. An interactive terminal,
root privileges and the exact evidence-bound confirmation are required.

The executor uses trusted discovery and pinned tools, a host lock, durable
journals, metadata backup, fresh identity checks and verified mutation boundaries.
CI exercises the actual operator CLI on disposable Ubuntu loop devices for ext4
`--by` and mounted XFS `--max`, including cancellation, noninteractive refusal,
backup tampering before confirmation, a sibling LV and sentinel preservation.
The Wave 1 matrix runs three times; distribution userland smoke tests do not prove
equivalent kernel/VM mutation coverage.

The TUI and `plan` commands remain read-only. Direct partition → filesystem,
partition → PV → LV → filesystem, swap migration and Create are **not** operator
`apply` profiles. Some have separate disposable harnesses; harness acceptance is
not operator CLI support. Shrinking or moving partition starts is not supported.

## Current safety work

PR #183 fixed delayed journal `IN_CLOSE_WRITE` from inherited writable descriptors.
PR #184 added the first operator `apply extend`. PR #185 added device/inode to
backup receipt schema v2 and rejects a different inode at revalidation. PR #185
does **not** pin the file across checks, detect transient changes or prevent writes
through an already-open descriptor; inode reuse also remains possible without a
held descriptor. Do not describe that partial check as complete backup protection.

The next safety boundary must retain durable independent backup copies, bind and
monitor their exact identities through the mutation and verification lifecycle,
reject existing writers, stop or enter recovery on violations, and preserve a
fail-closed durable state after crashes. Other privileged root processes can remove
or change local backups, alter kernel settings or kill the manager/observer; no
userspace lease can guarantee durability against arbitrary root or device failure.
Test those boundaries only on disposable Linux/VMs and state the supported threat
model and limits.

## Next executable work

1. Complete and review backup protection before enabling additional write profiles.
2. Add actual operator execution for adjacent-tail GPT and simple DOS primary
   partition → ext4, without moving partition starts. Verify the entire partition
   table and neighboring geometry before mutation, and verify kernel geometry as
   well as the authoritative table before filesystem continuation.
3. Add operator partition → PV → LV → filesystem using the existing guarded
   execution and recovery mechanisms.
4. Complete the Debian DOS tail-swap scenario. Space behind an extended partition
   is not adjacent to an earlier primary partition: the existing restricted route
   migrates active swap to a verified swapfile before removing the sole logical
   swap and its now-empty extended container. Hibernation, persistent boot resume,
   memory pressure, fstab, geometry and offline requirements must be proven;
   current mounted loop fixtures are not evidence for reboot or a real root mount.
5. Continue Create after the above priorities with its own execution and recovery
   gates. Update the support/scenario matrices only for verified operator behavior.

`storagemgr plan extend TARGET --max --freeze-handoff` remains a non-executable
handoff and returns a non-success status even when well formed. Historical
milestone handoffs describe older states; they are not the live baseline.

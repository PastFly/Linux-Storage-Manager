# Architecture

## Design goal

A user expresses intent such as "show storage", "extend /", or "create 8 GiB swap". Linux Storage Manager translates that intent into storage-aware operations without forcing the user to manually compose low-level commands.

## Layers

1. **Discovery** — interrogates the running host through structured outputs from Linux storage utilities.
2. **Normalized model** — represents disks, partitions, device-mapper layers, LVM, filesystems, mounts, and swap independent of the distribution.
3. **Planner** — converts user intent into an ordered dependency graph. This is introduced after M0.
4. **Safety/preflight** — verifies capabilities, topology invariants, free space, online/offline requirements, and whether an operation is reversible.
5. **Executor** — invokes narrowly scoped system tools with explicit arguments. It is intentionally absent from M0.
6. **Verification** — re-discovers storage after execution and validates expected invariants.
7. **Interfaces** — TUI for interactive administration and CLI for automation.

## M0 boundary

M0 contains discovery, the normalized read-only model, CLI inspection, TUI inspection, fixtures, and tests. There is no mutating executor.

## Discovery authority

No single Linux utility is treated as sufficient for future write decisions.

- `lsblk` supplies the primary block-device topology, filesystem facts, mountpoint hints, and normalized device relationships.
- `sfdisk --json` supplies an independent read-only view of authoritative partition-table geometry.
- `pvs`, `vgs`, and `lvs` supply LVM allocation facts.
- `findmnt` supplies the active mount tree.
- `/etc/fstab` supplies persistent mount intent.
- `/proc/swaps` supplies active swap state.

M0 reconciles these sources and emits diagnostics for contradictions. Future M1 write planning must fail closed when authoritative geometry is unavailable or disagrees with the topology model.

## Dependency direction

```text
cli -----> discovery -----> core
  \
   +-----> tui -----------> core
```

The UI must not contain storage mutation logic. Future planner/executor crates will depend on `core`, not on `tui`.

## Host capability model

Support is capability-based rather than distribution-based. A host can expose `lsblk`, LVM2, XFS, ext4, Btrfs, mdraid, cryptsetup, or other capabilities independently. The UI should show what was detected and disable actions whose prerequisites are absent.

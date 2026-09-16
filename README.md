# Linux Storage Manager

Linux Storage Manager is a safety-first terminal application for inspecting and managing Linux storage without requiring administrators to manually compose low-level storage commands.

The project is currently in the **M0 — Storage Discovery** phase. M0 is intentionally read-only: it discovers the host storage topology and explains what can be done, but does not mutate disks, partitions, LVM metadata, filesystems, mounts, or swap configuration.

## Initial goals

- Full-screen TUI suitable for local consoles and SSH sessions.
- CLI for scripting and automation.
- Capability-based discovery instead of hard-coding Linux distributions.
- A normalized storage graph covering disks, partitions, LVM, filesystems, mounts, and swap.
- Explicit planning and dry-run before any future write operation.
- Metadata backup and post-operation verification for future mutating operations.
- Conservative safety model: unsupported or ambiguous storage layouts must fail closed.

## Planned M0 support

- Block devices and partitions through structured `lsblk` data.
- Mount topology.
- LVM PV/VG/LV discovery.
- ext4 and XFS recognition.
- Swap partition / swap file discovery.
- Host capability inventory.
- Read-only TUI and CLI output.

Implementation language: **Rust**.

> This repository is under active development. Do not use unfinished builds to modify production storage.

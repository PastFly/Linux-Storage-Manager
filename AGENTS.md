# Development rules

## Project objective

Linux Storage Manager is a safety-first terminal application for Linux storage administration. The primary interface is a TUI that works over SSH; a scriptable CLI uses the same core.

## Safety boundary

M0 is strictly read-only. Code merged during M0 must not modify partition tables, LVM metadata, filesystems, mounts, `/etc/fstab`, swap state, RAID metadata, encryption metadata, or block-device contents.

Future write support must follow: discovery -> normalized model -> immutable plan -> preflight -> metadata backup -> explicit confirmation -> execution -> verification.

Unsupported, incomplete, ambiguous, or contradictory topology must fail closed.

Before any future partition-table write plan is considered valid, current `lsblk` topology must be reconciled with an independent authoritative partition-table read such as `sfdisk --json`. Geometry mismatch diagnostics are blockers, not warnings.

## Implementation rules

- Rust is the implementation language.
- Prefer structured machine-readable output from Linux utilities; never parse human-formatted tables when a stable JSON/report format exists.
- Always request explicit columns from tools such as `lsblk`.
- Preserve source-specific units in the normalized model. In particular, `lsblk START` is in 512-byte sectors and must not be multiplied by `LOG-SEC`.
- Never build shell command strings from runtime values. Use `std::process::Command` with separate arguments.
- Discovery must work without root whenever the host tools permit it.
- Keep distribution-specific package management outside the storage core.
- Unit tests use recorded fixtures. Destructive integration tests may run only against disposable loop devices or disposable VMs and must clean up resources on failure.
- Keep repository text files UTF-8 and do not encode source/configuration files as base64.

## Git workflow

- Develop on feature branches.
- Open a pull request into the default branch.
- Do not merge into the default branch without explicit project-owner approval.
- CI must pass before requesting merge approval.

## Multi-agent pilot boundary

- Public PR code runs only on disposable GitHub-hosted runners. Do not route it to the persistent AI-Agent-Loop-Lab runner or the shared VPN VPS.
- `Agent pilot` checks the exact PR head with Rust 1.88.0, format, Clippy, workspace tests, and the source-only harness. It does not replace the existing CI, journal, operator, or portability workflows.
- Actual loop/storage integration remains confined to the existing disposable GitHub VM jobs. Never run those jobs on a developer host or the shared VPS.
- Local Qwen/Gemma review is advisory only and starts after all current PR workflows succeed for the exact head SHA. Missing, pending, skipped, cancelled, or failed required checks block review.
- A trusted controller outside the PR checkout must pin the base/head and diff hash, treat the diff as untrusted data, and revalidate the PR and CI after generation. Models receive no shell tools, credentials, or write access.
- Model output is not merge approval or a CI result. Keep results local unless publication is explicitly requested; never automatically approve, merge, deploy, or change storage/VPN state.

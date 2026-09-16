# Development rules

## Project objective

Linux Storage Manager is a safety-first terminal application for Linux storage administration. The primary interface is a TUI that works over SSH; a scriptable CLI uses the same core.

## Safety boundary

M0 is strictly read-only. Code merged during M0 must not modify partition tables, LVM metadata, filesystems, mounts, `/etc/fstab`, swap state, RAID metadata, encryption metadata, or block-device contents.

Future write support must follow: discovery -> normalized model -> immutable plan -> preflight -> metadata backup -> explicit confirmation -> execution -> verification.

Unsupported, incomplete, or ambiguous topology must fail closed.

## Implementation rules

- Rust is the implementation language.
- Prefer structured machine-readable output from Linux utilities; never parse human-formatted tables when a stable JSON/report format exists.
- Always request explicit columns from tools such as `lsblk`.
- Never build shell command strings from runtime values. Use `std::process::Command` with separate arguments.
- Discovery must work without root whenever the host tools permit it.
- Keep distribution-specific package management outside the storage core.
- Unit tests use recorded fixtures. Destructive integration tests, when introduced, may run only against disposable loop devices or disposable VMs.
- Keep repository text files UTF-8 and do not encode source/configuration files as base64.

## Git workflow

- Develop on feature branches.
- Open a pull request into the default branch.
- Do not merge into the default branch without explicit project-owner approval.
- CI must pass before requesting merge approval.

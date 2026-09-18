# Linux portability

Linux Storage Manager targets distribution-independent Linux administration,
not a Ubuntu-only product. Debian 12 is an explicit compatibility target.
Do not upgrade or replace a host's glibc to run this prototype.

## Distribution format

The Portable Linux workflow builds two native Rust 1.88 musl candidates:

- `storagemgr-linux-x86_64-musl.tar.gz`: x86_64 / amd64.
- `storagemgr-linux-aarch64-musl.tar.gz`: aarch64 / arm64.

Each artifact must pass a binary inspection rejecting PT_INTERP, DT_NEEDED and
versioned GLIBC symbols. Static PIE may legitimately contain PT_DYNAMIC; that
segment alone is not evidence of an external runtime dependency. The resulting
program does not require a host glibc or musl installation. Binaries are specific
to the CPU architecture. No `target-cpu=native` optimization is used.

## Evidence and limits

The workflow executes target-specific Rust tests, then tests the SAME release
binary in Debian 12, Ubuntu 22.04/24.04, Rocky Linux 9, AlmaLinux 9, Fedora 44 and Alpine 3.22 userlands.
Startup, CLI help, missing-tool reporting and refusal of `--apply` are checked.
A separate Debian 12 image installs distro-provided storage tools and exercises
unprivileged JSON collectors and blocked planning without access to host disks.
Containers have no host device bind mounts or privileged mode, run read-only,
without network during testing, and share the runner kernel. These checks are
NOT a substitute for distro-kernel VM tests, real disks, or interactive TUI tests.
Read the exact artifact's BUILD_INFO.txt and PORTABILITY.txt for executed evidence.
A successful Portable Linux workflow does not override a failure in ordinary CI.

Broad distribution support is the goal, not a claim that every historical Linux
kernel, CPU, minimal image and storage stack has been validated. Older kernels,
other architectures and distribution-specific storage-tool variants require
separate validation. The first GNU/Ubuntu artifact requiring GLIBC_2.39 remains
historical and is not the download to use on Debian 12.

## Run

Extract the matching archive into an empty directory, then:

```sh
sha256sum -c SHA256SUMS
chmod +x storagemgr
./storagemgr --help
./storagemgr capabilities
./storagemgr
```

Only use `sudo ./storagemgr` when additional discovery permissions are needed.
The prototype cannot apply changes. Static linkage does not bundle `lsblk`,
`findmnt`, `sfdisk`, LVM2 or filesystem utilities. Missing/incompatible tools or
incomplete evidence must not become approval to modify storage. Package
installation remains explicit and distribution-specific, outside storage core.

Primary reference: https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes

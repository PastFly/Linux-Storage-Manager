# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager. Default branch: master.
The owner made the repository public on 2026-09-18 so GitHub-hosted Actions can run.
Do not change visibility, billing, permissions or merge the default branch without
appropriate approval. Read AGENTS.md and docs/SAFETY.md before writing.

## Development boundary

- M0 remains unmerged PR #1.
- Continue on draft PR #2, feature/m1a-read-only-planner. It includes M0.
- No executor or apply command. Every preview remains dry_run=true/executable=false.
- M1A now supports TWO read-only preview profiles:
  1. mounted ext4/XFS on a normal public linear LV in a local complete single-PV VG,
     using existing free extents;
  2. mounted ext4/XFS directly on an ordinary partition with verified adjacent free
     space on DOS/MBR or GPT.
- Direct DOS logical-partition growth inside an extended container is still unsupported.
- Legacy explain is advisory. Strict plan previews perform their own fail-closed checks.

## Current validated evidence

Exact validated source before this documentation refresh:
cbcf838afa8d6f1432832c7313a0ca7c0a1329a6

CI #175 / run 35352595585:
- harness safety tests PASS;
- rustfmt PASS;
- Clippy with -D warnings PASS;
- Rust workspace tests PASS;
- loop integration PASS;
- matrix executes three repetitions and includes plain ext4 direct-partition preview,
  LVM/ext4 and LVM/XFS;
- strict before/after owned storage facts and sentinel checks remain enabled;
- cleanup completed.

Portable Linux #54 / run 35352595536:
- static musl x86_64 PASS;
- static musl aarch64 PASS;
- same binaries smoke-tested in Debian 12, Ubuntu 22.04, Ubuntu 24.04,
  Rocky Linux 9 and Alpine 3.22;
- Debian 12 collector probe PASS.

Artifacts for that exact head:
- x86_64: storagemgr-linux-x86_64-musl-35352595536
- aarch64: storagemgr-linux-aarch64-musl-35352595536

The user's live Debian 12 host srv-phpIPAM also validated the real DOS layout:
sda1 ext4 root + sda2 extended container + sda5 swap logical sibling.
explain / reported 1,047,552 bytes adjacent capacity and needs_underlying_resize.
TUI navigation, direct-partition analysis and key handling were exercised live.

## Planner behavior

LVM preview:
- requires all six collectors complete;
- requires verified PV/VG/LV/filesystem identities;
- single-PV public linear active LV only;
- ext4/XFS read-write mount only;
- freezes extent-rounded growth into the preview.

Direct-partition preview:
- requires lsblk, partition_tables, mounts, fstab and swap collectors complete;
- LVM collector may be unavailable;
- target must resolve to a mounted ext4/XFS partition;
- parent must be a disk or disposable loop device;
- sfdisk/lsblk sector/start/size evidence must agree;
- DOS/MBR extended containers are boundaries; logical partition growth inside them is
  intentionally unsupported;
- GPT requires authoritative usable LBA bounds;
- --max freezes verified adjacent capacity;
- an oversized sector-rounded request blocks with no steps.

Typed partition preview steps:
1. revalidate snapshot;
2. require partition-table metadata backup;
3. describe extending the partition end only;
4. describe filesystem growth;
5. rediscover and verify.

These are descriptions only. No subprocess or device I/O exists in lsm-planner.

## Integration readiness lesson

Fixture setup may briefly expose stable-looking but incomplete udev identities after
LVM/filesystem creation. The harness therefore waits for TWO equal owned-fixture
samples AND required PV/VG/LV/filesystem UUIDs before plan testing begins.
After the first plan command, no mismatch is retried or ignored.

Do not weaken planner identity requirements to make a test pass. Setup stabilization is
bounded and fail-closed; diagnostic timeout messages list missing identities.

## TUI state

The TUI is a two-pane dashboard with:
- Disks / Volumes / Swap / Mounts / Diagnostics / Plans;
- DOS extended containers rendered as containers;
- pseudo-filesystems hidden from the default Mounts view;
- integrated advisory Can Grow analysis;
- strict plan preview for LVM and direct partitions;
- safe size presets only; no key executes mutations.

Plans key compatibility:
- increase: =, +, ], PageDown;
- decrease: -, _, [, PageUp;
- only KeyEventKind::Press mutates state; Repeat/Release are ignored.

## Remaining gates before any executor work

- broader direct-partition fixtures: GPT/XFS and 4K logical sectors;
- filesystem feature/health/version preflight;
- concurrency and locking model;
- fresh runtime device identity immediately before mutation;
- verified backup policy and recovery drills;
- explicit owner approval for exact reviewed code before any M1B executor work.

No merge to master without explicit owner approval. Preserve Cargo.lock and use --locked.
Cache unchanged blob SHAs during one working context.

# Linux Storage Manager handoff

Repository: PastFly/Linux-Storage-Manager. Default branch: master.
The owner made the repository public on 2026-09-18 so GitHub-hosted Actions can run.
Do not change visibility, billing, permissions or merge the default branch without
appropriate approval. Read AGENTS.md and docs/SAFETY.md before writing.

## Development boundary

- M0 remains unmerged PR #1.
- Continue on draft PR #2, feature/m1a-read-only-planner. It includes M0.
- No executor or apply command exists.
- Strict planner previews remain dry_run=true/executable=false.
- A deliberate kernel-rescan control action now exists in the TUI:
  - lowercase r = repeat read-only discovery only;
  - uppercase R = write "1" only to the validated selected disk
    /sys/class/block/<kname>/device/rescan control, then repeat discovery.
  This updates the kernel's capacity view only. It does NOT edit partitions,
  filesystems, LVM, fstab or user data.
- No automatic rescan is hidden behind ordinary refresh.

## Current exact validated code

Exact validated code head:
d0480bc60ccb083e6a2c8ace690079ae7f5a3643

CI #229 / run 35380689951:
- harness safety tests PASS;
- rustfmt PASS;
- Clippy with -D warnings PASS;
- Rust workspace tests PASS;
- loop integration PASS.

Portable Linux #108 / run 35380689991:
- static musl x86_64 PASS;
- static musl aarch64 PASS;
- same binaries smoke-tested across Debian 12, Ubuntu 22.04, Ubuntu 24.04,
  Rocky Linux 9 and Alpine 3.22;
- Debian 12 collector probe PASS.

Artifacts:
- x86_64: storagemgr-linux-x86_64-musl-35380689991
- aarch64: storagemgr-linux-aarch64-musl-35380689991

The branch may contain documentation-only commits after that code head. Do not claim a
later code head is validated unless its own workflows have completed.

## Live Debian 12 evidence

Host: srv-phpIPAM.

Original DOS layout:
- /dev/sda1: ext4 root /
- /dev/sda2: DOS extended container
- /dev/sda5: active swap logical partition

Before VM-disk rescan:
- Linux reported /dev/sda = 10 GiB.

After the user increased the virtual disk and ran:
  echo 1 > /sys/class/block/sda/device/rescan

Linux reported:
- /dev/sda = 11 GiB;
- partitions unchanged;
- TUI correctly reported Size 11.0 GiB and Tail free 1.0 GiB.

Important topology fact:
- the new ~1 GiB tail is NOT directly adjacent to sda1;
- sda2/sda5 sit between root and the new tail;
- direct root growth still sees only the ~1023 KiB pre-extended gap.

This is expected topology behavior, not a stale discovery bug after kernel rescan.

## Planner profiles

### LVM

Strict preview supports:
- mounted read-write ext4/XFS;
- normal public linear active LV;
- complete local single-PV VG;
- existing free extents;
- verified PV/VG/LV/filesystem identities.

### Direct partition

Strict preview supports:
- mounted read-write ext4/XFS directly on a normal partition;
- DOS/MBR or GPT;
- authoritative lsblk+sfdisk sector/start/size agreement;
- verified directly adjacent free sectors;
- sector-aligned frozen growth;
- no moving partition starts;
- no DOS logical-partition growth inside an extended container.

## Disk-tail layout opportunity

Planner now exposes a request-independent LayoutOpportunity for a deliberately narrow
DOS case:
- target is a primary filesystem partition;
- exactly one extended container follows it;
- exactly one active Linux swap logical partition exists inside that container;
- no unrelated payload partition follows the target;
- disk has new raw tail capacity;
- equivalent swap capacity can be preserved.

The opportunity records:
- maximum target filesystem growth while preserving equivalent swap;
- disk-tail free bytes;
- current swap bytes;
- blocking devices;
- sector size.

A request that exceeds direct adjacent space may still return status=Blocked and
executable=false, plus a LayoutAlternative. This is intentional: the alternative is
advisory, not an executable plan.

For the live srv-phpIPAM 11 GiB layout, +1 GiB root growth is representable only by a
future migration such as:
1. verify swap is not needed for hibernation/resume;
2. backup partition/fstab/resume metadata;
3. prepare swap migration;
4. deactivate old swap;
5. remove the logical swap and extended container;
6. grow root by requested capacity plus room for equivalent swap;
7. grow ext4;
8. create/activate equivalent swapfile and update persistent config;
9. rediscover and verify.

M1A DOES NOT execute any of those steps.

The TUI growth selector merges:
- directly adjacent growth choices; and
- the largest proven layout-opportunity size.
Thus the live host exposes a +1 GiB advisory choice instead of hiding the new tail.

## Preflight model

Successful strict previews contain structured preflight checks.

Verified examples:
- collectors complete;
- no error-level diagnostics;
- one matching read-write mount;
- required operation tools available;
- partition geometry or LVM identities/capacity consistent.

Required before future execution:
- fresh runtime identity recheck;
- filesystem health/features/grow-support validation;
- exclusive operation lock;
- verified metadata backup;
- explicit approval of the exact fresh plan.

Blocked plans do not pretend these future execution gates passed.

## TUI state

Dashboard sections:
- Disks
- Volumes
- Swap
- Mounts
- Diagnostics
- Plans

Current UI:
- structured tables for devices/volumes/mounts/swap;
- structured Diagnostics list with Details panel;
- capabilities panel;
- responsive wide Plans view with Summary / Preflight / Plan steps;
- compact fallback on narrow terminals;
- DOS extended container rendered as a container;
- Tail free shown in disk Details;
- advisory Can Grow analysis;
- strict plan preview;
- Tail opportunity summary and detailed advisory layout alternative;
- contextual toolbar.

Key controls:
- navigation: arrows / Tab / 1-6;
- Plans size: PgUp/PgDn plus legacy +/-/[ ];
- r = discovery refresh;
- R = selected-disk kernel rescan + refresh;
- q/Esc = quit.
Only KeyEventKind::Press mutates state; Repeat/Release are ignored.

## Remaining gates before any executor work

- filesystem feature/health/version preflight;
- concurrency and locking design;
- fresh runtime device identity immediately before mutation;
- verified backup policy and recovery drills;
- explicit owner approval for exact reviewed code before any M1B executor work.

No merge to master without explicit owner approval. Preserve Cargo.lock and use --locked.
Cache unchanged blob SHAs during one working context.

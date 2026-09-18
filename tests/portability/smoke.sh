#!/bin/sh
# Run unprivileged in a read-only container, without any host device mounts.
set -eu
binary=/probe/storagemgr
"$binary" --version | grep '^storagemgr '
"$binary" --help > /tmp/lsm-help
"$binary" plan extend --help > /tmp/lsm-plan-help
grep -q capabilities /tmp/lsm-help
grep -q -- '--max' /tmp/lsm-plan-help
"$binary" capabilities > /tmp/lsm-capabilities
if "$binary" plan extend / --max --apply > /tmp/apply-out 2>/tmp/apply-err; then
  echo 'FAIL: --apply was accepted' >&2; exit 1
else
  test "$?" -eq 2
fi
# Missing utilities must not prevent program startup or imply storage support.
env PATH=/nonexistent "$binary" capabilities > /tmp/missing-tools
grep -Eq '^lsblk[[:space:]]+missing$' /tmp/missing-tools
if env PATH=/nonexistent "$binary" tree > /tmp/tree-out 2>/tmp/tree-err; then
  echo 'FAIL: discovery succeeded without lsblk' >&2; exit 1
else
  test "$?" -eq 1
fi
grep -q lsblk /tmp/tree-err
printf 'USERLAND_SMOKE_OK startup=pass missing-tools=fail-closed apply=rejected\n'

#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != --allow-disposable-vm-tests || $# != 2 || $(uname -s) != Linux || $(id -u) != 0 ]]; then
  echo 'Requires root and explicit --allow-disposable-vm-tests on a disposable Linux VM' >&2
  exit 2
fi
binary=$2
if [[ ${binary} != /* || ! -x ${binary} ]]; then
  echo 'An absolute executable storagemgr path is required' >&2
  exit 2
fi
root=$(mktemp -d)
trap 'rm -f -- "${root}/lsblk" "${root}/executed"; rmdir -- "${root}"' EXIT
cat > "${root}/lsblk" <<'EOF'
#!/bin/sh
printf injected > "$LSM_TEST_MARKER"
printf '{"blockdevices":[]}'
EOF
chmod 755 "${root}/lsblk"
PATH="${root}:/usr/sbin:/usr/bin:/sbin:/bin" LSM_TEST_MARKER="${root}/executed" \
  "${binary}" json > /dev/null
if [[ -e ${root}/executed ]]; then
  echo 'Untrusted lsblk from PATH was executed by root discovery' >&2
  exit 1
fi
echo 'TRUSTED_DISCOVERY_PATH_OK'

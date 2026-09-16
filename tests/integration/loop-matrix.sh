#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "loop integration matrix must run as root" >&2
  exit 2
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BIN=${1:-"${REPO_ROOT}/target/debug/storagemgr"}

if [[ ! -x ${BIN} ]]; then
  echo "storagemgr binary not found or not executable: ${BIN}" >&2
  exit 2
fi

for command in losetup sfdisk partx mkfs.ext4 pvcreate vgcreate lvcreate vgremove jq mount mountpoint umount; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required integration command is missing: ${command}" >&2
    exit 2
  fi
done

TMP_ROOT=$(mktemp -d -t lsm-loop-matrix.XXXXXX)
declare -a LOOPS=()
declare -a MOUNTS=()
declare -a VGS=()
CREATED_LOOP=""

cleanup() {
  set +e
  local mount_path
  local vg
  local loop
  for mount_path in "${MOUNTS[@]}"; do
    mountpoint -q "${mount_path}" && umount "${mount_path}"
  done
  for vg in "${VGS[@]}"; do
    vgremove -ff -y "${vg}" >/dev/null 2>&1 || true
  done
  for loop in "${LOOPS[@]}"; do
    losetup -d "${loop}" >/dev/null 2>&1 || true
  done
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

wait_for_block() {
  local path=$1
  local attempt
  for attempt in $(seq 1 50); do
    if [[ -b ${path} ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "block device did not appear: ${path}" >&2
  return 1
}

create_loop() {
  local image=$1
  local size=$2
  truncate -s "${size}" "${image}"
  CREATED_LOOP=$(losetup --find --show --partscan "${image}")
  LOOPS+=("${CREATED_LOOP}")
}

refresh_partitions() {
  local loop=$1
  partx -u "${loop}" >/dev/null 2>&1 || true
  command -v udevadm >/dev/null 2>&1 && udevadm settle || true
}

assert_no_error_for_prefix() {
  local diagnostics=$1
  local prefix=$2
  if jq -e --arg prefix "${prefix}" '
      .[]
      | select(.severity == "error")
      | select((.device // "") | startswith($prefix))
    ' <<<"${diagnostics}" >/dev/null; then
    echo "unexpected error diagnostic for ${prefix}" >&2
    jq --arg prefix "${prefix}" '.[] | select((.device // "") | startswith($prefix))' \
      <<<"${diagnostics}" >&2
    return 1
  fi
}

echo "==> Case 1: GPT -> ext4 partition"
PLAIN_IMAGE="${TMP_ROOT}/plain.img"
create_loop "${PLAIN_IMAGE}" 256M
PLAIN_LOOP=${CREATED_LOOP}
printf 'label: gpt\n,128M\n' | sfdisk "${PLAIN_LOOP}" >/dev/null
refresh_partitions "${PLAIN_LOOP}"
PLAIN_PART="${PLAIN_LOOP}p1"
wait_for_block "${PLAIN_PART}"
mkfs.ext4 -F -q "${PLAIN_PART}"
PLAIN_MOUNT="${TMP_ROOT}/plain-mount"
mkdir -p "${PLAIN_MOUNT}"
mount "${PLAIN_PART}" "${PLAIN_MOUNT}"
MOUNTS+=("${PLAIN_MOUNT}")

SNAPSHOT=$(${BIN} snapshot)
jq -e --arg device "${PLAIN_LOOP}" '.partition_tables[] | select(.device == $device)' \
  <<<"${SNAPSHOT}" >/dev/null
jq -e --arg target "${PLAIN_MOUNT}" '.mounts[] | select(.target == $target and .fs_type == "ext4")' \
  <<<"${SNAPSHOT}" >/dev/null
DIAGNOSTICS=$(${BIN} diagnose)
assert_no_error_for_prefix "${DIAGNOSTICS}" "${PLAIN_LOOP}"

echo "==> Case 2: GPT -> LVM PV/VG/LV -> ext4"
LVM_IMAGE="${TMP_ROOT}/lvm.img"
create_loop "${LVM_IMAGE}" 768M
LVM_LOOP=${CREATED_LOOP}
printf 'label: gpt\n,640M\n' | sfdisk "${LVM_LOOP}" >/dev/null
refresh_partitions "${LVM_LOOP}"
LVM_PART="${LVM_LOOP}p1"
wait_for_block "${LVM_PART}"

VG="lsmtest${RANDOM}$$"
VGS+=("${VG}")
pvcreate -ff -y "${LVM_PART}" >/dev/null
vgcreate "${VG}" "${LVM_PART}" >/dev/null
lvcreate -L 256M -n root "${VG}" >/dev/null
command -v udevadm >/dev/null 2>&1 && udevadm settle || true
LV="/dev/${VG}/root"
wait_for_block "${LV}"
mkfs.ext4 -F -q "${LV}"
LVM_MOUNT="${TMP_ROOT}/lvm-mount"
mkdir -p "${LVM_MOUNT}"
mount "${LV}" "${LVM_MOUNT}"
MOUNTS+=("${LVM_MOUNT}")

SNAPSHOT=$(${BIN} snapshot)
jq -e --arg vg "${VG}" '.lvm.volume_groups[] | select(.name == $vg and .free_bytes > 0)' \
  <<<"${SNAPSHOT}" >/dev/null
jq -e --arg target "${LVM_MOUNT}" '.mounts[] | select(.target == $target and .fs_type == "ext4")' \
  <<<"${SNAPSHOT}" >/dev/null
ANALYSIS=$(${BIN} explain "${LVM_MOUNT}")
jq -e '.status == "ready" and .immediate_growth_bytes > 0' <<<"${ANALYSIS}" >/dev/null
DIAGNOSTICS=$(${BIN} diagnose)
assert_no_error_for_prefix "${DIAGNOSTICS}" "${LVM_LOOP}"

echo "LOOP_MATRIX_OK plain=${PLAIN_LOOP} lvm=${LVM_LOOP} vg=${VG}"

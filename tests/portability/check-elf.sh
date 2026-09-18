#!/usr/bin/env bash
# Inspect, but never execute, a candidate binary. Static PIE may have PT_DYNAMIC.
set -euo pipefail
export LC_ALL=C
[[ $# == 2 ]] || { echo 'Usage: check-elf.sh BINARY x86_64|aarch64' >&2; exit 2; }
binary=$1
case $2 in
  x86_64) machine='Advanced Micro Devices X86-64' ;;
  aarch64) machine='AArch64' ;;
  *) echo 'Unsupported architecture' >&2; exit 2 ;;
esac
[[ -f $binary && ! -L $binary ]] || { echo 'Regular binary required' >&2; exit 2; }
header=$(readelf -hW "$binary")
programs=$(readelf -lW "$binary")
dynamic=$(readelf -dW "$binary")
versions=$(readelf --version-info -W "$binary")
[[ $header == *ELF64* && $header == *"Machine:"*"$machine"* ]] || {
  echo 'PORTABILITY_FAILED: wrong ELF class/architecture' >&2; exit 1;
}
if grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)' <<< "$programs"; then
  echo 'PORTABILITY_FAILED: binary requires a dynamic loader' >&2; exit 1
fi
if grep -q '(NEEDED)' <<< "$dynamic"; then
  echo 'PORTABILITY_FAILED: shared library dependency' >&2; exit 1
fi
if grep -q 'GLIBC_' <<< "$versions"; then
  echo 'PORTABILITY_FAILED: versioned glibc dependency' >&2; exit 1
fi
printf 'STATIC_ELF_OK arch=%s interpreter=none shared-libraries=none glibc-symbols=none\n' "$2"

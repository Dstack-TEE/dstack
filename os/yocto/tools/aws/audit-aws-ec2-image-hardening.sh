#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  audit-aws-ec2-image-hardening.sh --kernel-config PATH --rootfs-manifest PATH [--rootfs-squashfs PATH]

Checks a dstack AWS EC2 release image for the hardening properties that are
independent of a live EC2 boot:
  - required NitroTPM / measured-root boot kernel features
  - forbidden remote-operator packages in the production rootfs manifest
  - locked root account and inert SSH/getty units when a squashfs is supplied

The script exits non-zero only for release blockers. It prints WARN lines for
hardening opportunities that should be tracked but are not part of the minimum
measurement and key-release chain.
USAGE
}

kernel_config=
rootfs_manifest=
rootfs_squashfs=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --kernel-config)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --kernel-config requires a path" >&2
        usage
        exit 2
      fi
      kernel_config=${2:-}
      shift 2
      ;;
    --rootfs-manifest)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --rootfs-manifest requires a path" >&2
        usage
        exit 2
      fi
      rootfs_manifest=${2:-}
      shift 2
      ;;
    --rootfs-squashfs)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --rootfs-squashfs requires a path" >&2
        usage
        exit 2
      fi
      rootfs_squashfs=${2:-}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "$kernel_config" ] || [ -z "$rootfs_manifest" ]; then
  usage
  exit 2
fi

if [ ! -f "$kernel_config" ]; then
  echo "ERROR: kernel config not found: $kernel_config" >&2
  exit 2
fi

if [ ! -f "$rootfs_manifest" ]; then
  echo "ERROR: rootfs manifest not found: $rootfs_manifest" >&2
  exit 2
fi

failures=0
warnings=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

warn() {
  echo "WARN: $*" >&2
  warnings=$((warnings + 1))
}

pass() {
  echo "PASS: $*"
}

config_value() {
  local symbol=$1
  if grep -qx "${symbol}=y" "$kernel_config"; then
    printf 'y'
  elif grep -qx "${symbol}=m" "$kernel_config"; then
    printf 'm'
  elif grep -qx "# ${symbol} is not set" "$kernel_config"; then
    printf 'n'
  else
    printf 'missing'
  fi
}

require_config() {
  local symbol=$1 expected=$2 actual
  actual=$(config_value "$symbol")
  if [ "$actual" = "$expected" ]; then
    pass "$symbol=$expected"
  else
    fail "$symbol expected $expected, got $actual"
  fi
}

recommend_config() {
  local symbol=$1 expected=$2 actual
  actual=$(config_value "$symbol")
  if [ "$actual" = "$expected" ]; then
    pass "$symbol=$expected"
  else
    warn "$symbol recommended $expected, got $actual"
  fi
}

echo "== Kernel required features =="
require_config CONFIG_EFI y
require_config CONFIG_EFI_STUB y
require_config CONFIG_EFI_PARTITION y
require_config CONFIG_TCG_TPM y
require_config CONFIG_TCG_CRB y
require_config CONFIG_BLK_DEV_DM y
require_config CONFIG_DM_VERITY y
require_config CONFIG_SQUASHFS y
require_config CONFIG_RANDOMIZE_BASE y
require_config CONFIG_STACKPROTECTOR_STRONG y
require_config CONFIG_SECCOMP y
require_config CONFIG_SECCOMP_FILTER y
require_config CONFIG_STRICT_DEVMEM y
require_config CONFIG_KEXEC n
require_config CONFIG_HIBERNATION n
require_config CONFIG_DEBUG_FS n

echo "== Kernel hardening recommendations =="
recommend_config CONFIG_SECURITY_DMESG_RESTRICT y
recommend_config CONFIG_IO_STRICT_DEVMEM y
recommend_config CONFIG_INIT_ON_ALLOC_DEFAULT_ON y
recommend_config CONFIG_INIT_ON_FREE_DEFAULT_ON y
recommend_config CONFIG_SLAB_FREELIST_RANDOM y
recommend_config CONFIG_SLAB_FREELIST_HARDENED y
recommend_config CONFIG_HARDENED_USERCOPY y
recommend_config CONFIG_FORTIFY_SOURCE y
recommend_config CONFIG_MAGIC_SYSRQ n
recommend_config CONFIG_LEGACY_TIOCSTI n

echo "== Rootfs forbidden package scan =="
for pattern in \
  '^openssh([[:space:]-]|$)' \
  '^dropbear([[:space:]-]|$)' \
  '^cloud-init([[:space:]-]|$)' \
  '^amazon-ssm-agent([[:space:]-]|$)' \
  '^ssm-agent([[:space:]-]|$)' \
  '^ec2-instance-connect([[:space:]-]|$)'
do
  if grep -Eiq "$pattern" "$rootfs_manifest"; then
    fail "rootfs manifest contains forbidden package pattern: $pattern"
  else
    pass "absent package pattern: $pattern"
  fi
done

if [ -n "$rootfs_squashfs" ]; then
  if [ ! -f "$rootfs_squashfs" ]; then
    fail "rootfs squashfs not found: $rootfs_squashfs"
  elif ! command -v unsquashfs >/dev/null 2>&1; then
    # A squashfs was supplied, so the caller expects the rootfs content checks
    # to run; a missing tool must not silently pass the audit (fail-closed).
    fail "unsquashfs not available; cannot run rootfs content checks (install squashfs-tools)"
  else
    echo "== Rootfs account and unit checks =="
    shadow=$(unsquashfs -cat "$rootfs_squashfs" etc/shadow 2>/dev/null || true)
    if printf '%s\n' "$shadow" | grep -Eq '^root:[!*]:'; then
      pass "root account is locked in /etc/shadow"
    else
      fail "root account is not locked in /etc/shadow"
    fi

    if unsquashfs -ll "$rootfs_squashfs" 2>/dev/null |
      grep -Eq 'squashfs-root/etc/systemd/system/.+\.wants/.+(ssh|sshd|getty|serial|cloud|ssm|ec2)'
    then
      fail "rootfs enables SSH/getty/cloud/SSM/EC2 unit symlinks"
    else
      pass "no enabled SSH/getty/cloud/SSM/EC2 unit symlinks"
    fi

    if unsquashfs -ll "$rootfs_squashfs" 2>/dev/null |
      grep -Eq 'squashfs-root/(usr/)?sbin/(sshd|dropbear)$'
    then
      fail "rootfs contains sshd/dropbear server binary"
    else
      pass "no sshd/dropbear server binary"
    fi
  fi
fi

echo "== Summary =="
echo "failures=$failures warnings=$warnings"

if [ "$failures" -ne 0 ]; then
  exit 1
fi

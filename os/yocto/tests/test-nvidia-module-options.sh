#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Exercise nvidia-module-options against synthetic GPU topologies.
#
# The interesting behaviour only shows up on hardware nobody has on a laptop --
# a Hopper box with NVSwitches passed through, a Blackwell tenant with eight
# GPUs and none. So the PCI topology is faked instead: a directory of
# vendor/class files is bind-mounted over /sys/bus/pci/devices inside a mount
# namespace, and the scripts run from their installed paths with no environment
# overrides at all. That exercises the same code the image runs, including the
# hardcoded /usr/bin/nvidia-gpu-detect and /run/modprobe.d.
#
# Where user namespaces are unavailable the same matrix runs through the
# NVIDIA_PCI_DEVICES / NVIDIA_GPU_DETECT / NVIDIA_MODPROBE_DIR overrides. That
# still covers the decision logic, just not the path wiring.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
files=$here/../layers/meta-nvidia/recipes-graphics/nvidia/files
detect=$files/nvidia-gpu-detect
generate=$files/nvidia-module-options
unit=$files/nvidia-module-options.service

for f in "$detect" "$generate" "$unit"; do
    [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

# make_tree <dir> <gpus> <nvswitches> [extra-vendor:class ...]
#
# Class codes match what the kernel exposes in sysfs: 0x0302xx is a 3D
# controller, 0x0300xx a VGA device, 0x06xxxx a bridge. Both GPU classes appear
# on real cards, so the count has to accept either.
make_tree() {
    local dir=$1 gpus=$2 switches=$3 i dev
    shift 3
    mkdir -p "$dir"
    for ((i = 0; i < gpus; i++)); do
        dev=$dir/0000:$(printf '%02x' $((i + 1))):00.0
        mkdir -p "$dev"
        printf '0x10de\n' >"$dev/vendor"
        printf '0x030200\n' >"$dev/class"
    done
    for ((i = 0; i < switches; i++)); do
        dev=$dir/0000:$(printf '%02x' $((i + 128))):00.0
        mkdir -p "$dev"
        printf '0x10de\n' >"$dev/vendor"
        printf '0x068000\n' >"$dev/class"
    done
    for spec in "$@"; do
        dev=$dir/0000:$(printf '%02x' $((RANDOM % 200 + 32))):00.0
        mkdir -p "$dev"
        printf '0x%s\n' "${spec%%:*}" >"$dev/vendor"
        printf '0x%s\n' "${spec##*:}" >"$dev/class"
    done
}

have_userns() {
    unshare -Urm true >/dev/null 2>&1
}

upper=$tmp/upper
work=$tmp/work
mkdir -p "$upper" "$work"
install -m 0755 "$detect" "$upper/nvidia-gpu-detect"
install -m 0755 "$generate" "$upper/nvidia-module-options"

# in_namespace <sysfs-dir>: run the installed generator against a faked PCI tree
# and print the options lines it produced.
#
# /run is a fresh tmpfs so the generator has to create /run/modprobe.d itself,
# the way it does on a real boot. overlayfs keeps the rest of /usr/bin visible,
# so the namespace still has a working shell and modprobe.
in_namespace() {
    unshare -Urm --map-root-user sh -c "
        set -e
        mount --bind '$1' /sys/bus/pci/devices
        mount -t tmpfs none /run
        mount -t overlay overlay \
            -o lowerdir=/usr/bin,upperdir='$upper',workdir='$work' /usr/bin
        /usr/bin/nvidia-module-options >/dev/null
        grep '^options' /run/modprobe.d/nvidia-dstack.conf || true
    "
}

# Probe the namespace path on a known tree rather than trusting that unshare and
# overlayfs are both usable here.
mode="mount namespace, installed paths, no overrides"
probe=$tmp/probe
mkdir -p "$probe/0000:01:00.0"
printf '0x10de\n' >"$probe/0000:01:00.0/vendor"
printf '0x030200\n' >"$probe/0000:01:00.0/class"
if [ "$(in_namespace "$probe" 2>/dev/null)" != 'options nvidia NVreg_NvLinkDisable=1' ]; then
    mode="environment overrides (namespace or overlayfs unavailable)"
fi

# run_generator <sysfs-dir> <output-dir>: emit the generated options lines.
run_generator() {
    local sysfs=$1 out=$2
    case $mode in
    "mount namespace"*)
        in_namespace "$sysfs"
        ;;
    *)
        mkdir -p "$out"
        NVIDIA_PCI_DEVICES=$sysfs \
        NVIDIA_GPU_DETECT=$detect \
        NVIDIA_MODPROBE_DIR=$out \
            "$generate" >/dev/null
        grep '^options' "$out/nvidia-dstack.conf" 2>/dev/null || true
        ;;
    esac
}

# check <name> <expected> <gpus> <switches> [extra ...]
check() {
    local name=$1 expected=$2 gpus=$3 switches=$4
    shift 4
    local dir=$tmp/tree.$((++case_no)) out=$tmp/out.$case_no actual
    make_tree "$dir" "$gpus" "$switches" "$@"
    actual=$(run_generator "$dir" "$out")
    if [ "$actual" = "$expected" ]; then
        printf 'ok   %s\n' "$name"
    else
        printf 'FAIL %s\n       want: %s\n       got:  %s\n' \
            "$name" "${expected:-<none>}" "${actual:-<none>}" >&2
        failures=$((failures + 1))
    fi
}

case_no=0
ppcie='options nvidia NVreg_RegistryDwords="RmEnableProtectedPcie=0x1"'
nvlink_off='options nvidia NVreg_NvLinkDisable=1'

echo "topology matrix ($mode)"
# A GPU-less host runs the same image and must stay clean.
check 'no NVIDIA device'                    ''            0 0 '1af4:010000'
# Single-GPU tenant: no fabric to wait for, so the probe must be short circuited.
check '1 GPU, no NVSwitch'                  "$nvlink_off" 1 0
# Blackwell MPT CC: Fabric Manager is on the host and NVLink must stay up.
check '2 GPUs, no NVSwitch'                 ''            2 0
check '8 GPUs, no NVSwitch'                 ''            8 0
# Hopper PPCIe is the only shape where the guest is handed NVSwitches.
check '8 GPUs + 4 NVSwitch'                 "$ppcie"      8 4
check '2 GPUs + 1 NVSwitch'                 "$ppcie"      2 1
# A lone GPU behind a switch is still PPCIe, and must not get NvLinkDisable.
check '1 GPU + 1 NVSwitch'                  "$ppcie"      1 1
# Foreign devices must not be mistaken for GPUs or NVSwitches.
check '1 GPU + Intel bridge'                "$nvlink_off" 1 0 '8086:060400'
check '1 GPU + non-NVIDIA 3D controller'    "$nvlink_off" 1 0 '1002:030200'

# A VGA-class NVIDIA device counts as a GPU too, so a VGA + 3D pair is two GPUs
# and must not be treated as the single-GPU case.
dir=$tmp/tree.vga out=$tmp/out.vga
mkdir -p "$dir/0000:01:00.0" "$dir/0000:02:00.0"
printf '0x10de\n' >"$dir/0000:01:00.0/vendor"; printf '0x030000\n' >"$dir/0000:01:00.0/class"
printf '0x10de\n' >"$dir/0000:02:00.0/vendor"; printf '0x030200\n' >"$dir/0000:02:00.0/class"
actual=$(run_generator "$dir" "$out")
if [ -z "$actual" ]; then
    echo 'ok   1 VGA + 1 3D controller counts as 2 GPUs'
else
    printf 'FAIL 1 VGA + 1 3D controller counts as 2 GPUs\n       got: %s\n' "$actual" >&2
    failures=$((failures + 1))
fi

# The generated file is only useful if modprobe actually reads /run/modprobe.d.
# kmod's search path is a compile-time list, so assert it rather than assume it.
echo
echo 'modprobe integration'
if command -v modprobe >/dev/null && have_userns; then
    got=$(unshare -Urm --map-root-user sh -c '
        mount -t tmpfs none /run
        mkdir -p /run/modprobe.d
        printf "options nvidia NVreg_TestSentinel=1\n" >/run/modprobe.d/nvidia-dstack.conf
        modprobe --showconfig 2>/dev/null | grep -F "NVreg_TestSentinel=1" || true
    ')
    if [ -n "$got" ]; then
        echo 'ok   modprobe honours /run/modprobe.d'
    else
        echo 'FAIL modprobe did not pick up /run/modprobe.d' >&2
        failures=$((failures + 1))
    fi
else
    echo 'skip modprobe or user namespaces unavailable'
fi

# Options written after the driver has loaded are ignored, so the generator has
# to precede every load site. There are two kinds. udev coldplug is the early
# one and the easiest to forget: nvidia.ko carries PCI aliases and systemd's
# 80-drivers.rules loads modules by MODALIAS, so the driver comes up during
# systemd-udev-trigger.service. The explicit modprobe calls in the NVIDIA units
# are the late one. A load site missing from Before= races the generator and the
# tenant silently gets the wrong options.
echo
echo 'module load sites'
ordered=$(sed -n 's/^Before=//p' "$unit" | tr ' ' '\n' | sed '/^$/d' | sort)
loaders=$({
    echo systemd-udev-trigger.service
    grep -rl 'modprobe nvidia' "$files" | xargs -r -n1 basename |
        sed 's/^nvidia-fabricmanager-nvswitch-condition\.conf$/nvidia-fabricmanager.service/'
} | sort -u)
if [ "$ordered" = "$loaders" ]; then
    echo 'ok   every load site is ordered after the generator'
else
    printf 'FAIL Before= does not cover all module load sites\n       Before=: %s\n       expected: %s\n' \
        "$(echo "$ordered" | tr '\n' ' ')" "$(echo "$loaders" | tr '\n' ' ')" >&2
    failures=$((failures + 1))
fi

# Ordering ahead of udev coldplug is only reachable from early boot. Dropping
# either of these would leave Before=systemd-udev-trigger.service unsatisfiable
# and put the generator back after the driver has already loaded.
for required in 'DefaultDependencies=no' 'WantedBy=sysinit.target'; do
    if grep -qxF "$required" "$unit"; then
        echo "ok   unit keeps $required"
    else
        echo "FAIL unit is missing $required, so it cannot precede udev coldplug" >&2
        failures=$((failures + 1))
    fi
done

echo
if [ "$failures" -eq 0 ]; then
    echo 'all checks passed'
else
    echo "$failures check(s) failed" >&2
    exit 1
fi

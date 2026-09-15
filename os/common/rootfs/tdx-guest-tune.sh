#!/bin/sh
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Runtime scaling policy for many-vCPU TDX guests (dstack kernel with
# tdx_wake_q_batch, tdx_pv_single_ipi and CONFIG_HALTPOLL_CPUIDLE=m).
#
# Experimental helper that may be removed from future images; the stable
# interface is the kernel switches it sets. See docs/tdx-guest-scaling.md.
#
# Usage: /usr/lib/dstack/tdx-guest-tune.sh [throughput|default|off|status] [options]
#   throughput  guest halt polling + wake-queue IPI batching (highest throughput,
#               extra CPU while idle-polling; for vCPUs that are not overcommitted)
#   default     kernel defaults: no guest polling, wake-queue batching and PV
#               single-target IPIs on ("nopoll" is accepted as an alias)
#   off         all switches off and polling module unloaded (pre-patch behavior)
#   status      print the current state
# Options:
#   --poll-us N       guest halt-poll window in microseconds (default: by vCPU count)
#   --pv-single Y|N   override tdx_pv_single_ipi for the selected profile
#   --force           apply even if this is not a TDX guest
# Environment: TDX_TUNE_PROFILE, TDX_TUNE_POLL_US, TDX_TUNE_PV_SINGLE.
set -eu

KP=/sys/module/kernel/parameters
HP=/sys/module/haltpoll/parameters
IDLE=/sys/devices/system/cpu/cpuidle

profile=${TDX_TUNE_PROFILE:-throughput}
[ "$profile" = nopoll ] && profile=default
poll_us=${TDX_TUNE_POLL_US:-}
pv_single=${TDX_TUNE_PV_SINGLE:-}
force=0

log() { echo "tdx-guest-tune: $*"; }
die() { echo "tdx-guest-tune: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case $1 in
        throughput|default|off|status) profile=$1 ;;
        nopoll) profile=default ;;
        --poll-us) [ $# -ge 2 ] || die "--poll-us needs a value"; poll_us=$2; shift ;;
        --pv-single) [ $# -ge 2 ] || die "--pv-single needs Y or N"; pv_single=$2; shift ;;
        --force) force=1 ;;
        -h|--help) sed -n '12,23p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

readf() { cat "$1" 2>/dev/null || echo "-"; }

status() {
    driver=$(readf "$IDLE/current_driver")
    governor=$(readf "$IDLE/current_governor")
    loaded=no
    grep -q '^cpuidle_haltpoll ' /proc/modules 2>/dev/null && loaded=yes
    log "vcpus=$(nproc) tdx_guest=$(is_tdx && echo yes || echo no) idle_driver=$driver governor=$governor haltpoll_module=$loaded"
    log "guest_halt_poll_ns=$(readf "$HP/guest_halt_poll_ns") allow_shrink=$(readf "$HP/guest_halt_poll_allow_shrink") grow_start=$(readf "$HP/guest_halt_poll_grow_start")"
    log "tdx_wake_q_batch=$(readf "$KP/tdx_wake_q_batch") tdx_pv_single_ipi=$(readf "$KP/tdx_pv_single_ipi")"
}

is_tdx() {
    [ -e /dev/tdx_guest ] || grep -qw tdx_guest /proc/cpuinfo 2>/dev/null
}

write() { # write FILE VALUE
    [ -w "$1" ] || die "missing or read-only: $1 (kernel without the dstack TDX knobs?)"
    printf '%s\n' "$2" > "$1"
}

# Window derived from measurements: 32 vCPUs -> 200 us, 248 vCPUs -> 4 ms.
# Both are ~20-25x the TD exit round trip seen under that vCPU concurrency
# (about 9 us and 170 us); intermediate steps are interpolated, not measured.
default_poll_us() {
    n=$(nproc)
    if [ "$n" -le 32 ]; then echo 200
    elif [ "$n" -le 64 ]; then echo 500
    elif [ "$n" -le 128 ]; then echo 1000
    else echo 4000
    fi
}

# Enable guest halt polling with a fixed, non-shrinking window.
enable_polling() {
    ns=$(( $1 * 1000 ))
    # Clamp any previously grown per-CPU limit: allow shrinking to zero on the
    # next long idle, then set the new window before disabling shrink again.
    write "$HP/guest_halt_poll_allow_shrink" Y
    write "$HP/guest_halt_poll_shrink" 0
    write "$HP/guest_halt_poll_ns" 1000
    sleep 1
    write "$HP/guest_halt_poll_shrink" 2
    write "$HP/guest_halt_poll_grow_start" "$ns"
    write "$HP/guest_halt_poll_ns" "$ns"
    write "$HP/guest_halt_poll_allow_shrink" N
    if [ "$(readf "$IDLE/current_driver")" != haltpoll ]; then
        modprobe cpuidle_haltpoll force=1 ||
            die "cannot load cpuidle_haltpoll (image without CONFIG_HALTPOLL_CPUIDLE=m?)"
    fi
}

# Restore the haltpoll governor parameters to their kernel defaults.
reset_polling() {
    write "$HP/guest_halt_poll_allow_shrink" Y
    write "$HP/guest_halt_poll_grow_start" 50000
    write "$HP/guest_halt_poll_ns" 200000
}

disable_polling() {
    if grep -q '^cpuidle_haltpoll ' /proc/modules 2>/dev/null; then
        rmmod cpuidle_haltpoll
    elif [ "$(readf "$IDLE/current_driver")" = haltpoll ]; then
        log "warning: haltpoll is built in or bound at boot; only shortening its window"
        write "$HP/guest_halt_poll_allow_shrink" Y
        write "$HP/guest_halt_poll_ns" 50000
    fi
}

case $profile in
    status) status; exit 0 ;;
    throughput|default|off) ;;
    *) die "unknown profile: $profile" ;;
esac

[ "$(id -u)" -eq 0 ] || die "must run as root"
if ! is_tdx && [ "$force" -ne 1 ]; then
    die "not a TDX guest; use --force to apply anyway"
fi
case ${pv_single:-} in ""|Y|N) ;; *) die "--pv-single must be Y or N" ;; esac
case ${poll_us:-} in ""|*[!0-9]*) [ -z "${poll_us:-}" ] || die "--poll-us must be an integer" ;; esac

case $profile in
    throughput)
        [ -n "${poll_us:-}" ] || poll_us=$(default_poll_us)
        enable_polling "$poll_us"
        write "$KP/tdx_wake_q_batch" Y
        # With polling and batching, PV single-target IPIs measured -5%..+5%.
        write "$KP/tdx_pv_single_ipi" "${pv_single:-N}"
        ;;
    default)
        disable_polling
        reset_polling
        write "$KP/tdx_wake_q_batch" Y
        # Without polling most wakeups need an IPI; PV single IPIs measured +10%..+32%.
        write "$KP/tdx_pv_single_ipi" "${pv_single:-Y}"
        ;;
    off)
        disable_polling
        reset_polling
        write "$KP/tdx_wake_q_batch" N
        write "$KP/tdx_pv_single_ipi" "${pv_single:-N}"
        ;;
esac
log "applied profile: $profile"
status

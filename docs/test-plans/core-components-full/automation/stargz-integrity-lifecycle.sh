#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
PAYLOAD_IMAGE=${1:?payload image}
PAYLOAD_ID=${2:?payload image id}
REGISTRY_IMAGE=${3:?registry image}
REGISTRY_ID=${4:?registry archive image id}
UNIT=${5:?snapshotter unit}
SNAPSHOTTER=${6:?snapshotter name}
ROOT=/run/dstack-test-stargz
SNAPSHOTTER_ROOT=/var/lib/containerd-stargz-grpc
SNAPSHOTTER_STORAGE=/dstack/persistent/var/lib/containerd-stargz-grpc
REGISTRY=dstack-stargz-registry
NORMAL=127.0.0.1:5000/dstack/busybox:normal
LAZY=127.0.0.1:5000/dstack/busybox:estargz
CORRUPT_NORMAL=127.0.0.1:5000/dstack/busybox:corrupt-source
CORRUPT_LAZY=127.0.0.1:5000/dstack/busybox:corrupt-estargz
NS=dstargz-main
BASELINE_NS=dstargz-overlay
CONCURRENT_A=dstargz-concurrent-a
CONCURRENT_B=dstargz-concurrent-b
CORRUPT_NS=dstargz-corrupt
STOPPED_NS=dstargz-stopped
checks=0
unit_override=false

check() { "$@"; checks=$((checks + 1)); }
clear_snapshotter_state() {
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  { findmnt -Rno TARGET "$SNAPSHOTTER_ROOT" 2>/dev/null || true; } \
    | sort -r \
    | while IFS= read -r target; do
        test "$target" = "$SNAPSHOTTER_ROOT" && continue
        umount -l -- "$target" >/dev/null 2>&1 || true
      done
  rm -rf "${SNAPSHOTTER_ROOT:?}"/* /run/containerd-stargz-grpc
}
prepare_snapshotter_storage() {
  mkdir -p "$SNAPSHOTTER_ROOT" "$SNAPSHOTTER_STORAGE"
  if ! mountpoint -q "$SNAPSHOTTER_ROOT"; then
    mount --bind "$SNAPSHOTTER_STORAGE" "$SNAPSHOTTER_ROOT"
  fi
}
failure_diagnostics() {
  rc=$?
  printf 'stargz lifecycle failed: line=%s rc=%s checks=%s\n' "$1" "$rc" "$checks" >&2
  for log in "$ROOT"/*.log; do
    test -f "$log" || continue
    printf '%s\n' "--- ${log##*/} ---" >&2
    tail -n 40 "$log" >&2
  done
  return "$rc"
}
trap 'failure_diagnostics "$LINENO"' ERR
wait_snapshotter() {
  for _ in $(seq 1 50); do
    if systemctl is-active --quiet "$UNIT" && ctr-remote -n "$NS" snapshots --snapshotter "$SNAPSHOTTER" ls >/dev/null 2>&1; then
      sleep 0.25
      systemctl is-active --quiet "$UNIT" && return 0
    fi
    sleep 0.1
  done
  return 1
}
# shellcheck disable=SC2317
cleanup() {
  set +e
  docker rm -f "$REGISTRY" stargz-corrupt-source >/dev/null 2>&1 || true
  for ns in "$NS" "$BASELINE_NS" "$CONCURRENT_A" "$CONCURRENT_B" "$CORRUPT_NS" "$STOPPED_NS"; do
    ctr-remote -n "$ns" containers ls -q 2>/dev/null | xargs -r -n1 ctr-remote -n "$ns" containers rm >/dev/null 2>&1 || true
    ctr-remote -n "$ns" images ls -q 2>/dev/null | xargs -r ctr-remote -n "$ns" images rm >/dev/null 2>&1 || true
    for snapshotter in overlayfs stargz; do
      ctr-remote -n "$ns" snapshots --snapshotter "$snapshotter" ls -q 2>/dev/null | xargs -r ctr-remote -n "$ns" snapshots --snapshotter "$snapshotter" rm >/dev/null 2>&1 || true
    done
    ctr-remote namespaces rm "$ns" >/dev/null 2>&1 || true
  done
  if $unit_override; then
    clear_snapshotter_state
    umount -l -- "$SNAPSHOTTER_ROOT" >/dev/null 2>&1 || true
    rm -rf "$SNAPSHOTTER_STORAGE"
    rm -rf "/run/systemd/system/$UNIT.d"
    systemctl daemon-reload
    systemctl start "$UNIT" >/dev/null 2>&1 || true
  fi
  rm -rf "$ROOT"
}
trap cleanup EXIT

mkdir -p "$ROOT/registry"
for binary in ctr ctr-remote nerdctl containerd-stargz-grpc curl findmnt jq mount mountpoint sha256sum umount; do check command -v "$binary" >/dev/null; done
check test "$(docker image inspect "$PAYLOAD_IMAGE" --format '{{.Id}}')" = "$PAYLOAD_ID"
actual_registry_id=$(docker image inspect "$REGISTRY_IMAGE" --format '{{.Id}}')
check test "$actual_registry_id" = "$REGISTRY_ID"
check grep -q "address = \"/run/containerd-stargz-grpc/containerd-stargz-grpc.sock\"" /etc/containerd/config.toml
check sh -c "ctr plugins ls | grep -q 'io.containerd.snapshotter.v1.*$SNAPSHOTTER.*ok'"
systemctl cat "$UNIT" >"$ROOT/unit.txt"
check grep -Fq 'runner == "nerdctl-compose"' "$ROOT/unit.txt"
check grep -Fq 'snapshotter // "overlayfs"' "$ROOT/unit.txt"

# The production unit is intentionally gated by app-compose policy. This lease-owned
# transient override exercises the exact packaged daemon without changing app policy.
mkdir -p "/run/systemd/system/$UNIT.d"
cat >"/run/systemd/system/$UNIT.d/test-override.conf" <<EOT
[Service]
ExecCondition=
ExecCondition=/bin/true
EOT
unit_override=true
systemctl daemon-reload
prepare_snapshotter_storage
clear_snapshotter_state
check systemctl start "$UNIT"
check wait_snapshotter

check docker run -d --name "$REGISTRY" --network host -v "$ROOT/registry:/var/lib/registry" "$REGISTRY_IMAGE" >/dev/null
for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:5000/v2/ >/dev/null && break; sleep 0.25; done
check curl -fsS http://127.0.0.1:5000/v2/ >/dev/null
check docker tag "$PAYLOAD_IMAGE" "$NORMAL"
check docker push "$NORMAL" >/dev/null
normal_digest=$(curl -fsSI -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' "http://127.0.0.1:5000/v2/dstack/busybox/manifests/normal" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')
check test -n "$normal_digest"

# Explicit normal overlay path is the documented caller-selected fallback.
check ctr-remote -n "$BASELINE_NS" images pull --local --plain-http --snapshotter overlayfs "$NORMAL" >/dev/null
baseline_output=$(ctr-remote -n "$BASELINE_NS" run --rm --snapshotter overlayfs "$NORMAL" overlay-baseline sh -c 'printf overlay-ok')
check test "$baseline_output" = overlay-ok

check ctr-remote -n "$NS" images pull --local --plain-http --snapshotter overlayfs "$NORMAL" >/dev/null
check ctr-remote -n "$NS" images optimize --oci --no-optimize "$NORMAL" "$LAZY" >/dev/null
check ctr-remote -n "$NS" images push --local --plain-http "$LAZY" >/dev/null
lazy_digest=$(curl -fsSI -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://127.0.0.1:5000/v2/dstack/busybox/manifests/estargz" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')
check test -n "$lazy_digest"
ctr-remote -n "$NS" images rm "$NORMAL" "$LAZY" >/dev/null
check ctr-remote -n "$NS" images rpull --plain-http --snapshotter "$SNAPSHOTTER" "$LAZY" >/dev/null
lazy_output=$(ctr-remote -n "$NS" run --rm --snapshotter "$SNAPSHOTTER" "$LAZY" lazy-first sh -c 'test -x /bin/sh; find / -xdev -type f -exec cat {} \; >/dev/null; printf lazy-ok')
check test "$lazy_output" = lazy-ok

# Two adjacent namespaces exercise duplicate/concurrent pulls against one daemon.
(ctr-remote -n "$CONCURRENT_A" images rpull --plain-http --snapshotter "$SNAPSHOTTER" "$LAZY" >"$ROOT/concurrent-a.log" 2>&1) &
pa=$!
(ctr-remote -n "$CONCURRENT_B" images rpull --plain-http --snapshotter "$SNAPSHOTTER" "$LAZY" >"$ROOT/concurrent-b.log" 2>&1) &
pb=$!
wait "$pa"; ra=$?
wait "$pb"; rb=$?
check test "$ra" -eq 0
check test "$rb" -eq 0

# Restart preserves the already fetched execution path. Registry outage then proves
# cached content remains usable while an uncached reference fails closed.
check systemctl restart "$UNIT"
check wait_snapshotter
restart_output=$(ctr-remote -n "$NS" run --rm --snapshotter "$SNAPSHOTTER" "$LAZY" lazy-restart sh -c 'printf restart-ok; test -x /bin/sh')
check test "$restart_output" = restart-ok
check docker stop "$REGISTRY" >/dev/null
overlay_cache_output=$(ctr-remote -n "$BASELINE_NS" run --rm --snapshotter overlayfs "$NORMAL" overlay-cached sh -c 'printf overlay-cache-ok')
check test "$overlay_cache_output" = overlay-cache-ok
if ctr-remote -n "$NS" images rpull --plain-http --snapshotter "$SNAPSHOTTER" 127.0.0.1:5000/dstack/busybox:uncached >"$ROOT/unavailable.log" 2>&1; then
  unavailable_rc=0
else
  unavailable_rc=$?
fi
check test "$unavailable_rc" -ne 0
check sh -c "grep -Eq 'connect: connection refused|failed to resolve|connection refused' '$ROOT/unavailable.log'"
check docker start "$REGISTRY" >/dev/null
for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:5000/v2/ >/dev/null && break; sleep 0.25; done
check curl -fsS http://127.0.0.1:5000/v2/ >/dev/null

# Produce a distinct layer, optimize it, then mutate the registry blob before its
# first lazy pull and remove the local content copy so digest verification is forced.
check docker create --name stargz-corrupt-source "$PAYLOAD_IMAGE" sh -c 'printf integrity-marker >/integrity-marker' >/dev/null
check docker start -a stargz-corrupt-source >/dev/null
check docker commit stargz-corrupt-source "$CORRUPT_NORMAL" >/dev/null
check docker push "$CORRUPT_NORMAL" >/dev/null
check ctr-remote -n "$CORRUPT_NS" images pull --local --plain-http --snapshotter overlayfs "$CORRUPT_NORMAL" >/dev/null
check ctr-remote -n "$CORRUPT_NS" images optimize --oci --no-optimize "$CORRUPT_NORMAL" "$CORRUPT_LAZY" >/dev/null
check ctr-remote -n "$CORRUPT_NS" images push --local --plain-http "$CORRUPT_LAZY" >/dev/null
manifest=$(curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://127.0.0.1:5000/v2/dstack/busybox/manifests/corrupt-estargz")
corrupt_layer=$(printf '%s' "$manifest" | jq -r '.layers[-1].digest')
check test "$corrupt_layer" != null
ctr-remote -n "$CORRUPT_NS" images rm "$CORRUPT_NORMAL" "$CORRUPT_LAZY" >/dev/null
ctr-remote -n "$CORRUPT_NS" content rm "$corrupt_layer" >/dev/null 2>&1 || true
hex=${corrupt_layer#sha256:}
blob="$ROOT/registry/docker/registry/v2/blobs/sha256/${hex:0:2}/$hex/data"
check test -f "$blob"
blob_size=$(stat -c %s "$blob")
check test "$blob_size" -gt 128
for offset in $(seq 16 32 $((blob_size - 16))); do
  printf X | dd of="$blob" bs=1 seek="$offset" count=1 conv=notrunc status=none
done
if ctr-remote -n "$CORRUPT_NS" images rpull --plain-http --snapshotter "$SNAPSHOTTER" "$CORRUPT_LAZY" >"$ROOT/corrupt.log" 2>&1; then
  corrupt_pull_rc=0
else
  corrupt_pull_rc=$?
fi
corrupt_run_rc=0
if test "$corrupt_pull_rc" -eq 0; then
  if ctr-remote -n "$CORRUPT_NS" run --rm --snapshotter "$SNAPSHOTTER" "$CORRUPT_LAZY" corrupt-run cat /integrity-marker >>"$ROOT/corrupt.log" 2>&1; then
    corrupt_run_rc=0
  else
    corrupt_run_rc=$?
  fi
fi
check sh -c "test '$corrupt_pull_rc' -ne 0 || test '$corrupt_run_rc' -ne 0"
check sh -c "grep -Eqi 'digest|checksum|unexpected commit|failed to copy|invalid|failed to mount' '$ROOT/corrupt.log'"

# With the snapshotter unavailable, its path fails closed. The explicit overlay
# path remains available and is the truthful fallback (there is no silent fallback).
check systemctl stop "$UNIT"
if ctr-remote -n "$STOPPED_NS" images rpull --plain-http --snapshotter "$SNAPSHOTTER" "$LAZY" >"$ROOT/stopped.log" 2>&1; then
  stopped_rc=0
else
  stopped_rc=$?
fi
check test "$stopped_rc" -ne 0
check sh -c "grep -Eqi 'connect|snapshotter|socket|unavailable' '$ROOT/stopped.log'"
fallback_output=$(ctr-remote -n "$BASELINE_NS" run --rm --snapshotter overlayfs "$NORMAL" overlay-fallback sh -c 'printf fallback-ok')
check test "$fallback_output" = fallback-ok
check systemctl start "$UNIT"
check systemctl is-active --quiet "$UNIT"

printf '{"checks":%d,"payload_id":"%s","registry_archive_id":"%s","normal_digest":"%s","lazy_digest":"%s","overlay_baseline":true,"lazy_execution":true,"concurrent_pulls":2,"restart_recovery":true,"overlay_cache_outage":true,"unavailable_registry_rejected":true,"corrupt_layer_rejected":true,"snapshotter_outage_rejected":true,"explicit_overlay_fallback":true,"silent_fallback_claimed":false}\n' \
  "$checks" "$PAYLOAD_ID" "$actual_registry_id" "$normal_digest" "$lazy_digest"

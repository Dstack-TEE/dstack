#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
OUTER=sysbox-case-outer
FAST=sysbox-case-fast
FAULT=sysbox-case-fault
ROOT=/run/dstack-test-sysbox
DIND_IMAGE=${1:?dind image}
DIND_DIGEST=${2:?dind image digest}
DIND_ID=${3:?dind image id}
PAYLOAD_IMAGE=${4:?payload image}
PAYLOAD_DIGEST=${5:?payload image digest}
PAYLOAD_ID=${6:?payload image id}
mkdir -p "$ROOT"
cleanup() {
  set +e
  docker rm -f "$OUTER" "$FAST" "$FAULT" >/dev/null 2>&1
  systemctl start sysbox-mgr.service sysbox-fs.service sysbox.service >/dev/null 2>&1
  rm -rf "$ROOT"
}
trap cleanup EXIT
for unit in sysbox-mgr.service sysbox-fs.service sysbox.service; do systemctl is-active --quiet "$unit"; done
test -x /bin/rsync
docker info --format '{{json .Runtimes}}' | grep -q 'sysbox-runc'
test "$(docker image inspect "$DIND_IMAGE" --format '{{.Id}}')" = "$DIND_ID"
test "$(docker image inspect "$PAYLOAD_IMAGE" --format '{{.Id}}')" = "$PAYLOAD_ID"
case "$DIND_DIGEST:$PAYLOAD_DIGEST" in sha256:????????????????????????????????????????????????????????????????:sha256:????????????????????????????????????????????????????????????????) ;; *) exit 25 ;; esac
BASELINE=true
# A bounded ordinary Sysbox lifecycle must use remapped host credentials and no agent sockets.
docker create --name "$FAST" --runtime=sysbox-runc "$PAYLOAD_IMAGE" sleep 30 >/dev/null
docker start "$FAST" >/dev/null
PID=$(docker inspect "$FAST" --format '{{.State.Pid}}')
grep -q '^Uid:[[:space:]]*100000' "/proc/$PID/status"
grep -q '^Gid:[[:space:]]*100000' "/proc/$PID/status"
grep -q '^[[:space:]]*0[[:space:]]*100000[[:space:]]*65536' "/proc/$PID/uid_map"
docker exec "$FAST" sh -c 'test ! -S /run/dstack.sock; test ! -S /run/tappd.sock; test ! -e /dev/kvm'
docker stop -t 2 "$FAST" >/dev/null
docker rm "$FAST" >/dev/null
LIFECYCLE=true
# The nested daemon uses vfs and suppresses the irrelevant guest ZFS probe, which otherwise consumes dockerd's fixed startup budget.
docker run -d --name "$OUTER" --runtime=sysbox-runc --entrypoint sh "$DIND_IMAGE" -c \
  'mv /usr/sbin/zfs /usr/sbin/zfs.disabled; exec dockerd-entrypoint.sh --host=unix:///var/run/docker.sock --storage-driver=vfs --tls=false' >/dev/null
for _ in $(seq 1 45); do
  docker exec "$OUTER" docker info >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$OUTER" docker info >/dev/null
docker save "$PAYLOAD_IMAGE" | docker exec -i "$OUTER" docker load >/dev/null
NESTED=$(docker exec "$OUTER" docker run --rm -v /:/outer-root:ro "$PAYLOAD_IMAGE" sh -c '
  set -e
  test ! -S /run/dstack.sock
  test ! -S /run/tappd.sock
  test ! -e /dev/kvm
  test ! -S /outer-root/run/dstack.sock
  test ! -S /outer-root/run/tappd.sock
  test ! -e /outer-root/dev/kvm
  test "$(cat /proc/1/cgroup)" = "0::/"
  mount | grep -q "proc on /proc type proc"
  mount | grep -q "sysfs on /sys type sysfs"
  echo NESTED_OK
')
test "$NESTED" = NESTED_OK
NESTED_BOUNDARY=true
docker rm -f "$OUTER" >/dev/null
# A manager outage must fail closed; partial recovery must remain closed; full recovery must converge.
systemctl stop sysbox-mgr.service
for _ in $(seq 1 20); do
  if ! systemctl is-active --quiet sysbox-mgr.service && ! pgrep -x sysbox-mgr >/dev/null; then break; fi
  sleep 0.25
done
if systemctl is-active --quiet sysbox-mgr.service; then exit 23; fi
if pgrep -x sysbox-mgr >/dev/null; then exit 24; fi
sleep 1
if docker run --name "$FAULT" --runtime=sysbox-runc "$PAYLOAD_IMAGE" true >"$ROOT/fault.out" 2>"$ROOT/fault.err"; then exit 21; fi
docker rm -f "$FAULT" >/dev/null 2>&1 || true
grep -Eqi 'sysbox|socket|connect|runtime' "$ROOT/fault.err"
FAIL_CLOSED=true
systemctl start sysbox-mgr.service
if docker run --name "$FAULT" --runtime=sysbox-runc "$PAYLOAD_IMAGE" true >"$ROOT/partial.out" 2>"$ROOT/partial.err"; then exit 22; fi
docker rm -f "$FAULT" >/dev/null 2>&1 || true
PARTIAL_CLOSED=true
RECOVERY_RETRIED=false
if ! systemctl start sysbox-fs.service sysbox.service; then
  # Sysbox-fs can lose its first bounded startup race while releasing the
  # nested container's FUSE state. A clean retry must still converge.
  RECOVERY_RETRIED=true
  systemctl reset-failed sysbox-fs.service sysbox.service
  systemctl start sysbox-fs.service sysbox.service
fi
for unit in sysbox-mgr.service sysbox-fs.service sysbox.service; do systemctl is-active --quiet "$unit"; done
docker run --name "$FAULT" --runtime=sysbox-runc "$PAYLOAD_IMAGE" true
docker rm "$FAULT" >/dev/null
RECOVERED=true
printf '{"baseline":%s,"lifecycle":%s,"nested_boundary":%s,"failure_closed":%s,"partial_recovery_closed":%s,"recovery_retried":%s,"recovered":%s,"cleanup":true}\n' \
 "$BASELINE" "$LIFECYCLE" "$NESTED_BOUNDARY" "$FAIL_CLOSED" "$PARTIAL_CLOSED" "$RECOVERY_RETRIED" "$RECOVERED"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Integration tests for the gateway's proxy data path.
#
# Covers what unit tests cannot: a real gateway process relaying real
# connections, across every combination of the two gated optimisations
# (`tcp_splice`, `ktls`) and both proxy paths (TLS terminate, TLS passthrough).
#
# Complements `test_suite.sh`, which covers the control plane, WaveKV and the
# handshake cache. This one is about bytes on the wire.
#
# Runs inside the proxy-e2e container, which supplies python3, openssl and ip,
# and carries NET_ADMIN so the WireGuard-named link the gateway expects at
# startup can be created in the container's own namespace. Nothing here needs
# sudo, and nothing it creates outlives the container.
#
#   ./test_proxy.sh                 # build and run everything
#   GATEWAY_BIN=/path/to/dstack-gateway ./test_proxy.sh
#   KEEP_LOGS=1 ./test_proxy.sh     # leave the work dir behind on success
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CORE_DIR="$(cd "$HERE/../.." && pwd -P)"
PROXY_DIR="$HERE/proxy"
WORK="${WORK:-$(mktemp -d /tmp/dstack-gw-proxy-test.XXXXXX)}"

# Ports are derived from one base so a busy CI machine can shift the whole set.
BASE_PORT="${BASE_PORT:-38400}"
PROXY_PORT=$((BASE_PORT + 0))
RPC_PORT=$((BASE_PORT + 1))
ADMIN_PORT=$((BASE_PORT + 2))
WG_PORT=$((BASE_PORT + 3))
ORIGIN_PLAIN=$((BASE_PORT + 4))
ORIGIN_TLS=$((BASE_PORT + 5))

BASE_DOMAIN="gwtest.local"
# `insecure_localhost_backend` routes `localhost-<port>[s]` to 127.0.0.1:<port>,
# which is what lets these tests run without registering a CVM.
SNI_TERMINATE="localhost-$ORIGIN_PLAIN.$BASE_DOMAIN"
SNI_PASSTHROUGH="localhost-${ORIGIN_TLS}s.$BASE_DOMAIN"
ADMIN_TOKEN="proxy-integration-test"
WG_IFACE="${WG_IFACE:-gwtest0}"

GATEWAY_BIN="${GATEWAY_BIN:-$CORE_DIR/target/release/dstack-gateway}"

PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=()

say() { printf '%s\n' "$*"; }
group() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# $1 = test name, remaining args = command. The command must exit 0 to pass.
check() {
  local name="$1"; shift
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then
    PASS=$((PASS + 1))
    printf '  \033[32mPASS\033[0m %-52s %s\n' "$name" "$(tail -1 <<<"$out")"
  else
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("$name")
    printf '  \033[31mFAIL\033[0m %-52s %s\n' "$name" "$(tail -1 <<<"$out")"
    printf '        %s\n' "${out//$'\n'/$'\n'        }" | tail -12
  fi
}

skip() {
  SKIP=$((SKIP + 1))
  printf '  \033[33mSKIP\033[0m %-52s %s\n' "$1" "$2"
}

probe() { python3 "$PROXY_DIR/probe.py" "$@"; }

# --- setup ------------------------------------------------------------------

cleanup() {
  stop_gateway
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null
  if [ -n "${WG_CREATED:-}" ]; then
    ip link del "$WG_IFACE" 2>/dev/null
  fi
  if [ $FAIL -eq 0 ] && [ -z "${KEEP_LOGS:-}" ]; then
    rm -rf "$WORK"
  else
    say "work dir kept at $WORK"
  fi
}
trap cleanup EXIT

require() {
  command -v "$1" >/dev/null || { say "missing required tool: $1"; exit 1; }
}

setup() {
  require python3; require openssl; require ip; require ss
  mkdir -p "$WORK/certs" "$WORK/logs"

  # Fail fast on a port that is already taken. A stale listener does not just
  # break startup: the probes reach *it* instead, and its config is not the arm
  # under test, so the run reports a scatter of unrelated assertion failures.
  # That cost a long time to diagnose once.
  local port
  local busy=""
  for port in "$PROXY_PORT" "$RPC_PORT" "$ADMIN_PORT" "$ORIGIN_PLAIN" "$ORIGIN_TLS"; do
    if ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
      busy="$busy $port"
    fi
  done
  if [ -n "$busy" ]; then
    say "ports already in use:$busy"
    say "stop whatever holds them, or re-run with BASE_PORT set to a free range"
    exit 1
  fi

  if [ ! -x "$GATEWAY_BIN" ]; then
    say "building the gateway (set GATEWAY_BIN to skip)"
    (cd "$CORE_DIR" && cargo build --release -p dstack-gateway) || exit 1
  fi

  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" \
    -subj "/CN=$BASE_DOMAIN" \
    -addext "subjectAltName=DNS:$BASE_DOMAIN,DNS:*.$BASE_DOMAIN,IP:127.0.0.1" \
    2>/dev/null || { say "failed to generate a test certificate"; exit 1; }

  # The gateway insists on a link with the configured name at startup. A real
  # WireGuard device also makes `wg show` work, which the Status RPC needs; a
  # dummy link is enough for the data path, so fall back to one rather than
  # skipping every test on a host without the wireguard module.
  # NET_ADMIN in the container's own namespace, so no sudo and nothing that
  # outlives the run.
  if ip link show "$WG_IFACE" >/dev/null 2>&1; then
    WG_KIND=preexisting
  elif ip link add "$WG_IFACE" type wireguard 2>/dev/null; then
    WG_KIND=wireguard; WG_CREATED=1
  elif ip link add "$WG_IFACE" type dummy 2>/dev/null; then
    WG_KIND=dummy; WG_CREATED=1
  else
    say "cannot create the link '$WG_IFACE' the gateway needs at startup"; exit 1
  fi
  [ -n "${WG_CREATED:-}" ] && ip link set "$WG_IFACE" up
  say "link $WG_IFACE: $WG_KIND"

  CERT="$WORK/certs/cert.pem" KEY="$WORK/certs/key.pem" \
    PLAIN_PORT="$ORIGIN_PLAIN" TLS_PORT="$ORIGIN_TLS" \
    python3 "$PROXY_DIR/origin.py" >"$WORK/logs/origin.log" 2>&1 &
  ORIGIN_PID=$!
  for _ in $(seq 50); do
    grep -q "origin ready" "$WORK/logs/origin.log" 2>/dev/null && break
    sleep 0.2
  done
  grep -q "origin ready" "$WORK/logs/origin.log" || { say "origin failed to start"; exit 1; }
}

# --- gateway lifecycle ------------------------------------------------------

stop_gateway() {
  [ -n "${GW_PID:-}" ] || return 0
  kill "$GW_PID" 2>/dev/null
  for _ in $(seq 50); do
    kill -0 "$GW_PID" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$GW_PID" 2>/dev/null
  GW_PID=""
  # The suite restarts the gateway ~25 times. Killing the process is not enough:
  # its listeners linger briefly, and the next arm then dies with EADDRINUSE on
  # the RPC port -- which showed up as unrelated assertions failing. Wait for the
  # ports to actually come back before handing them to the next arm.
  local port
  for port in "$PROXY_PORT" "$RPC_PORT" "$ADMIN_PORT"; do
    for _ in $(seq 100); do
      ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN || break
      sleep 0.1
    done
  done
}

# start_gateway <label> [gwconfig key=value ...]
start_gateway() {
  local label="$1"; shift
  stop_gateway
  rm -rf "$WORK/data"; mkdir -p "$WORK/data"
  GW_LOG="$WORK/logs/gw-$label.log"
  python3 "$PROXY_DIR/gwconfig.py" "$WORK" \
    proxy_port="$PROXY_PORT" rpc_port="$RPC_PORT" admin_port="$ADMIN_PORT" \
    wg_port="$WG_PORT" wg_iface="$WG_IFACE" admin_token="$ADMIN_TOKEN" \
    base_domain="$BASE_DOMAIN" "$@" >"$WORK/gw.toml" || return 1
  RUST_LOG="${RUST_LOG:-warn}" "$GATEWAY_BIN" -c "$WORK/gw.toml" \
    >"$GW_LOG" 2>&1 &
  GW_PID=$!
  for _ in $(seq 100); do
    if probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 64 \
        >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$GW_PID" 2>/dev/null || { say "gateway exited; see $GW_LOG"; return 1; }
    sleep 0.2
  done
  say "gateway did not become ready; see $GW_LOG"
  return 1
}

# Assert on the gateway's own log, which is where the fallbacks announce
# themselves -- a fallback that happens silently is the bug, not the fallback.
log_contains() { grep -q "$1" "$GW_LOG"; }
log_lacks() { ! grep -q "$1" "$GW_LOG"; }

tls_stat() { awk -v k="$1" '$1==k{print $2}' /proc/net/tls_stat 2>/dev/null || echo 0; }

# --- the arms ---------------------------------------------------------------
#
# Both gated optimisations have three states, and the point of the gates is that
# the state can change mid-connection, so each arm is run against both proxy
# paths and both sides of its gate.

ARMS=(
  "baseline|splice=off ktls=off"
  "splice-immediate|splice=immediate ktls=off"
  "splice-gated|splice=after:65536:5s ktls=off"
  "ktls-immediate|splice=immediate ktls=immediate"
  "ktls-gated|splice=after:65536:5s ktls=after:65536:5s"
)

test_data_path() {
  group "data path: payload integrity across every arm and both paths"
  local arm name cfg
  for arm in "${ARMS[@]}"; do
    name="${arm%%|*}"; cfg="${arm#*|}"
    # shellcheck disable=SC2086  # $cfg is a list of gwconfig arguments
    start_gateway "$name" $cfg || { FAIL=$((FAIL+1)); FAILED_NAMES+=("$name: startup"); continue; }
    # Under the gate and over it, so both halves of each arm are exercised.
    check "$name / terminate 1 KiB" \
      probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1024
    check "$name / terminate 1 MiB" \
      probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1048576
    check "$name / passthrough 1 KiB" \
      probe fetch --port "$PROXY_PORT" --sni "$SNI_PASSTHROUGH" --size 1024
    check "$name / passthrough 1 MiB" \
      probe fetch --port "$PROXY_PORT" --sni "$SNI_PASSTHROUGH" --size 1048576
    check "$name / 16 concurrent transfers" \
      probe concurrent --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 262144 --count 16
  done
}

test_half_close() {
  group "half-close: a client that finishes its request still gets the reply"
  # Needs a TLS client that can send close_notify without waiting for the
  # peer's, which `ssl.SSLSocket` cannot express -- see `proxy/tlsclient.py`.
  # This found a bug `shutdown(SHUT_WR)` could not: after kTLS offload, splice
  # reports the client's close_notify as EINVAL, which used to be fatal and
  # took the app's in-flight response down with it.
  local arm name cfg
  for arm in "${ARMS[@]}"; do
    name="${arm%%|*}"; cfg="${arm#*|}"
    # shellcheck disable=SC2086  # $cfg is a list of gwconfig arguments
    start_gateway "halfclose-$name" $cfg || { FAIL=$((FAIL+1)); continue; }
    check "$name / terminate" \
      probe halfclose --port "$PROXY_PORT" --sni "$SNI_TERMINATE"
    check "$name / passthrough" \
      probe halfclose --port "$PROXY_PORT" --sni "$SNI_PASSTHROUGH"
  done
}

test_close_notify() {
  group "close: the app closing reaches the client as an orderly TLS shutdown"
  local arm name cfg
  for arm in "${ARMS[@]}"; do
    name="${arm%%|*}"; cfg="${arm#*|}"
    # shellcheck disable=SC2086  # $cfg is a list of gwconfig arguments
    start_gateway "close-$name" $cfg || { FAIL=$((FAIL+1)); continue; }
    check "$name / terminate 1 MiB" \
      probe close-notify --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1048576
  done
}

test_idle_timeout() {
  group "timeouts.idle applies to every relay path, gated or not"
  # 3s window, 12s of silence: comfortably past it without making CI slow.
  local common="idle=3s data_timeout=true"
  local arm
  for arm in \
    "buffered|splice=off ktls=off|$SNI_TERMINATE|1048576" \
    "splice engaged|splice=after:1024 ktls=off|$SNI_PASSTHROUGH|1048576" \
    "ktls engaged|splice=immediate ktls=immediate|$SNI_TERMINATE|1048576" \
    "splice configured, gate not reached|splice=after:10485760 ktls=off|$SNI_PASSTHROUGH|1024" \
    "ktls configured, gate not reached|ktls=after:10485760 splice=after:10485760|$SNI_TERMINATE|1024"
  do
    local name="${arm%%|*}" rest="${arm#*|}"
    local cfg="${rest%%|*}" rest2="${rest#*|}"
    local sni="${rest2%%|*}" size="${rest2##*|}"
    # shellcheck disable=SC2086  # both are lists of gwconfig arguments
    start_gateway "idle-${name// /-}" $cfg $common || { FAIL=$((FAIL+1)); continue; }
    check "reaped: $name" \
      probe idle --port "$PROXY_PORT" --sni "$sni" --size "$size" --wait 12 --expect reaped
  done

  # A half-closed request whose backend never answers must still be reaped:
  # the drain phase runs outside the main relay loop, so it needs the watchdog
  # of its own that it did not originally have.
  local arm2
  for arm2 in \
    "buffered|splice=off ktls=off|$SNI_TERMINATE" \
    "splice engaged|splice=immediate ktls=off|$SNI_PASSTHROUGH" \
    "splice gated|splice=after:1048576 ktls=off|$SNI_PASSTHROUGH" \
    "ktls gated|splice=after:1048576 ktls=after:1048576|$SNI_TERMINATE"
  do
    local n2="${arm2%%|*}" r2="${arm2#*|}"
    local c2="${r2%%|*}" s2="${r2##*|}"
    # shellcheck disable=SC2086  # $c2 is a list of gwconfig arguments
    start_gateway "stalled-${n2// /-}" $c2 $common || { FAIL=$((FAIL+1)); continue; }
    check "reaped after half-close, backend silent: $n2" \
      probe stalled-halfclose --port "$PROXY_PORT" --sni "$s2" --wait 20
    # The mirror: the backend floods and *this* side stops reading, so the
    # relay stalls in its write instead of its read. Watching only the read
    # half left this one running to `timeouts.total`.
    check "reaped after half-close, client not reading: $n2" \
      probe stalled-write-halfclose --port "$PROXY_PORT" --sni "$s2" \
        --size 67108864 --wait 15 --timeout 90
  done

  start_gateway "idle-disabled" splice=immediate ktls=immediate idle=3s data_timeout=false \
    || { FAIL=$((FAIL+1)); return; }
  check "kept: data_timeout_enabled = false" \
    probe idle --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1048576 --wait 12 --expect alive
}

test_ktls_engages() {
  group "kTLS actually offloads, and only when the gate says so"
  if [ ! -r /proc/net/tls_stat ]; then
    skip "kTLS offload counters" "/proc/net/tls_stat unavailable"
    return
  fi

  start_gateway "ktls-engage" splice=immediate ktls=immediate || { FAIL=$((FAIL+1)); return; }
  if log_contains "kTLS is configured but unavailable"; then
    skip "kTLS offload counters" "kernel has no TLS ULP; fallback path covered below"
    return
  fi
  local before after err_before err_after
  before=$(tls_stat TlsTxSw); err_before=$(tls_stat TlsDecryptError)
  check "immediate / 1 MiB transfer intact" \
    probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1048576
  after=$(tls_stat TlsTxSw); err_after=$(tls_stat TlsDecryptError)
  check "immediate / offloaded to the kernel" \
    test "$after" -gt "$before"
  check "immediate / no TLS decrypt errors" \
    test "$err_after" -eq "$err_before"

  start_gateway "ktls-gate" splice=after:65536 ktls=after:65536 || { FAIL=$((FAIL+1)); return; }
  before=$(tls_stat TlsTxSw)
  probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1024 >/dev/null
  after=$(tls_stat TlsTxSw)
  check "gated / a small request does not offload" test "$after" -eq "$before"
  probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1048576 >/dev/null
  after=$(tls_stat TlsTxSw)
  check "gated / a large transfer does offload" test "$after" -gt "$before"
}

test_capability_fallbacks() {
  group "capability fallbacks announce themselves and keep serving"

  # kTLS on a kernel without the TLS ULP must fall back, not truncate.
  #
  # The condition used to be produced with `sudo rmmod tls`, which takes the
  # module away from the entire host, needs passwordless sudo, and silently
  # skips whenever anything else on the machine is using TLS. The suite runs in
  # a container now, where a seccomp profile makes
  # `setsockopt(IPPROTO_TCP, TCP_ULP)` return ENOPROTOOPT -- which is precisely
  # what probe_ktls() sees on a kernel built without CONFIG_TLS, and affects
  # nothing outside this container.
  #
  # A seccomp profile is fixed at container creation, so this arm gets its own
  # container and the main run skips it.
  if [ "${GWTEST_ULP_UNAVAILABLE:-0}" = 1 ]; then
    start_gateway "ktls-no-ulp" splice=immediate ktls=after:65536
    check "no TLS ULP / warns at startup" log_contains "kTLS is configured but unavailable"
    check "no TLS ULP / small request intact" \
      probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1024
    # The regression this guards: a gated offload used to return HTTP 200 with
    # the body cut off at exactly the gate.
    check "no TLS ULP / large transfer not truncated" \
      probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1048576
    stop_gateway
  else
    skip "kTLS fallback without the TLS ULP" "runs in the notls container"
  fi

  start_gateway "rebalance-inert" splice=off ktls=off tpc=false rebalance=true \
    || { FAIL=$((FAIL+1)); return; }
  check "connection_rebalance without thread_per_core / warns" \
    log_contains "connection_rebalance is set but has no effect"
  check "connection_rebalance without thread_per_core / still serves" \
    probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 65536

  start_gateway "rebalance-on" splice=off ktls=off tpc=true rebalance=true \
    || { FAIL=$((FAIL+1)); return; }
  check "thread_per_core + rebalance / no inert warning" \
    log_lacks "connection_rebalance is set but has no effect"
  check "thread_per_core + rebalance / serves concurrently" \
    probe concurrent --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 131072 --count 24
}

test_runtime_modes() {
  group "runtime modes all serve traffic"
  local mode
  for mode in "tpc=true rebalance=true" "tpc=true rebalance=false" \
              "tpc=false rebalance=false"; do
    # shellcheck disable=SC2086  # $mode is a pair of gwconfig arguments
    start_gateway "mode-${mode// /-}" splice=off ktls=off $mode \
      || { FAIL=$((FAIL+1)); FAILED_NAMES+=("$mode: startup"); continue; }
    check "$mode" \
      probe concurrent --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 65536 --count 16
  done
}

test_accel_status() {
  group "the Status RPC reports what the data path is doing"
  start_gateway "accel" splice=after:65536:5s ktls=after:65536:5s || { FAIL=$((FAIL+1)); return; }
  # `Status` calls `refresh_state`, which shells out to `wg show` -- that needs
  # both a real WireGuard device and the privileges to query it. Probe it rather
  # than guessing from the link kind, so this skips for the right reason.
  if ! curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
       "http://127.0.0.1:$ADMIN_PORT/prpc/Admin.Status?json" \
       | grep -q '"accel"'; then
    skip "accel status counters" "Status RPC unavailable (wg show needs a real device + privileges)"
    return
  fi
  probe fetch --port "$PROXY_PORT" --sni "$SNI_TERMINATE" --size 1048576 >/dev/null
  probe fetch --port "$PROXY_PORT" --sni "$SNI_PASSTHROUGH" --size 1048576 >/dev/null
  local accel
  accel=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "http://127.0.0.1:$ADMIN_PORT/prpc/Admin.Status?json" \
    | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin).get("accel",{})))')
  say "    $accel"
  check "reports the configured splice mode" \
    python3 -c "import sys,json; a=json.loads(sys.argv[1]); sys.exit(0 if 'after' in a.get('splice_mode','') else 1)" "$accel"
  check "counts spliced connections" \
    python3 -c "import sys,json; a=json.loads(sys.argv[1]); sys.exit(0 if a.get('splice_engaged',0) > 0 else 1)" "$accel"
  check "reports no failed offloads" \
    python3 -c "import sys,json; a=json.loads(sys.argv[1]); sys.exit(0 if a.get('ktls_offload_failed',0) == 0 else 1)" "$accel"
}

# --- run --------------------------------------------------------------------

setup
say "gateway:  $GATEWAY_BIN"
say "work dir: $WORK"

test_data_path
test_half_close
test_close_notify
test_idle_timeout
test_ktls_engages
test_capability_fallbacks
test_runtime_modes
test_accel_status

printf '\n\033[1m%d passed, %d failed, %d skipped\033[0m\n' "$PASS" "$FAIL" "$SKIP"
if [ $FAIL -gt 0 ]; then
  printf 'failed:\n'
  printf '  - %s\n' "${FAILED_NAMES[@]}"
  exit 1
fi

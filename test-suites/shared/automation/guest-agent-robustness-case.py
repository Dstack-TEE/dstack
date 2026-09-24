#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Drive the live guest agent under concurrent load and a stalled log reader.

Head-of-line blocking (tc-gos-concurrency-002) only means something where a
quote costs real work, so that case reports BLOCKED instead of PASS when one
quote is cheaper than ``LOAD_COST_FLOOR_SECONDS``.

Standalone use for development:

    guest-agent-robustness-case.py --standalone \\
        --case tc-gos-concurrency-001 \\
        --runtime /tmp/simulator-runtime --pid 12345
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable

# `workers` in dstack/guest-agent/dstack.toml. The runtime is built before the
# config is read, so the real width is one worker per vCPU, which is smaller.
AGENT_WORKERS = 8
CONCURRENCY = 3 * AGENT_WORKERS

# `TDX_QUOTE_REPORT_DATA_RANGE` in dstack/dstack-attest/src/attestation.rs.
REPORT_DATA_BYTES = 64
QUOTE_REPORT_DATA_RANGE = (568, 632)

TRIVIAL_LATENCY_BOUND_SECONDS = 1.0
LOAD_COST_FLOOR_SECONDS = 0.05
LOAD_SECONDS = 20.0
TRIVIAL_SAMPLE_INTERVAL_SECONDS = 0.1

STALL_SECONDS = 30.0
STALL_SAMPLE_INTERVAL_SECONDS = 2.0
# Room for the socket and write buffers; more is the agent buffering the stream.
STALL_RSS_GROWTH_KB = 32 * 1024
# About 3.3 MB/s, so buffering would pass the RSS bound well inside the window.
CHATTY_SCRIPT = (
    "line=$(printf 'L%.0s' $(seq 1 100)); i=0; while :; do i=$((i+1)); "
    'printf "%s %s\n" "$i" "$line"; '
    "[ $((i % 500)) -eq 0 ] && sleep 0.01; done"
)

CALL_TIMEOUT_SECONDS = 30
LOG_SOURCE_PREFIX = "dstack-robustness"


class Blocked(Exception):
    """A prerequisite the fixture does not provide."""


@dataclass
class Target:
    """One pRPC listener, reached over a unix socket or a forwarded port."""

    route_template: str
    socket_path: str | None = None
    base_url: str | None = None

    def route(self, method: str) -> str:
        """Resolve the route for one method (isolated and physical-TDX templates)."""
        return self.route_template.replace("<Method>", method).replace(
            "{method}", method
        )


@dataclass
class Reply:
    """One observed response."""

    status: int | None
    body: bytes
    seconds: float
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the listener answered with a success status."""
        return self.status == 200 and self.error is None

    def json(self) -> dict[str, Any]:
        """The decoded response body."""
        value = json.loads(self.body)
        if not isinstance(value, dict):
            raise AssertionError("response body was not a JSON object")
        return value


class UnixConnection(http.client.HTTPConnection):
    """An HTTP/1.1 connection over a unix domain socket."""

    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        """Open the unix socket instead of a TCP one."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


def connect(target: Target, timeout: float = CALL_TIMEOUT_SECONDS):
    """Open one connection to the target listener."""
    if target.socket_path:
        return UnixConnection(target.socket_path, timeout)
    host = str(target.base_url).split("//", 1)[-1]
    return http.client.HTTPConnection(host, timeout=timeout)


def post(target: Target, method: str, payload: dict[str, Any]) -> Reply:
    """Send one JSON pRPC request on its own connection, so calls never queue."""
    body = json.dumps(payload).encode()
    started = time.monotonic()
    connection = connect(target)
    try:
        connection.request(
            "POST",
            target.route(method),
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        response = connection.getresponse()
        return Reply(response.status, response.read(), time.monotonic() - started)
    except (OSError, http.client.HTTPException) as error:
        return Reply(
            None, b"", time.monotonic() - started, f"{type(error).__name__}: {error}"
        )
    finally:
        connection.close()


def parallel(count: int, work: Callable[[int], Any]) -> list[Any]:
    """Run `work` for indices 0..count concurrently and keep the order."""
    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(work, range(count)))


def digest(value: Any) -> str:
    """A digest of one response field, so key material never reaches an artifact."""
    if isinstance(value, str):
        return hashlib.sha256(value.encode()).hexdigest()
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def require_all_ok(replies: list[Reply], what: str) -> None:
    """Fail unless every concurrent call was answered."""
    bad = [
        {
            "status": reply.status,
            "error": reply.error,
            "body": reply.body[:200].decode(errors="replace"),
        }
        for reply in replies
        if not reply.ok
    ]
    if bad:
        raise AssertionError(
            f"{len(bad)}/{len(replies)} concurrent {what} calls failed: {bad[:3]}"
        )


def process_stats(pid: int) -> dict[str, int]:
    """Resident size, thread count and open descriptors of the agent."""
    stats: dict[str, int] = {}
    with open(f"/proc/{pid}/status", encoding="utf-8") as status:
        for line in status:
            if line.startswith(("VmRSS:", "Threads:")):
                name, value = line.split(":", 1)
                stats[name.lower().rstrip(":")] = int(value.split()[0])
    try:
        stats["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except PermissionError:
        # /proc/<pid>/fd is owner-only and the fixture may run the agent as another uid.
        stats["fds"] = None
    return stats


def guest_command(values: dict[str, Any], command: str) -> str | None:
    """Run one command in the guest over the fixture's ssh_argv, or return None."""
    argv = values.get("ssh_argv")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) for item in argv)
    ):
        return None
    try:
        process = subprocess.run(
            [*argv, command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return process.stdout if process.returncode == 0 else None


AGENT_UNIT = "dstack-guest-agent.service"
AGENT_STATE_COMMAND = (
    f'p=$(systemctl show -p MainPID --value {AGENT_UNIT}); echo "pid $p"; '
    f'echo "restarts $(systemctl show -p NRestarts --value {AGENT_UNIT})"; '
    'echo "stat $(cat /proc/$p/stat)"; '
    "grep -E '^Threads:|^VmRSS:' /proc/$p/status"
)


def guest_agent_state(values: dict[str, Any]) -> dict[str, Any] | None:
    """The in-guest agent's (pid, start time), size and restart count."""
    output = guest_command(values, AGENT_STATE_COMMAND)
    if output is None:
        return None
    state: dict[str, Any] = {}
    for line in output.splitlines():
        name, _, rest = line.partition(" ")
        if name == "pid":
            state["pid"] = int(rest) if rest.strip().isdigit() else None
        elif name == "restarts":
            state["restarts"] = int(rest) if rest.strip().isdigit() else None
        elif name == "stat":
            fields = rest.rsplit(") ", 1)[-1].split()
            state["starttime_ticks"] = int(fields[19]) if len(fields) > 19 else None
        elif name.startswith("Threads:"):
            state["threads"] = int(line.split()[1])
        elif name.startswith("VmRSS:"):
            state["vmrss_kb"] = int(line.split()[1])
    if state.get("pid") is None or state.get("starttime_ticks") is None:
        return None
    return state


def guest_agent_journal(values: dict[str, Any]) -> list[str]:
    """The last few lines the agent's unit logged, for a run that lost it."""
    output = guest_command(
        values, f"journalctl -u {AGENT_UNIT} --no-pager -n 12 -o short-unix"
    )
    return output.strip().splitlines() if output else []


def guest_agent_restarted(
    before: dict[str, Any] | None, after: dict[str, Any] | None
) -> bool:
    """Whether the agent is a different process than it was before the load."""
    if before is None or after is None:
        return False
    return (before["pid"], before["starttime_ticks"]) != (
        after["pid"],
        after["starttime_ticks"],
    )


def process_identity(pid: int) -> dict[str, Any]:
    """The agent's (pid, start time); a restart onto the same pid changes it."""
    with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
        fields = stat.read().rsplit(") ", 1)[1].split()
    return {"pid": pid, "starttime_ticks": int(fields[19])}


# --------------------------------------------------------------------------
# tc-gos-concurrency-001: repeated derivation under concurrency
# --------------------------------------------------------------------------


def derivation_identical(targets: dict[str, Target]) -> dict[str, Any]:
    """N concurrent identical derivations must agree byte for byte."""
    guest, tappd = targets["DstackGuest"], targets["Tappd"]
    observations: dict[str, Any] = {"concurrency": CONCURRENCY}

    get_key_request = {
        "path": "robustness/a",
        "purpose": "robustness",
        "algorithm": "ed25519",
    }
    replies = parallel(CONCURRENCY, lambda _: post(guest, "GetKey", get_key_request))
    require_all_ok(replies, "DstackGuest.GetKey")
    keys = {digest(reply.json()["key"]) for reply in replies}
    chains = {digest(reply.json()["signature_chain"]) for reply in replies}
    observations["get_key"] = {
        "key_digests": sorted(keys),
        "signature_chain_digests": sorted(chains),
    }
    if len(keys) != 1 or len(chains) != 1:
        raise AssertionError(
            f"{CONCURRENCY} identical DstackGuest.GetKey calls returned "
            f"{len(keys)} distinct keys and {len(chains)} distinct signature chains"
        )

    replies = parallel(
        CONCURRENCY, lambda _: post(tappd, "DeriveK256Key", get_key_request)
    )
    require_all_ok(replies, "Tappd.DeriveK256Key")
    k256 = {digest(reply.json()["k256_key"]) for reply in replies}
    observations["derive_k256_key"] = {"key_digests": sorted(k256)}
    if len(k256) != 1:
        raise AssertionError(
            f"{CONCURRENCY} identical Tappd.DeriveK256Key calls returned {len(k256)} distinct keys"
        )

    # The key is a pure function of the request; the freshly issued chain is not.
    derive_request = {
        "path": "robustness/a",
        "subject": "localhost",
        "alt_names": ["localhost"],
        "usage_ra_tls": True,
        "usage_server_auth": True,
        "usage_client_auth": False,
        "random_seed": False,
    }
    replies = parallel(CONCURRENCY, lambda _: post(tappd, "DeriveKey", derive_request))
    require_all_ok(replies, "Tappd.DeriveKey")
    derived = {digest(reply.json()["key"]) for reply in replies}
    issued = {digest(reply.json()["certificate_chain"]) for reply in replies}
    observations["derive_key"] = {
        "key_digests": sorted(derived),
        "distinct_certificate_chains": len(issued),
    }
    if len(derived) != 1:
        raise AssertionError(
            f"{CONCURRENCY} identical Tappd.DeriveKey calls returned {len(derived)} distinct keys"
        )

    # Two controls, so "identical" cannot be satisfied by a constant answer.
    other_path = dict(get_key_request, path="robustness/b")
    other = post(guest, "GetKey", other_path)
    require_all_ok([other], "DstackGuest.GetKey")
    observations["path_isolation"] = {
        "same_as_baseline": digest(other.json()["key"]) in keys
    }
    if digest(other.json()["key"]) in keys:
        raise AssertionError("a different derivation path returned the same key")

    random_request = dict(derive_request, random_seed=True)
    replies = parallel(CONCURRENCY, lambda _: post(tappd, "DeriveKey", random_request))
    require_all_ok(replies, "Tappd.DeriveKey random_seed")
    random_keys = {digest(reply.json()["key"]) for reply in replies}
    observations["random_seed_control"] = {"distinct_keys": len(random_keys)}
    if len(random_keys) != CONCURRENCY:
        raise AssertionError(
            f"{CONCURRENCY} concurrent random-seed derivations produced only "
            f"{len(random_keys)} distinct keys"
        )
    return observations


def quote_binding_concurrent(targets: dict[str, Target]) -> dict[str, Any]:
    """N concurrent quotes must each carry the caller's own report data."""
    guest = targets["DstackGuest"]
    expected = [
        (index.to_bytes(2, "big") + os.urandom(REPORT_DATA_BYTES - 2)).hex()
        for index in range(CONCURRENCY)
    ]
    replies = parallel(
        CONCURRENCY,
        lambda index: post(guest, "GetQuote", {"report_data": expected[index]}),
    )
    require_all_ok(replies, "DstackGuest.GetQuote")
    start, end = QUOTE_REPORT_DATA_RANGE
    mismatches = []
    for index, reply in enumerate(replies):
        document = reply.json()
        embedded = document["quote"][start * 2 : end * 2]
        if document["report_data"] != expected[index] or embedded != expected[index]:
            mismatches.append(
                {
                    "index": index,
                    "echoed_matches": document["report_data"] == expected[index],
                    "embedded_matches": embedded == expected[index],
                }
            )
    if mismatches:
        raise AssertionError(
            f"{len(mismatches)}/{CONCURRENCY} concurrent quotes did not bind their "
            f"own report data: {mismatches[:3]}"
        )
    return {
        "concurrency": CONCURRENCY,
        "distinct_quotes": len({digest(reply.json()["quote"]) for reply in replies}),
        "report_data_offset": list(QUOTE_REPORT_DATA_RANGE),
    }


# --------------------------------------------------------------------------
# tc-gos-concurrency-002: head-of-line blocking
# --------------------------------------------------------------------------


def latency_samples(target: Target, count: int) -> list[float]:
    """Latency of a method that does no work, measured serially."""
    samples = []
    for _ in range(count):
        reply = post(target, "Version", {})
        require_all_ok([reply], "DstackGuest.Version")
        samples.append(reply.seconds)
    return samples


def percentile(values: list[float], fraction: float) -> float:
    """The `fraction` percentile of a sample, nearest rank."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * len(ordered)) - 1))
    return ordered[index]


def head_of_line(targets: dict[str, Target], values: dict[str, Any]) -> dict[str, Any]:
    """Saturate the attestation path and watch a trivial method."""
    guest = targets["DstackGuest"]
    agent_before = guest_agent_state(values)
    baseline = latency_samples(guest, 20)

    def quote(_: int) -> Reply:
        return post(
            guest, "GetQuote", {"report_data": os.urandom(REPORT_DATA_BYTES).hex()}
        )

    cost = [quote(0).seconds for _ in range(3)]
    unit_cost = sorted(cost)[len(cost) // 2]
    if unit_cost < LOAD_COST_FLOOR_SECONDS:
        raise Blocked(
            f"one GetQuote costs {unit_cost * 1000:.1f}ms on this fixture, below the "
            f"{LOAD_COST_FLOOR_SECONDS * 1000:.0f}ms floor. Head-of-line blocking on the "
            "global quote mutex cannot be demonstrated where taking it is free: the "
            "simulator answers from a fixture instead of the host's QGS"
        )

    deadline = time.monotonic() + LOAD_SECONDS
    load_replies: list[Reply] = []
    probe: list[float] = []
    failures: list[str] = []

    def saturate(_: int) -> None:
        while time.monotonic() < deadline:
            load_replies.append(quote(0))

    with ThreadPoolExecutor(max_workers=CONCURRENCY + 1) as pool:
        loaders = [pool.submit(saturate, index) for index in range(CONCURRENCY)]
        time.sleep(1.0)
        while time.monotonic() < deadline:
            reply = post(guest, "Version", {})
            if not reply.ok:
                failures.append(reply.error or f"status {reply.status}")
            probe.append(reply.seconds)
            time.sleep(TRIVIAL_SAMPLE_INTERVAL_SECONDS)
        for loader in loaders:
            loader.result()

    agent_after = guest_agent_state(values)
    restarted = guest_agent_restarted(agent_before, agent_after)
    observations = {
        "load_concurrency": CONCURRENCY,
        "load_seconds": LOAD_SECONDS,
        "load_calls": len(load_replies),
        "quote_unit_cost_seconds": round(unit_cost, 4),
        "baseline_p95_seconds": round(percentile(baseline, 0.95), 4),
        "loaded_samples": len(probe),
        "loaded_p50_seconds": round(percentile(probe, 0.50), 4),
        "loaded_p95_seconds": round(percentile(probe, 0.95), 4),
        "loaded_max_seconds": round(max(probe, default=0.0), 4),
        "bound_seconds": TRIVIAL_LATENCY_BOUND_SECONDS,
        "probe_failures": failures[:5],
        "agent_before": agent_before,
        "agent_after": agent_after,
        "agent_restarted": restarted,
        "agent_journal": guest_agent_journal(values) if restarted else [],
    }
    # Checked first: a watchdog restart explains every dropped call below (#1256).
    if restarted:
        raise AssertionError(
            f"the agent did not survive the load: {agent_before} became {agent_after}. "
            f"{sum(1 for reply in load_replies if not reply.ok)} of {len(load_replies)} "
            f"saturating calls and {len(failures)} of {len(probe)} probes were dropped "
            f"with it. Agent journal: {observations['agent_journal'][-6:]}"
        )
    require_all_ok(load_replies, "DstackGuest.GetQuote under load")
    if failures:
        raise AssertionError(
            f"{len(failures)} of {len(probe)} Version probes were not answered while "
            f"the attestation path was saturated: {failures[:3]}"
        )
    if percentile(probe, 0.95) > TRIVIAL_LATENCY_BOUND_SECONDS:
        raise AssertionError(
            f"Version p95 was {observations['loaded_p95_seconds']}s under "
            f"{CONCURRENCY} concurrent GetQuote calls, past the "
            f"{TRIVIAL_LATENCY_BOUND_SECONDS}s bound; the quote path is blocking the runtime"
        )
    return observations


# --------------------------------------------------------------------------
# tc-gos-concurrency-003: survival and process identity
# --------------------------------------------------------------------------


MIXED_LOAD: list[tuple[str, str, dict[str, Any]]] = [
    (
        "DstackGuest",
        "GetKey",
        {"path": "robustness/load", "purpose": "load", "algorithm": "ed25519"},
    ),
    ("DstackGuest", "GetQuote", {"report_data": "5a" * REPORT_DATA_BYTES}),
    ("DstackGuest", "Info", {}),
    ("DstackGuest", "Version", {}),
    (
        "DstackGuest",
        "GetTlsKey",
        {
            "subject": "localhost",
            "alt_names": ["localhost"],
            "usage_ra_tls": True,
            "usage_server_auth": True,
            "usage_client_auth": False,
            "with_app_info": True,
        },
    ),
    ("Tappd", "TdxQuote", {"report_data": "5b" * 32, "hash_algorithm": "sha512"}),
    ("Tappd", "Info", {}),
    ("Worker", "Info", {}),
    ("Worker", "Version", {}),
    ("GuestApi", "Info", {}),
    ("GuestApi", "SysInfo", {}),
]


def survives_load(
    targets: dict[str, Target], pid: int, _values: dict[str, Any]
) -> dict[str, Any]:
    """Mixed concurrent load across every listener the agent serves."""
    identity = process_identity(pid)
    before = process_stats(pid)
    rounds = 6

    def one(index: int) -> tuple[str, Reply]:
        service, method, payload = MIXED_LOAD[index % len(MIXED_LOAD)]
        return f"{service}.{method}", post(targets[service], method, payload)

    replies = parallel(rounds * len(MIXED_LOAD), one)
    unanswered = [
        f"{name}: {reply.error}" for name, reply in replies if reply.status is None
    ]
    if unanswered:
        raise AssertionError(
            f"{len(unanswered)} of {len(replies)} concurrent calls got no HTTP answer: "
            f"{unanswered[:3]}"
        )
    require_all_ok([reply for _, reply in replies], "mixed-load")

    liveness = post(targets["DstackGuest"], "GetKey", MIXED_LOAD[0][2])
    require_all_ok([liveness], "post-load DstackGuest.GetKey")
    after_identity = process_identity(pid)
    after = process_stats(pid)
    if after_identity != identity:
        raise AssertionError(
            f"the agent is not the process it started as: {identity} became {after_identity}; "
            "a restart between the load and the probe would hide a wedge or an abort"
        )
    observations = {
        "calls": len(replies),
        "methods": sorted({name for name, _ in replies}),
        "identity": identity,
        "stats_before": before,
        "stats_after": after,
        "fd_growth": (
            after["fds"] - before["fds"]
            if before["fds"] is not None and after["fds"] is not None
            else None
        ),
        "rss_growth_kb": after["vmrss"] - before["vmrss"],
    }
    # Every connection is closed by now, so a descriptor still held is a leak.
    if before["fds"] is None or after["fds"] is None:
        observations["fd_growth_unavailable"] = "/proc/<pid>/fd is not readable"
    elif after["fds"] > before["fds"] + AGENT_WORKERS:
        raise AssertionError(
            f"the agent held {after['fds'] - before['fds']} more descriptors after "
            f"{len(replies)} closed connections"
        )
    return observations


# --------------------------------------------------------------------------
# tc-gos-observability-slow-consumer: a log reader that stops draining
# --------------------------------------------------------------------------


def docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run one bounded Docker command."""
    return subprocess.run(
        ["docker", *args], text=True, capture_output=True, timeout=timeout, check=False
    )


def container_runtime() -> str:
    """The reachable container runtime, or the reason there is none."""
    probe = docker("version", "--format", "{{.Server.Version}}", timeout=30)
    if probe.returncode != 0:
        raise Blocked(
            "the fixture provides no reachable Docker daemon, so the agent has no "
            f"container to stream: {probe.stderr.strip()[:300]}"
        )
    return probe.stdout.strip()


def start_log_source(name: str, script: str) -> None:
    """Start one run-scoped container the agent can stream logs from."""
    container_runtime()
    docker("rm", "-f", name)
    created = docker(
        "run",
        "-d",
        "--log-opt",
        "max-size=32m",
        "--log-opt",
        "max-file=2",
        "--name",
        name,
        "alpine:3",
        "sh",
        "-c",
        script,
    )
    if created.returncode != 0:
        raise Blocked(
            f"the fixture could not start the run-scoped log source: {created.stderr.strip()[:300]}"
        )


def open_log_stream(target: Target, container: str) -> tuple[socket.socket, bytes]:
    """Open a `follow` log stream and read only its response head."""
    if not target.socket_path:
        raise Blocked("the slow-consumer probe needs the agent's external unix socket")
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(30)
    stream.connect(target.socket_path)
    stream.sendall(
        f"GET /logs/{container}?text=true&tail=all&follow=true HTTP/1.1\r\nHost: localhost\r\n"
        "Connection: close\r\n\r\n".encode()
    )
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = stream.recv(4096)
        if not chunk:
            break
        head += chunk
    return stream, head


def slow_consumer(
    targets: dict[str, Target], pid: int, _values: dict[str, Any]
) -> dict[str, Any]:
    """A reader that stops draining must not become the agent's problem."""
    worker = targets["Worker"]
    chatty = f"{LOG_SOURCE_PREFIX}-chatty-{os.getpid()}"
    observations: dict[str, Any] = {}
    start_log_source(chatty, CHATTY_SCRIPT)
    try:
        time.sleep(2)
        stream, head = open_log_stream(worker, chatty)
        try:
            if not head.startswith(b"HTTP/1.1 200"):
                raise AssertionError(
                    f"the log stream did not start: {head[:200].decode(errors='replace')}"
                )
            before = process_stats(pid)
            series = []
            deadline = time.monotonic() + STALL_SECONDS
            while time.monotonic() < deadline:
                time.sleep(STALL_SAMPLE_INTERVAL_SECONDS)
                series.append(process_stats(pid))
            peak = max(sample["vmrss"] for sample in series)
            observations["stall"] = {
                "seconds": STALL_SECONDS,
                "rss_before_kb": before["vmrss"],
                "rss_peak_kb": peak,
                "rss_growth_kb": peak - before["vmrss"],
                "bound_kb": STALL_RSS_GROWTH_KB,
                "threads_before": before["threads"],
                "threads_peak": max(sample["threads"] for sample in series),
            }
            if peak - before["vmrss"] > STALL_RSS_GROWTH_KB:
                raise AssertionError(
                    f"the agent grew {peak - before['vmrss']}KB of resident memory while a "
                    f"log reader stalled for {STALL_SECONDS}s, past the "
                    f"{STALL_RSS_GROWTH_KB}KB bound: the stream is being buffered "
                    "instead of pushed back on"
                )
            # Data still pending proves the window stalled a live stream.
            stream.settimeout(10)
            drained = 0
            try:
                while drained < 256 * 1024:
                    chunk = stream.recv(65536)
                    if not chunk:
                        break
                    drained += len(chunk)
            except (TimeoutError, socket.timeout):
                pass
            observations["stall"]["drained_bytes_after_resume"] = drained
            if drained == 0:
                raise AssertionError(
                    "the stalled log stream produced nothing when the reader resumed, so "
                    "the window above did not measure a stalled live stream"
                )
        finally:
            stream.close()

        # More stalled readers than workers: a parked worker would stop answers.
        stalled = []
        try:
            for _ in range(AGENT_WORKERS + 2):
                stalled.append(open_log_stream(worker, chatty)[0])
            time.sleep(2)
            probe = post(targets["DstackGuest"], "Version", {})
            require_all_ok([probe], "DstackGuest.Version with stalled log readers")
            observations["stalled_readers"] = {
                "readers": len(stalled),
                "agent_workers": AGENT_WORKERS,
                "version_seconds": round(probe.seconds, 4),
            }
        finally:
            for extra in stalled:
                extra.close()
    finally:
        docker("rm", "-f", chatty)
    return observations


# --------------------------------------------------------------------------
# Case table
# --------------------------------------------------------------------------


@dataclass
class Step:
    """One declared step of a case."""

    observation: str
    evidence: str
    run: Callable[[dict[str, Target], int, dict[str, Any]], dict[str, Any]]


@dataclass
class Case:
    """One case this harness handles."""

    services: list[str]
    needs_pid: bool
    summary: str
    steps: list[Step]
    remarks: str
    artifact: str
    artifact_description: str


def _reachable_with_log_source(
    targets: dict[str, Target], pid: int, values: dict[str, Any]
) -> dict[str, Any]:
    """Confirm the listeners and that a container runtime can host a log source."""
    return {
        **_reachable(targets, pid, values),
        "container_runtime": container_runtime(),
    }


def _reachable(
    targets: dict[str, Target], _pid: int, _values: dict[str, Any]
) -> dict[str, Any]:
    """Confirm every listener this case needs answers before it is loaded."""
    observed = {}
    for service, target in targets.items():
        method = "Version" if service in ("DstackGuest", "Tappd", "Worker") else "Info"
        reply = post(target, method, {})
        require_all_ok([reply], f"{service}.{method}")
        observed[service] = {
            "route": target.route(method),
            "seconds": round(reply.seconds, 4),
        }
    return {"listeners": observed}


CASES: dict[str, Case] = {
    "tc-gos-concurrency-001": Case(
        services=["DstackGuest", "Tappd"],
        needs_pid=False,
        summary="Concurrent identical derivations agreed byte for byte and every "
        "concurrent quote bound its own report data.",
        remarks="This confirms derivation determinism and per-call quote binding under "
        "concurrency. It does not confirm physical TEE trust properties: under the "
        "simulator the quote is a patched fixture, not hardware evidence.",
        artifact="derivation-concurrency.json",
        artifact_description="Per-call digests of every concurrently derived key, the "
        "distinct-key controls, and the report-data binding of every concurrent quote.",
        steps=[
            Step(
                "The lease-owned internal and legacy listeners answered before any load.",
                "Proves the listeners were healthy before the concurrent phase.",
                _reachable,
            ),
            Step(
                "Identical concurrent derivations returned one key digest each, a "
                "different path returned a different key, and random-seed derivations "
                "were all distinct.",
                "Proves derivation is a pure function of its arguments under concurrency.",
                lambda targets, _pid, _values: derivation_identical(targets),
            ),
            Step(
                "Every concurrent quote echoed and embedded its own report data.",
                "Proves concurrent quote requests do not cross-bind report data.",
                lambda targets, _pid, _values: quote_binding_concurrent(targets),
            ),
        ],
    ),
    "tc-gos-concurrency-002": Case(
        services=["DstackGuest"],
        needs_pid=False,
        summary="A trivial method stayed within its latency bound while the attestation "
        "path was saturated, in the agent process the case started with.",
        remarks="This is a hardware claim. The blocking operation is the global quote "
        "mutex plus the vsock round trip to the host's QGS; a fixture-backed simulator "
        "takes the mutex and returns, so a simulated run cannot confirm it and this "
        "harness reports BLOCKED rather than PASS when the load turns out to be free.",
        artifact="head-of-line-blocking.json",
        artifact_description="Unloaded and loaded latency distributions for the trivial "
        "method, the measured cost of one attestation call, the saturation parameters, and "
        "the in-guest agent's process identity, thread count and resident size before and "
        "after the load.",
        steps=[
            Step(
                "The listener answered before the load.",
                "Proves the listener was healthy before saturation.",
                _reachable,
            ),
            Step(
                "The attestation path was saturated above the agent's worker count while "
                "a trivial method was polled on its own connection, and the agent was the "
                "same process afterwards.",
                "Proves whether quote generation stalls the connections the agent serves, "
                "and whether it survives the load at all.",
                lambda targets, _pid, values: head_of_line(targets, values),
            ),
            Step(
                "The listener answered a valid request after the load.",
                "Proves the saturation did not wedge the listener. A listener that answers "
                "because the agent was killed and restarted is caught in step 2, not here.",
                _reachable,
            ),
        ],
    ),
    "tc-gos-concurrency-003": Case(
        services=["DstackGuest", "Tappd", "Worker", "GuestApi"],
        needs_pid=True,
        summary="The agent answered every concurrent call across all four listeners, "
        "answered a valid request afterwards, and was the same process throughout.",
        remarks="This confirms in-process survival of the agent under concurrent mixed "
        "load. It does not confirm physical TEE trust properties.",
        artifact="mixed-load-survival.json",
        artifact_description="Every method driven concurrently across the four listeners, "
        "the agent's process identity before and after, and its descriptor, thread and "
        "resident-memory deltas.",
        steps=[
            Step(
                "All four lease-owned listeners answered before the load.",
                "Proves every listener was healthy before the concurrent phase.",
                _reachable,
            ),
            Step(
                "Every concurrent call across the four listeners was answered, the agent "
                "answered a valid request afterwards, and its process identity was unchanged.",
                "Proves the agent survived the load in the process it started as.",
                survives_load,
            ),
            Step(
                "The listeners still answered after the load.",
                "Proves post-load availability on every surface the agent serves.",
                _reachable,
            ),
        ],
    ),
    "tc-gos-observability-slow-consumer": Case(
        services=["Worker", "DstackGuest"],
        needs_pid=True,
        summary="A log reader that stopped draining did not make the agent buffer without "
        "bound or park its runtime.",
        remarks="This confirms streaming backpressure for the agent's own log route. It "
        "does not confirm physical TEE trust properties.",
        artifact="log-slow-consumer.json",
        artifact_description="Resident-memory and thread samples across the stalled window, "
        "the bytes recovered when the reader resumed, and the liveness probe taken with more "
        "stalled readers than the agent has workers.",
        steps=[
            Step(
                "The external and internal listeners answered and a container runtime "
                "was reachable to host a log source.",
                "Proves the case could obtain a live stream before the reader stalled.",
                _reachable_with_log_source,
            ),
            Step(
                "A stalled reader left the agent's resident memory within bound, the stream "
                "resumed with data still pending, and the agent answered with more stalled "
                "readers open than it has workers.",
                "Proves the agent pushes back on a slow consumer instead of buffering.",
                slow_consumer,
            ),
            Step(
                "The agent answered after every stream closed.",
                "Proves the streaming phase left the listeners healthy.",
                _reachable,
            ),
        ],
    ),
}


# --------------------------------------------------------------------------
# Fixture resolution and entrypoints
# --------------------------------------------------------------------------


def resolve_targets(values: dict[str, Any], services: list[str]) -> dict[str, Target]:
    """Build one target per listener from the lease-owned fixture."""
    published = values.get("services") or {}
    targets: dict[str, Target] = {}
    for service in services:
        fixture = published.get(service)
        if not isinstance(fixture, dict):
            raise Blocked(f"the fixture publishes no {service} listener")
        path = fixture.get("socket")
        if path:
            if not pathlib.Path(path).is_socket():
                raise Blocked(f"the fixture {service} socket is not available: {path}")
            targets[service] = Target(str(fixture["route"]), socket_path=str(path))
            continue
        url = fixture.get("url")
        if not url:
            raise Blocked(
                f"the fixture {service} listener has neither a socket nor a url"
            )
        scheme, rest = str(url).split("://", 1)
        authority, _, route = rest.partition("/")
        targets[service] = Target("/" + route, base_url=f"{scheme}://{authority}")
    return targets


def resolve_pid(values: dict[str, Any]) -> int:
    """The lease-owned agent process, for the checks that need /proc."""
    pid = values.get("pid")
    if not isinstance(pid, int):
        raise Blocked(
            "the fixture publishes no agent PID, so process identity and resident-memory "
            "growth cannot be observed from the control host"
        )
    if not pathlib.Path(f"/proc/{pid}").is_dir():
        raise Blocked(f"the fixture agent process {pid} is not visible in /proc")
    return pid


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def execute(case_id: str, case: Case, values: dict[str, Any]) -> dict[str, Any]:
    """Run every step of one case, reporting rather than raising."""
    report: dict[str, Any] = {"case_id": case_id, "steps": {}}
    status, failure = "PASS", None
    targets: dict[str, Target] = {}
    pid = 0
    for number, step in enumerate(case.steps, start=1):
        step_id = f"{case_id}-step-{number:02d}"
        print(f"STEP {step_id} START", flush=True)
        try:
            if number == 1:
                targets = resolve_targets(values, case.services)
                pid = resolve_pid(values) if case.needs_pid else 0
            observed = step.run(targets, pid, values)
        except Blocked as error:
            status, failure = "BLOCKED", f"{error}"
            print(f"EVIDENCE {step_id} - {step.evidence}", flush=True)
            print(f"STEP {step_id} END - BLOCKED", flush=True)
            report["steps"][step_id] = {"status": "BLOCKED", "observed": failure}
            break
        except Exception as error:  # noqa: BLE001 - the harness reports, never crashes
            status, failure = "FAIL", f"{type(error).__name__}: {error}"
            print(failure, file=sys.stderr, flush=True)
            print(f"STEP {step_id} END - FAIL", flush=True)
            report["steps"][step_id] = {"status": "FAIL", "observed": failure}
            break
        report["steps"][step_id] = {
            "status": "PASS",
            "observed": step.observation,
            **observed,
        }
        print(f"EVIDENCE {step_id} - {step.evidence}", flush=True)
        print(f"STEP {step_id} END - PASS", flush=True)
    report["status"] = status
    report["failure"] = failure
    return report


def finalize(case_id: str, case: Case, report: dict[str, Any]) -> None:
    """Write `result.json` and the case artifact."""
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    atomic_json(artifacts / case.artifact, report)
    status = report["status"]
    steps = []
    for number, step in enumerate(case.steps, start=1):
        step_id = f"{case_id}-step-{number:02d}"
        recorded = report["steps"].get(step_id)
        if recorded is None:
            steps.append(
                {
                    "id": step_id,
                    "status": "NOT_RUN" if status != "PASS" else "PASS",
                    "observed": report["failure"] or step.observation,
                }
            )
            continue
        steps.append(
            {
                "id": step_id,
                "status": recorded["status"],
                "observed": recorded["observed"],
            }
        )
    artifact = {
        "name": case.artifact.removesuffix(".json").replace("-", " ").capitalize(),
        "path": f"artifacts/{case.artifact}",
        "step_id": f"{case_id}-step-02",
        "description": case.artifact_description,
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": case.summary if status == "PASS" else report["failure"],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": case.remarks,
        },
    )


def standalone() -> int:
    """Development entrypoint against a local simulator runtime directory."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--standalone", action="store_true")
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument(
        "--runtime",
        required=True,
        help="a simulator runtime directory holding tappd.sock, dstack.sock, "
        "external.sock and guest.sock",
    )
    parser.add_argument(
        "--pid", type=int, help="the simulator process, for /proc observations"
    )
    parser.add_argument("--output")
    arguments = parser.parse_args()
    runtime = pathlib.Path(arguments.runtime).resolve()
    values: dict[str, Any] = {
        "services": {
            "Tappd": {
                "socket": str(runtime / "tappd.sock"),
                "route": "/prpc/Tappd.<Method>",
            },
            "DstackGuest": {
                "socket": str(runtime / "dstack.sock"),
                "route": "/<Method>",
            },
            "Worker": {
                "socket": str(runtime / "external.sock"),
                "route": "/prpc/<Method>",
            },
            "GuestApi": {
                "socket": str(runtime / "guest.sock"),
                "route": "/api/<Method>",
            },
        }
    }
    if arguments.pid:
        values["pid"] = arguments.pid
    report = execute(arguments.case, CASES[arguments.case], values)
    if arguments.output:
        pathlib.Path(arguments.output).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


def main() -> int:
    """Case-harness entrypoint."""
    if "--standalone" in sys.argv:
        return standalone()
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    case = CASES[case_id]
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text(
            encoding="utf-8"
        )
    )
    report = execute(case_id, case, manifest["values"])
    finalize(case_id, case, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

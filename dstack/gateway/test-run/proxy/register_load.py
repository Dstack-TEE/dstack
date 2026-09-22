#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Measure RegisterCvm interference with Info and new proxy connections.

Use only with the isolated simulator environment described in register-load.md.
Client certificates client0.pem ... client63.pem must carry distinct AppInfo
instance IDs. Only public WireGuard keys are synthesized; this is not a tunnel
throughput benchmark. Emits aggregate measurements, never key/config contents.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import math
import multiprocessing
from pathlib import Path
import ssl
import time


def context(certs, client=None):
    ctx = ssl.create_default_context(cafile=str(certs / "cert.pem"))
    if client is not None:
        ctx.load_cert_chain(certs / f"client{client}.pem", certs / f"client{client}.key")
    return ctx


def public_key(client, revision):
    return base64.b64encode(hashlib.sha256(f"{client}:{revision}".encode()).digest()).decode()


async def connect(port, ctx=None, name="127.0.0.1"):
    return await asyncio.wait_for(asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname=name if ctx else None), 5)


async def request(conn, path, body=None, extra=""):
    reader, writer = conn
    payload = json.dumps(body).encode() if body is not None else b""
    method = "POST" if body is not None else "GET"
    writer.write((f"{method} {path} HTTP/1.1\r\nHost: gwtest.local\r\n"
                  f"Content-Length: {len(payload)}\r\nContent-Type: application/json\r\n"
                  f"{extra}\r\n").encode() + payload)
    await writer.drain()
    header = await reader.readuntil(b"\r\n\r\n")
    status = int(header.split(b" ")[1])
    fields = dict(line.split(b":", 1) for line in header.lower().split(b"\r\n")[1:] if b":" in line)
    if b"content-length" in fields:
        response = await reader.readexactly(int(fields[b"content-length"]))
    elif b"chunked" in fields.get(b"transfer-encoding", b""):
        chunks = []
        while True:
            size = int((await reader.readline()).split(b";", 1)[0], 16)
            if not size:
                await reader.readline()
                break
            chunks.append(await reader.readexactly(size))
            await reader.readexactly(2)
        response = b"".join(chunks)
    else:
        raise RuntimeError("response lacks framing")
    if status != 200:
        raise RuntimeError(f"HTTP {status}: {response[:200]!r}")
    return response


def close(conn):
    if conn:
        conn[1].close()


def stats(samples, errors, seconds):
    values = sorted(samples)
    def percentile(q):
        return values[min(len(values)-1, math.ceil(q*len(values))-1)] if values else None
    return dict(count=len(values), errors=errors, rps=len(values)/seconds,
                p50_ms=percentile(.50), p95_ms=percentile(.95), p99_ms=percentile(.99),
                max_ms=max(values) if values else None)


async def run_probe(kind, args, start, end):
    certs = Path(args.certs)
    rpc_ctx = context(certs, 0)
    proxy_ctx = context(certs)
    samples, errors = [], 0
    await asyncio.sleep(max(0, start-time.monotonic()))
    while time.monotonic() < end:
        t = time.monotonic()
        conn = None
        try:
            if kind == "info":
                conn = await connect(args.rpc_port, rpc_ctx)
                await asyncio.wait_for(request(conn, "/prpc/Info?json"), 5)
            else:
                conn = await connect(args.proxy_port, proxy_ctx, "localhost-38404.gwtest.local")
                body = await asyncio.wait_for(request(conn, "/bytes/1024"), 5)
                pattern = b"dstack-gateway-proxy-test-0123456789abcdef"
                assert body == (pattern*27)[:1024]
            samples.append((time.monotonic()-t)*1000)
        except Exception:
            errors += 1
        finally:
            close(conn)
        # One sequential probe per kind, capped at 50 requests/s.
        await asyncio.sleep(max(0, .02-(time.monotonic()-t)))
    return samples, errors


def probe_process(kind, args, start, end, output):
    output.send(asyncio.run(run_probe(kind, args, start, end)))
    output.close()


async def main(args):
    certs = Path(args.certs)
    clients = [context(certs, i) for i in range(64)]
    async def register(conn, i, rev):
        data = await request(conn, "/prpc/RegisterCvm?json", {
            "client_public_key": public_key(i, rev), "health_check": False,
            "port_policy": {"ports": [], "restrict_mode": False}})
        result = json.loads(data)
        if not result.get("wg", {}).get("client_ip"):
            raise RuntimeError("registration returned no client IP")
    # Seed the same 64 instances for every arm, outside the measured interval.
    for i in range(64):
        conn = await connect(args.rpc_port, clients[i])
        try:
            await asyncio.wait_for(register(conn, i, 0), 5)
        finally:
            close(conn)
    await asyncio.sleep(2)

    async def metrics():
        conn = await connect(args.admin_port)
        try:
            raw = await request(conn, "/metrics", extra="Authorization: Bearer benchmark-only\r\n")
            result = {}
            for line in raw.decode().splitlines():
                if line.startswith("dstack_gateway_wg_reconfigure_"):
                    key, value = line.split()
                    result[key] = float(value)
            return result
        finally:
            close(conn)

    for repeat in range(args.rounds):
        for mode, concurrency in [("idle", 0), ("repeat", 1), ("repeat", 16), ("repeat", 64), ("churn", 64)]:
            # Restore identical peer state before each measured condition.
            for i in range(64):
                conn = await connect(args.rpc_port, clients[i])
                try:
                    await asyncio.wait_for(register(conn, i, 0), 5)
                finally:
                    close(conn)
            await asyncio.sleep(1)
            before = await metrics()
            start = time.monotonic() + 1
            end = start + args.seconds
            probes = []
            mp = multiprocessing.get_context("spawn")
            for kind in ("info", "proxy"):
                parent, child = mp.Pipe(duplex=False)
                proc = mp.Process(target=probe_process, args=(kind, args, start, end, child))
                proc.start()
                child.close()
                probes.append((kind, proc, parent))
            await asyncio.sleep(max(0, start-time.monotonic()))
            results = {k: [[], 0] for k in ("register", "info", "proxy")}
            revisions = [0] * 64
            async def load(i):
                conn = None
                while time.monotonic() < end:
                    t = time.monotonic()
                    try:
                        if conn is None:
                            conn = await connect(args.rpc_port, clients[i])
                        if mode == "churn":
                            revisions[i] += 1
                        await asyncio.wait_for(register(conn, i, revisions[i]), 5)
                        results["register"][0].append((time.monotonic()-t)*1000)
                    except Exception:
                        results["register"][1] += 1
                        close(conn)
                        conn = None
                close(conn)

            await asyncio.gather(*(load(i) for i in range(concurrency)))
            await asyncio.sleep(max(0, end-time.monotonic()))
            for kind, proc, pipe in probes:
                # Probes have independent interpreters, so high registration
                # throughput cannot starve their timers or TLS handshakes.
                if not await asyncio.to_thread(pipe.poll, 15):
                    proc.terminate()
                    raise RuntimeError(f"{kind} probe did not finish")
                results[kind] = pipe.recv()
                proc.join(timeout=5)
                if proc.exitcode != 0:
                    raise RuntimeError(f"{kind} probe failed")
                pipe.close()
            elapsed = time.monotonic()-start
            convergence_ms = None
            if args.interface:
                expected = {public_key(i, revisions[i]) for i in range(64)}
                convergence_start = time.monotonic()
                while True:
                    proc = await asyncio.create_subprocess_exec(
                        "wg", "show", args.interface, "peers", stdout=asyncio.subprocess.PIPE)
                    stdout, _ = await proc.communicate()
                    if proc.returncode:
                        raise RuntimeError("could not inspect WireGuard peers")
                    if set(stdout.decode().split()) == expected:
                        convergence_ms = (time.monotonic()-convergence_start)*1000
                        break
                    if time.monotonic()-convergence_start > 5:
                        raise RuntimeError("WireGuard did not converge to all acknowledged registrations")
                    await asyncio.sleep(.005)
            await asyncio.sleep(1)
            after = await metrics()
            record = dict(arm=args.arm, round=repeat+1, mode=mode, concurrency=concurrency,
                          duration_s=elapsed, requested_duration_s=args.seconds,
                          convergence_after_load_ms=convergence_ms,
                          metrics_delta={k: after[k]-before.get(k,0) for k in after},
                          **{k: stats(*v, elapsed) for k,v in results.items()})
            print(json.dumps(record), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certs", required=True)
    parser.add_argument("--arm", required=True)
    parser.add_argument("--seconds", type=float, default=15)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--interface", help="Optional isolated WireGuard interface to verify convergence")
    parser.add_argument("--rpc-port", type=int, default=38401)
    parser.add_argument("--proxy-port", type=int, default=38400)
    parser.add_argument("--admin-port", type=int, default=38402)
    asyncio.run(main(parser.parse_args()))

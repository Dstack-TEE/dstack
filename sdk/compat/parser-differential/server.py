#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Canned-response HTTP server on a unix socket.

Serves one fixed body+status for every POST, whatever the path. Used to feed
the same malformed guest-agent response to all four dstack SDKs.
"""
import json, os, socket, sys, threading

sock_path = sys.argv[1]
cases_file = sys.argv[2]

CASES = json.load(open(cases_file))
current = {"name": None}

if os.path.exists(sock_path):
    os.unlink(sock_path)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
srv.listen(64)

def handle(conn):
    try:
        conn.settimeout(5)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        path = lines[0].split(b" ")[1].decode()
        clen = 0
        for line in lines[1:]:
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":")[1])
        while len(rest) < clen:
            rest += conn.recv(65536)
        # control channel: /__case/<name> selects the canned response
        if path.startswith("/__case/"):
            current["name"] = path[len("/__case/"):]
            body = b"ok"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (len(body), body))
            return
        case = CASES[current["name"]]
        body = case["body"].encode("utf-8") if isinstance(case["body"], str) else json.dumps(case["body"]).encode()
        status = case.get("status", 200)
        conn.sendall(
            b"HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % (status, len(body)) + body)
    except Exception as e:
        sys.stderr.write("server: %r\n" % (e,))
    finally:
        try: conn.close()
        except Exception: pass

print("READY", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()

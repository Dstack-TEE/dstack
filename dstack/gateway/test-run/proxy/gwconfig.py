#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Emit a gateway config for one arm of the proxy integration tests.

Every knob the suite varies is written explicitly rather than left to the
shipped defaults, so a test says what it is testing and a default change shows
up as a test change rather than as a silent shift in what was covered.

Usage: gwconfig.py DIR [key=value ...]

  splice=off|immediate|after:<bytes>[:<duration>]
  ktls=off|immediate|after:<bytes>[:<duration>]
  tpc=true|false          thread_per_core
  rebalance=true|false    connection_rebalance
  idle=<duration>         timeouts.idle
  data_timeout=true|false timeouts.data_timeout_enabled
  workers=<n>
"""

import sys


def gate_section(name: str, spec: str, extra: str = "") -> str:
    """Render `[core.proxy.<name>]` for one of the two gated optimisations.

    Absent section = off, empty section = engage immediately, keys = gated;
    the same three states the config documents.
    """
    if spec == "off":
        return ""
    body = f"\n[core.proxy.{name}]\n"
    if spec != "immediate":
        _, _, rest = spec.partition(":")
        parts = rest.split(":")
        body += f"after_bytes = {parts[0]}\n"
        if len(parts) > 1:
            body += f'after_duration = "{parts[1]}"\n'
    return body + extra


def main():
    """Write one arm's config to stdout."""
    d = sys.argv[1].rstrip("/")
    o = dict(a.split("=", 1) for a in sys.argv[2:] if "=" in a)

    cert, key = f"{d}/certs/cert.pem", f"{d}/certs/key.pem"
    cfg = f"""workers = 2
address = "127.0.0.1:{o["rpc_port"]}"
[tls]
key = "{key}"
certs = "{cert}"
[tls.mutual]
ca_certs = "{cert}"
[core]
rpc_domain = ""
set_ulimit = false
[core.debug]
insecure_localhost_backend = true
insecure_enable_debug_rpc = false
[core.admin]
enabled = true
address = "127.0.0.1:{o["admin_port"]}"
auth_token = "{o["admin_token"]}"
[core.sync]
enabled = false
node_id = 1
data_dir = "{d}/data"
[core.wg]
public_key = ""
private_key = ""
listen_port = {o["wg_port"]}
ip = "10.90.0.1/24"
reserved_net = ["10.90.0.1/32"]
client_ip_range = "10.90.0.0/25"
config_path = "{d}/wg.conf"
interface = "{o["wg_iface"]}"
endpoint = "10.90.0.1:{o["wg_port"]}"
[core.proxy]
listen_addr = "127.0.0.1"
listen_port = {o["proxy_port"]}
base_domain = "{o["base_domain"]}"
cert_chain = "{cert}"
cert_key = "{key}"
workers = {o.get("workers", "2")}
max_connections_per_app = 0
buffer_size = 65536
tls_versions = ["1.2"]
thread_per_core = {o.get("tpc", "true")}
connection_rebalance = {o.get("rebalance", "true")}

[core.proxy.timeouts]
idle = "{o.get("idle", "10m")}"
data_timeout_enabled = {o.get("data_timeout", "true")}
"""
    cfg += gate_section(
        "tcp_splice", o.get("splice", "off"), extra="release_idle_pipes = true\n"
    )
    cfg += gate_section("ktls", o.get("ktls", "off"))
    print(cfg)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Select and verify an isolated subnet pool for case-owned Docker networks."""

from __future__ import annotations

import ipaddress
import json
import os
import shlex
import subprocess

CANDIDATES = ("10.240.0.0/12", "10.224.0.0/12", "10.208.0.0/12", "10.192.0.0/12")


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run Docker through the required unprivileged identity."""
    return subprocess.run(
        [
            os.environ.get(
                "DSTACK_TEST_DOCKER_SHELL_RUNNER",
                os.path.join(
                    os.environ["DSTACK_TEST_PLAN_DIR"],
                    "shared/automation/run-docker-shell",
                ),
            ),
            shlex.join(["docker", *args]),
        ],
        text=True,
        capture_output=True,
        check=check,
    )


def occupied_networks() -> list[ipaddress.IPv4Network]:
    """Return bounded host-route and Docker-IPAM networks."""
    occupied: list[ipaddress.IPv4Network] = []
    routes = json.loads(
        subprocess.run(
            ["ip", "-j", "-4", "route"], capture_output=True, text=True, check=True
        ).stdout
    )
    for route in routes:
        destination = route.get("dst")
        if destination and destination != "default":
            try:
                occupied.append(ipaddress.ip_network(destination, strict=False))
            except ValueError:
                pass
    identifiers = docker("network", "ls", "-q").stdout.split()
    if identifiers:
        networks = json.loads(docker("network", "inspect", *identifiers).stdout)
        for network in networks:
            for config in network.get("IPAM", {}).get("Config") or []:
                subnet = config.get("Subnet")
                if subnet:
                    try:
                        occupied.append(ipaddress.ip_network(subnet, strict=False))
                    except ValueError:
                        pass
    return occupied


def main() -> int:
    """Print the first nonoverlapping pool after a real create/remove probe."""
    occupied = occupied_networks()
    for value in CANDIDATES:
        pool = ipaddress.ip_network(value)
        if any(pool.overlaps(network) for network in occupied):
            continue
        subnet = next(pool.subnets(new_prefix=24))
        name = f"dstack-network-probe-{os.getpid()}"
        created = docker(
            "network", "create", "--subnet", str(subnet), name, check=False
        )
        if created.returncode:
            continue
        removed = docker("network", "rm", name, check=False)
        if removed.returncode:
            raise SystemExit(
                f"failed to remove Docker network probe: {removed.stderr.strip()}"
            )
        print(pool)
        return 0
    raise SystemExit(
        "no isolated Docker subnet pool passed route, IPAM, and create/remove probes"
    )


if __name__ == "__main__":
    raise SystemExit(main())

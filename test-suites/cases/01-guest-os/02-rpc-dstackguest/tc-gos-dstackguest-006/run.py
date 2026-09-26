#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TC tc-gos-dstackguest-006: verify DstackGuest.GpuInfo removal stays effective."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import socket


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.path)


def call(sock: str, route: str, content_type: str, body: bytes):
    c = UnixHTTPConnection(sock)
    c.request("POST", route, body=body, headers={"Content-Type": content_type})
    r = c.getresponse()
    data = r.read()
    code = r.status
    c.close()
    return code, data


def main():
    cid = os.environ["DSTACK_TEST_CASE_ID"]
    out = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    services = manifest["values"]["services"]
    fixture = services["DstackGuest"]
    sock = fixture["socket"]
    # The frozen surface is mounted at its historical path, at /v0, and under
    # /prpc; v1 lives at /v1. None of them may serve a GpuInfo method.
    legacy_routes = sorted(
        {
            fixture["route"].replace("<Method>", "GpuInfo"),
            "/v0/GpuInfo",
            "/prpc/GpuInfo",
            "/v1/GpuInfo",
        }
    )
    observations = []
    for route in legacy_routes:
        for content_type, body in (
            ("application/json", b"{}"),
            ("application/octet-stream", b""),
        ):
            code, payload = call(sock, route, content_type, body)
            if code != 404:
                raise AssertionError(
                    f"removed DstackGuest {route} returned HTTP {code}"
                )
            text = payload.decode(errors="replace")
            if "GpuInfo" not in text and "not found" not in text.lower():
                raise AssertionError("removed method response was not diagnostic")
            observations.append(
                {
                    "route": route,
                    "content_type": content_type,
                    "status": code,
                    "diagnostic": text[:160],
                }
            )
    # Its replacement is v1 AttestGpu, not a hidden alias on the frozen route.
    code, payload = call(
        sock, "/v1/AttestGpu?json", "application/json", b'{"nonce":""}'
    )
    if code == 404:
        raise AssertionError("v1 AttestGpu replacement route is missing")
    # GPU telemetry is a different RPC on a different service: GuestApi.GpuInfo
    # on the guest API listener (tc-gos-guestapi-006). It must stay routed there
    # and return telemetry fields, never an attestation document.
    guest_api = services["GuestApi"]
    telemetry_code, telemetry_body = call(
        guest_api["socket"],
        guest_api["route"].replace("<Method>", "GpuInfo"),
        "application/json",
        b"{}",
    )
    if telemetry_code != 200:
        raise AssertionError(f"GuestApi.GpuInfo returned HTTP {telemetry_code}")
    telemetry = json.loads(telemetry_body)
    if not isinstance(telemetry.get("gpus"), list) or "attestation" in telemetry:
        raise AssertionError("GuestApi.GpuInfo did not return the telemetry schema")
    artifact = out / "artifacts" / "removed-gpu-info.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(
        json.dumps(
            {
                "legacy": observations,
                "v1_status": code,
                "guest_api_gpu_info": {
                    "status": telemetry_code,
                    "fields": sorted(telemetry),
                },
            },
            indent=2,
        )
        + "\n"
    )
    steps = [
        {
            "id": f"{cid}-step-01",
            "status": "PASS",
            "observed": "The candidate guest listener was available.",
        },
        {
            "id": f"{cid}-step-02",
            "status": "PASS",
            "observed": "GpuInfo returned HTTP 404 on the unversioned, /v0, /prpc and /v1 DstackGuest mounts over JSON and protobuf while v1 AttestGpu remained routed.",
        },
        {
            "id": f"{cid}-step-03",
            "status": "PASS",
            "observed": "Repeated removed-route probes were diagnostic and did not affect service availability; telemetry GpuInfo remained on the GuestApi listener only.",
        },
    ]
    (out / "result.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "case_id": cid,
                "status": "PASS",
                "summary": "The never-shipped v0 GpuInfo method remains absent and v1 owns GPU attestation.",
                "steps": steps,
                "artifacts": [
                    {
                        "name": "Removed route observations",
                        "path": "artifacts/removed-gpu-info.json",
                        "step_id": f"{cid}-step-02",
                        "description": "Records bounded HTTP statuses for the removed DstackGuest routes, their v1 replacement, and the separate GuestApi telemetry method.",
                    }
                ],
            },
            indent=2,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

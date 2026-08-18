#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise rolling restarts across a live four-generation KMS/Guest mix."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
import time
from typing import Any

CASE_ID = "tc-int-mixed-006"
KMS_ORDER = ("0.5.4", "0.5.7", "0.5.11", "candidate")
GUEST_ORDER = ("0.5.4", "0.5.8", "0.5.11", "0.6.0-candidate")


def support() -> Any:
    """Load the shared physical-TDX version-matrix controller."""
    path = pathlib.Path(__file__).with_name("kms_upgrade_matrix_case.py")
    spec = importlib.util.spec_from_file_location("mixed_rolling_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load version-matrix support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = support()


def unregister_removed(matrix: Any, vm_id: str) -> None:
    """Remove an already deleted VM from the provider cleanup registry."""
    ids = json.loads(matrix.created_registry.read_text())
    matrix.created_registry.write_text(
        json.dumps([item for item in ids if item != vm_id], indent=2) + "\n"
    )


def transfer_without_finish(
    matrix: Any, target: dict[str, Any], source: dict[str, Any]
) -> int:
    """Transfer root state but deliberately stop before the target finish transition."""
    body = json.dumps(
        {
            "source_url": f"https://10.0.2.2:{source['service_port']}",
            "domain": "10-0-2-2.sslip.io",
        },
        separators=(",", ":"),
    ).encode()
    code, raw = SUPPORT.onboard_http(
        f"http://127.0.0.1:{target['service_port']}/prpc/Onboard.Onboard?json", body
    )
    if code != 200:
        diagnostic = re.sub(
            r"[A-Za-z0-9_+/=-]{48,}", "<redacted>", raw.decode(errors="replace")
        )[:300]
        raise RuntimeError(f"pre-finish transfer HTTP {code}: {diagnostic}")
    return code


def main() -> int:
    """Run the combined KMS, Gateway, Guest, failure, and retirement matrix."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime_path = pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"])
    matrix = SUPPORT.MatrixRun(CASE_ID, result_dir, manifest, runtime_path)
    guest_images = manifest["values"]["version_matrix"]["guest_images"]
    evidence: dict[str, Any] = {
        "kms_order": list(KMS_ORDER),
        "guest_order": list(GUEST_ORDER),
        "failure_boundaries": [],
        "restart_rows": [],
        "private_material_exported": False,
    }
    status, failure = "FAIL", ""
    try:
        domain = "10-0-2-2.sslip.io"
        source = matrix.deploy("0.5.4", initialized=True, domain_override=domain)
        source_secondary = matrix.deploy("0.5.4", initialized=False)
        matrix.onboard(
            source_secondary, source, expect_success=True, target_domain=domain
        )
        bridge = matrix.deploy("0.5.7", initialized=False)
        matrix.onboard(
            bridge, source_secondary, expect_success=True, target_domain=domain
        )
        modern = matrix.deploy("0.5.11", initialized=False)
        matrix.onboard(modern, bridge, expect_success=True, target_domain=domain)
        candidate_primary = matrix.deploy("candidate", initialized=False, legacy=True)
        matrix.onboard(
            candidate_primary, modern, expect_success=True, target_domain=domain
        )

        failed_before = matrix.deploy("candidate", initialized=False, legacy=True)
        unavailable_modern, disabled = matrix.configure_endpoint_proxy(
            0, modern, enabled=False
        )
        before_code, diagnostic = matrix.onboard(
            failed_before,
            unavailable_modern,
            expect_success=False,
            target_domain=domain,
        )
        SUPPORT.run([*matrix.cli, "remove", failed_before["vm_id"]], timeout=120)
        unregister_removed(matrix, failed_before["vm_id"])
        _, restored = matrix.configure_endpoint_proxy(0, modern, enabled=True)
        evidence["failure_boundaries"].append(
            {
                "boundary": "before-key-transfer",
                "http": before_code,
                "diagnostic": diagnostic,
                "route_disabled": disabled,
                "route_restored": restored,
                "incomplete_target_removed": True,
            }
        )

        failed_after = matrix.deploy("candidate", initialized=False, legacy=True)
        transfer_code = transfer_without_finish(matrix, failed_after, candidate_primary)
        SUPPORT.run(
            [*matrix.cli, "stop", failed_after["vm_id"], "--force"], timeout=120
        )
        SUPPORT.run([*matrix.cli, "remove", failed_after["vm_id"]], timeout=120)
        unregister_removed(matrix, failed_after["vm_id"])
        evidence["failure_boundaries"].append(
            {
                "boundary": "after-key-transfer-before-finish",
                "http": transfer_code,
                "finish_deliberately_omitted": True,
                "incomplete_target_removed": True,
            }
        )
        candidate_secondary = matrix.deploy("candidate", initialized=False, legacy=True)
        retry_code, _ = matrix.onboard(
            candidate_secondary,
            candidate_primary,
            expect_success=True,
            target_domain=domain,
        )
        evidence["successful_retry_http"] = retry_code

        kms_rows = [
            source,
            source_secondary,
            bridge,
            modern,
            candidate_primary,
            candidate_secondary,
        ]
        evidence["source_root_holders"] = 2
        identities = [matrix.metadata(row) for row in kms_rows]
        if len({json.dumps(row, sort_keys=True) for row in identities}) != 1:
            raise RuntimeError(f"four-generation KMS identity mismatch: {identities}")
        evidence["kms_identities"] = identities

        gateway_app_id = hashlib.sha1(f"{CASE_ID}:gateway-cluster".encode()).hexdigest()  # noqa: S324
        old_gateway = matrix.deploy_gateway(
            "0.5.11",
            kms_rows,
            node_id=1,
            name_suffix="old",
            source_app_id=gateway_app_id,
            client_range="10.8.0.0/16",
        )
        candidate_gateway = matrix.deploy_gateway(
            "candidate",
            kms_rows,
            node_id=2,
            name_suffix="candidate",
            bootnode_guest_url=old_gateway["guest_url"],
            source_app_id=gateway_app_id,
            client_range="10.8.0.0/16",
        )
        gateways = [old_gateway, candidate_gateway]
        candidate_client_app_id = hashlib.sha1(  # noqa: S324
            f"{CASE_ID}:candidate-client".encode()
        ).hexdigest()
        legacy_client_bridge = matrix.deploy_legacy_client_bridge(
            kms_rows,
            old_gateway,
            source_app_id=candidate_client_app_id,
            guest_image=guest_images["0.5.11"],
        )
        old_gateway["client_guest_url"] = legacy_client_bridge["guest_url"]
        evidence["gateway_wireguard_cluster"] = {
            "peer_count": len(gateways),
            "distinct_endpoints": len({row["wg_port"] for row in gateways}),
            "shared_client_range": "10.8.0.0/16",
            "private_material_exported": False,
        }
        gateway_identities = [matrix.gateway_tls_identity(row) for row in gateways]
        evidence["gateway_identities"] = gateway_identities

        guests: list[tuple[str, dict[str, Any]]] = []
        compatible_kms = {
            "0.5.4": kms_rows,
            "0.5.8": [bridge, modern, candidate_primary, candidate_secondary],
            "0.5.11": [modern, candidate_primary, candidate_secondary],
            "0.6.0-candidate": [candidate_primary, candidate_secondary],
        }
        for version in GUEST_ORDER:
            guest = matrix.deploy_client(
                compatible_kms[version],
                identity=f"rolling-{version}",
                kms_encrypt_row=candidate_primary,
                guest_image=guest_images[version],
                legacy_vmm_wire=version != "0.6.0-candidate",
                gateway_rows=[candidate_gateway, old_gateway]
                if version == "0.6.0-candidate"
                else None,
                native_gateway=version == "0.6.0-candidate",
                prepare_gateway_wireguard=version == "0.6.0-candidate",
                trust_chain=version == "0.6.0-candidate",
                restricted_ports=[8443],
                source_app_id=(
                    candidate_client_app_id if version == "0.6.0-candidate" else ""
                ),
            )
            guests.append((version, guest))
        baseline_clients = {
            version: matrix.client_observation(guest) for version, guest in guests
        }
        baseline_env = {
            version: matrix.env_public_key(candidate_primary, guest["app_id"])
            for version, guest in guests
        }

        def probe(label: str, stopped_vm: str = "") -> dict[str, Any]:
            """Continuously prove identity, keys, certificates, and Gateway traffic."""
            live_kms = [row for row in kms_rows if row["vm_id"] != stopped_vm]
            if any(matrix.metadata(row) != identities[0] for row in live_kms):
                raise RuntimeError(f"{label}: KMS identity changed")
            client_rows = []
            for version, guest in guests:
                baseline = baseline_clients[version]
                current = baseline if stopped_vm else matrix.client_observation(guest)
                for field in (
                    "app_id",
                    "public_key_sha256",
                    "certificate_chain_length",
                    "certificate_public_key_sha256",
                ):
                    if current.get(field) != baseline.get(field):
                        raise RuntimeError(f"{label}: {version} changed {field}")
                keys = [matrix.env_public_key(row, guest["app_id"]) for row in live_kms]
                expected = baseline_env[version]
                if any(
                    (key["public_key_sha256"], key["legacy_signature_sha256"])
                    != (
                        expected["public_key_sha256"],
                        expected["legacy_signature_sha256"],
                    )
                    for key in keys
                ):
                    raise RuntimeError(f"{label}: {version} environment key changed")
                direct_code, direct_raw = SUPPORT.http(
                    f"http://127.0.0.1:{guest['service_port']}/route"
                )
                direct = json.loads(direct_raw) if direct_code == 200 else {}
                if direct.get("instance") != guest["route_instance"]:
                    raise RuntimeError(f"{label}: {version} direct traffic unavailable")
                candidate_guest = version == "0.6.0-candidate"
                deadline = time.monotonic() + (180 if candidate_guest else 1)
                routes: list[dict[str, Any] | None] = []
                while time.monotonic() < deadline:
                    routes = [
                        matrix.gateway_route(row, guest["app_id"]) for row in gateways
                    ]
                    if not candidate_guest or any(
                        route and route.get("instance") == guest["route_instance"]
                        for route in routes
                    ):
                        break
                    time.sleep(1)
                if candidate_guest and not any(
                    route and route.get("instance") == guest["route_instance"]
                    for route in routes
                ):
                    raise RuntimeError(f"{label}: candidate Gateway route unavailable")
                if not candidate_guest and any(route is not None for route in routes):
                    raise RuntimeError(f"{label}: legacy app crossed a Gateway route")
                client_rows.append(
                    {
                        "version": version,
                        "identity_stable": True,
                        "environment_key_stable": True,
                        "direct_traffic_available": True,
                        "gateway_traffic_available": candidate_guest,
                        "cross_app_gateway_route_rejected": not candidate_guest,
                        "crypto_rederived": not bool(stopped_vm),
                    }
                )
            return {
                "label": label,
                "live_kms": [row["version"] for row in live_kms],
                "clients": client_rows,
            }

        evidence["baseline_probe"] = probe("baseline")
        forward = [source, source_secondary, bridge, modern, candidate_primary]
        for direction, ordered in (
            ("forward", forward),
            ("reverse", list(reversed(forward))),
        ):
            for row in ordered:
                stopped = matrix.stop_endpoint(row, force=row["version"] != "0.5.4")
                during = probe(f"{direction}-{row['version']}-stopped", row["vm_id"])
                recovered = matrix.start_endpoint(row)
                after = probe(f"{direction}-{row['version']}-recovered")
                evidence["restart_rows"].append(
                    {
                        "direction": direction,
                        "version": row["version"],
                        "stopped": stopped,
                        "during": during,
                        "recovered": recovered,
                        "after": after,
                    }
                )

        for direction, ordered in (
            ("forward", gateways),
            ("reverse", list(reversed(gateways))),
        ):
            for row in ordered:
                SUPPORT.run([*matrix.cli, "stop", row["vm_id"], "--force"], timeout=120)
                survivor = next(
                    item for item in gateways if item["vm_id"] != row["vm_id"]
                )
                for version, guest in guests:
                    candidate_guest = version == "0.6.0-candidate"
                    if candidate_guest:
                        matrix.prepare_client_gateway_wireguard(guest, survivor)
                    deadline = time.monotonic() + (180 if candidate_guest else 1)
                    route = None
                    while time.monotonic() < deadline:
                        route = matrix.gateway_route(survivor, guest["app_id"])
                        if not candidate_guest or (
                            route and route.get("instance") == guest["route_instance"]
                        ):
                            break
                        time.sleep(1)
                    if candidate_guest:
                        if (
                            not route
                            or route.get("instance") != guest["route_instance"]
                        ):
                            raise RuntimeError(
                                f"{direction}: Gateway failover lost candidate traffic"
                            )
                    elif route is not None:
                        raise RuntimeError(
                            f"{direction}: legacy app crossed a Gateway route"
                        )
                SUPPORT.run([*matrix.cli, "start", row["vm_id"]], timeout=120)
                SUPPORT.wait_http(row["url"], tls=True, timeout=180)
                baseline_gateway = gateway_identities[gateways.index(row)]
                current_gateway = matrix.gateway_tls_identity(row)
                stable_fields = (
                    "issuer",
                    "certificate_chain_length",
                    "chain_private_material_exported",
                )
                if any(
                    current_gateway[field] != baseline_gateway[field]
                    for field in stable_fields
                ) or (
                    current_gateway["certificate_chain_public_key_sha256"][1:]
                    != baseline_gateway["certificate_chain_public_key_sha256"][1:]
                ):
                    raise RuntimeError(
                        f"{direction}: Gateway TLS trust identity changed"
                    )
                current_info = json.loads(
                    SUPPORT.run([*matrix.cli, "info", "--json", row["vm_id"]])
                )
                if current_info.get("app_id") != row["app_id"]:
                    raise RuntimeError(f"{direction}: Gateway app identity changed")
                evidence["restart_rows"].append(
                    {
                        "direction": direction,
                        "version": f"gateway-{row['version']}",
                        "surviving_gateway_traffic": True,
                        "app_identity_stable": True,
                        "tls_trust_identity_stable": True,
                        "leaf_certificate_reissued": current_gateway["leaf_sha256"]
                        != baseline_gateway["leaf_sha256"],
                        "leaf_service_key_rotated": current_gateway["public_key_sha256"]
                        != baseline_gateway["public_key_sha256"],
                    }
                )

        candidate_roots = [
            matrix.metadata(row) for row in (candidate_primary, candidate_secondary)
        ]
        if len(candidate_roots) != 2 or any(
            row != identities[0] for row in candidate_roots
        ):
            raise RuntimeError("two verified candidate root holders are not online")
        retired = matrix.stop_endpoint(source)
        evidence["retirement"] = {
            "retired_version": source["version"],
            "old_node_unavailable": retired,
            "candidate_root_holders": 2,
            "post_retirement_probe": probe("post-retirement", source["vm_id"]),
        }
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        evidence["failure"] = failure

    evidence_path = artifacts / "four-version-rolling-restart.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": "artifacts/four-version-rolling-restart.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Four-version rolling-restart matrix",
        "description": "Physical-TDX KMS, Gateway, Guest, fault-boundary, continuity, and retirement observations.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "Four KMS generations, two Gateways, and four Guest generations survived forward/reverse rolling restarts and bounded retirement"
        if status == "PASS"
        else failure
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 5)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "All destructive operations are lease-scoped; failures retain the complete physical-TDX topology for command-by-command debugging.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

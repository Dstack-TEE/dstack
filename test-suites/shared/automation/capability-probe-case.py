#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Finalise a case as BLOCKED by probing for the capability it requires.

A case may legitimately be unrunnable because the lab lacks the hardware it
needs. Recording that as BLOCKED on an assertion is worthless: nothing shows
the capability was ever checked, and nothing notices when the lab gains it.

This harness probes for the capability named by the case's fixture profile and
records what it observed. It finalises BLOCKED only when the capability is
absent. If the probe finds the capability present the case FAILS, because the
case is then runnable and its BLOCKED registration has become a lie.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Any

# capability -> (human description, probes). Each probe returns the observation
# and whether the capability appears present.
CAPABILITIES: dict[str, str] = {
    "gpu-policy": "an NVIDIA confidential-computing GPU",
    "gpu": "an NVIDIA GPU",
    "sev-snp": "an AMD SEV-SNP platform",
    "hugepages": "preallocated 2 MiB hugepages",
    "acme-dns-sandbox": (
        "an isolated ACME directory, controllable DNS API, and non-production "
        "DNS credential"
    ),
    "gateway-multidomain-caa": "implemented multi-domain Gateway CAA mutation",
    "kms-attested-client": (
        "a fixture-declared client certificate with key-bound verifiable attestation"
    ),
    "kms-onboard-source": "a fixture-declared independent bootstrapped source KMS",
    "cross-platform-attestation": (
        "a fixture-declared complete SEV-SNP, cloud TDX, Nitro TPM, and "
        "Nitro Enclave attestation suite"
    ),
    "tdx-v2-attestation": (
        "a fixture-declared signed TDX quote whose RTMR3 binds V2 runtime events"
    ),
    "tdx-collateral-matrix": (
        "a fixture-declared TDX current, outdated, revoked, expired, malformed, "
        "and network-failure collateral suite"
    ),
    "simulated-attestation-suite": (
        "a fixture-declared five-platform mock evidence suite with matching collateral "
        "and separate development and production verifier policies"
    ),
    "simulator-lifecycle-suite": (
        "a fixture-declared isolated mount namespace with FUSE, controlled TPM and NSM "
        "backends, signal orchestration, and mount/backend fault injection"
    ),
    "tdx-eventlog-cli-suite": (
        "a fixture-declared exclusive resettable TDX guest with RTMR and quote reads, "
        "device fault injection, restart control, and a separate guest identity"
    ),
    "quote-cli-suite": (
        "a fixture-declared hardware guest and simulator with independent quote verification, "
        "TEE and output fault injection, restart control, and a separate guest identity"
    ),
    "ra-key-cli-suite": (
        "a fixture-declared hardware guest and simulator with independent X.509 validation, "
        "output fault injection, restart control, and a separate guest identity"
    ),
    "vtpm-cli-suite": (
        "a fixture-declared GCP vTPM and simulator matrix with controlled EK chain, PCR and "
        "event-log mutations, TPM/network faults, restart control, and a second identity"
    ),
    "versioned-attestation-cli-suite": (
        "a fixture-declared all-platform V0/V1 attestation corpus with independent verification, "
        "encoding/output fault injection, restart control, and a second identity"
    ),
    "kms-getkeys-cli-suite": (
        "a fixture-declared attested KMS endpoint matrix with healthy, timeout, wrong-certificate, "
        "deny and failover modes, output faults, restart control, and a second identity"
    ),
    "kms-provider-failover-suite": (
        "a fixture-declared attested KMS failover matrix plus controlled local sealing-key and "
        "TPM providers, dependency faults, restart control, and a second identity"
    ),
    "guest-identity-matrix-suite": (
        "a fixture-declared five-guest identity matrix with duplicate inputs and "
        "independent compose, image, and instance changes"
    ),
    "configuration-materialization-candidate-kms": (
        "a fixture-declared controlled KMS that authorizes and can retrieve the candidate "
        "guest image for encrypted environment materialization and fault/recovery checks"
    ),
    "gateway-registration-refresh-suite": (
        "a fixture-declared gateway registration matrix with multiple healthy, outage, "
        "malformed-response and wrong-identity endpoints, write faults, restart control, "
        "request capture, and a second identity"
    ),
    "host-api-sealing-suite": (
        "a fixture-declared Host API matrix with ordered queued/direct notification capture, "
        "healthy, timeout, malformed and wrong-quote sealing responses, controlled PCCS "
        "outage, restart control, and a second identity"
    ),
    "supervisor-client-lifecycle-suite": (
        "a fixture-declared prepared async/sync Supervisor client driver with full API, "
        "configuration boundary, delayed daemon, concurrent auto-start, socket replacement, "
        "timeout, restart, and adjacent-process controls"
    ),
    "verifier-image-download-suite": (
        "a fixture-declared full-TDX quote, hash-bound image archive, and controllable "
        "download server with corrupt and traversal variants"
    ),
    "verifier-acpi-swtpm-suite": (
        "a fixture-declared supported-QEMU ACPI matrix and matching full-TDX "
        "swtpm=true attestation"
    ),
    "measurement-cli-suite": (
        "a fixture-declared dstack-mr metadata, firmware, kernel, initrd, rootfs, "
        "QEMU/config vector, and corrupt-artifact matrix"
    ),
    "verifier-tcb-policy-suite": (
        "a fixture-declared TDX, SEV-SNP, Nitro TPM, Nitro Enclave, and GCP "
        "status, advisory, revocation, and conflicting-field evidence matrix"
    ),
    "verifier-ra-certificate-suite": (
        "a fixture-declared guest and gateway RA certificate matrix with chain, "
        "validity, SAN, key-usage, quote, app-info, and image-hash mutations"
    ),
    "verifier-build-supply-chain-suite": (
        "a fixture-declared clean and offline verifier build environment with "
        "wrapped Docker, pin mutation, SBOM, license, generated-output, and "
        "controlled dependency-failure checks"
    ),
    "verifier-config-precedence-suite": (
        "a fixture-declared verifier configuration inventory, file and environment "
        "precedence, invalid-field, mode-selection, outage, and restart matrix"
    ),
    "os-artifact-assembly-suite": (
        "a fixture-declared OS artifact manifest, component digest, UKI "
        "Authenticode, aggregate image hash, and missing/extra mutation matrix"
    ),
    "verifier-platform-strategy-suite": (
        "a fixture-declared six-platform online/offline evidence and signed-measurement "
        "mutation matrix"
    ),
}

CASE_CAPABILITIES = {
    "tc-kms-kms-001": {
        "action": "KMS.GetAppKey",
        "capability": "kms-attested-client",
    },
    "tc-kms-kms-002": {
        "action": "KMS.GetKmsKey",
        "capability": "kms-attested-client",
    },
    "tc-kms-kms-006": {
        "action": "KMS.SignCert",
        "capability": "kms-attested-client",
    },
    "tc-kms-onboard-002": {
        "action": "Onboard.Onboard",
        "capability": "kms-onboard-source",
    },
    "tc-gw-admin-006": {
        "action": "Admin.SetCaa",
        "capability": "gateway-multidomain-caa",
    },
    "tc-gw-admin-026": {
        "action": "Admin.RenewZtDomainCert",
        "capability": "acme-dns-sandbox",
    },
    "tc-gos-attestatio-002": {
        "action": "Cross-platform versioned attestation",
        "capability": "cross-platform-attestation",
    },
    "tc-kms-attestatio-002": {
        "action": "SEV-SNP app authorization",
        "capability": "cross-platform-attestation",
    },
    "tc-kms-attestatio-003": {
        "action": "GCP TDX and Nitro TPM authorization",
        "capability": "cross-platform-attestation",
    },
    "tc-kms-platform-006": {
        "action": "Nitro Enclave app and KMS authorization",
        "capability": "cross-platform-attestation",
    },
    "tc-ver-input-plat-002": {
        "action": "TDX quote collateral and TCB policy matrix",
        "capability": "tdx-collateral-matrix",
    },
    "tc-ver-input-plat-003": {
        "action": "TDX V2 event preimage and RTMR replay verification",
        "capability": "tdx-v2-attestation",
    },
    "tc-ver-image-meas-001": {
        "action": "Image download digest and extraction security matrix",
        "capability": "verifier-image-download-suite",
    },
    "tc-ver-image-meas-003": {
        "action": "ACPI table measurement and swtpm policy matrix",
        "capability": "verifier-acpi-swtpm-suite",
    },
    "tc-ver-image-meas-005": {
        "action": "Measurement cache correctness and concurrency integration matrix",
        "capability": "verifier-image-download-suite",
    },
    "tc-ver-cli-cert-o-003": {
        "action": "OS image hash strict, allowlist, missing, and offline modes",
        "capability": "verifier-image-download-suite",
    },
    "tc-ver-tools-001": {
        "action": "dstack-mr supported configuration CLI matrix",
        "capability": "measurement-cli-suite",
    },
    "tc-ver-tools-002": {
        "action": "dstack-mr boot artifact and command-line boundary matrix",
        "capability": "measurement-cli-suite",
    },
    "tc-ver-tcb-007": {
        "action": "Canonical TCB status, advisory, and auth-policy projection matrix",
        "capability": "verifier-tcb-policy-suite",
    },
    "tc-ver-cli-cert-o-002": {
        "action": "Guest and gateway RA certificate verification matrix",
        "capability": "verifier-ra-certificate-suite",
    },
    "tc-ver-build-002": {
        "action": "Verifier default, file, environment, and mode precedence matrix",
        "capability": "verifier-config-precedence-suite",
    },
    "tc-ver-image-meas-004": {
        "action": "OS artifact manifest and component/aggregate hash binding matrix",
        "capability": "os-artifact-assembly-suite",
    },
    "tc-ver-strategy-006": {
        "action": "Six-platform image verification strategy matrix",
        "capability": "verifier-platform-strategy-suite",
    },
    "tc-ver-input-plat-007": {
        "action": "Five-platform simulated evidence labeling and policy matrix",
        "capability": "simulated-attestation-suite",
    },
    "tc-gos-boot-and-i-004": {
        "action": "Stable app, instance, device, and compose identity",
        "capability": "guest-identity-matrix-suite",
    },
    "tc-gos-boot-and-i-003": {
        "action": "System and user configuration materialization",
        "capability": "configuration-materialization-candidate-kms",
    },
    "tc-gos-setup-006": {
        "action": "KMS URL failover and local/TPM provider orthogonality matrix",
        "capability": "kms-provider-failover-suite",
    },
    "tc-gos-setup-009": {
        "action": "Gateway registration refresh and key-store persistence matrix",
        "capability": "gateway-registration-refresh-suite",
    },
    "tc-gos-setup-010": {
        "action": "Host API notification and sealing-key verification matrix",
        "capability": "host-api-sealing-suite",
    },
    "tc-gos-setup-012": {
        "action": "Supervisor async/sync full API and trusted auto-start matrix",
        "capability": "supervisor-client-lifecycle-suite",
    },
    "tc-gos-setup-017": {
        "action": "Simulator platform selection, mount, failure, and recovery matrix",
        "capability": "simulator-lifecycle-suite",
    },
    "tc-gos-setup-018": {
        "action": "TDX event-log CLI extension, replay, failure, and identity matrix",
        "capability": "tdx-eventlog-cli-suite",
    },
    "tc-gos-setup-019": {
        "action": "Quote and quote-report CLI binding and failure matrix",
        "capability": "quote-cli-suite",
    },
    "tc-gos-setup-020": {
        "action": "RA CA, certificate, and app-key CLI safety matrix",
        "capability": "ra-key-cli-suite",
    },
    "tc-gos-setup-022": {
        "action": "vTPM attest, quote, verify, mutation, and recovery matrix",
        "capability": "vtpm-cli-suite",
    },
    "tc-gos-setup-023": {
        "action": "Versioned attestation create, inspect, JSON, strip, and recovery matrix",
        "capability": "versioned-attestation-cli-suite",
    },
    "tc-gos-setup-024": {
        "action": "KMS GetKeys CLI authorization, failover, output, and recovery matrix",
        "capability": "kms-getkeys-cli-suite",
    },
    "tc-ver-input-plat-005": {
        "action": "SEV-SNP certificate and report verification",
        "capability": "cross-platform-attestation",
    },
    "tc-ver-input-plat-006": {
        "action": "Cloud TDX and Nitro TPM verification",
        "capability": "cross-platform-attestation",
    },
    "tc-ver-nitro-008": {
        "action": "Nitro Enclave document verification and debug rejection",
        "capability": "cross-platform-attestation",
    },
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, delete=False, encoding="utf-8"
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = handle.name
    os.replace(temporary, path)


def read_first_line(path: str) -> str | None:
    """Return the first line of a sysfs file, or None when it is absent."""
    try:
        return pathlib.Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def probe_gpu() -> tuple[bool, dict[str, Any]]:
    """Look for an NVIDIA GPU through both the tool and the device nodes."""
    tool = shutil.which("nvidia-smi")
    listing = None
    if tool:
        process = subprocess.run(
            [tool, "-L"], capture_output=True, text=True, timeout=30, check=False
        )
        listing = process.stdout.strip() or process.stderr.strip()
    nodes = sorted(str(p) for p in pathlib.Path("/dev").glob("nvidia*"))
    observed = {"nvidia_smi": tool, "nvidia_smi_output": listing, "device_nodes": nodes}
    return bool(nodes) or bool(listing and "GPU 0" in listing), observed


def probe_sev_snp() -> tuple[bool, dict[str, Any]]:
    """Look for SEV-SNP through its device nodes and the CPU flags."""
    nodes = [p for p in ("/dev/sev", "/dev/sev-guest") if pathlib.Path(p).exists()]
    try:
        flags = "sev" in pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8")
    except OSError:
        flags = False
    return bool(nodes) or flags, {"device_nodes": nodes, "cpuinfo_reports_sev": flags}


def probe_hugepages() -> tuple[bool, dict[str, Any]]:
    """Report whether any 2 MiB hugepages are preallocated."""
    path = "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
    value = read_first_line(path)
    count = int(value) if value and value.isdigit() else 0
    return count > 0, {"path": path, "nr_hugepages": value, "count": count}


def probe_acme_dns_sandbox() -> tuple[bool, dict[str, Any]]:
    """Check for explicit, non-secret certificate-renewal sandbox declarations."""
    runtime_path = pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"])
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    environment = runtime.get("environment") or {}
    required = (
        "DSTACK_TEST_ACME_DIRECTORY_URL",
        "DSTACK_TEST_DNS_API_URL",
        "DSTACK_TEST_DNS_API_TOKEN_FILE",
    )
    declared = {name: bool(environment.get(name)) for name in required}
    return all(declared.values()), {"declarations": declared}


def probe_gateway_multidomain_caa() -> tuple[bool, dict[str, Any]]:
    """Check the exact candidate source for a real SetCaa implementation."""
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text(
            encoding="utf-8"
        )
    )
    source = pathlib.Path(runtime["repository"]) / "dstack/gateway/src/admin_service.rs"
    content = source.read_bytes()
    unavailable_marker = (
        b"set_caa is not implemented for multi-domain certificates yet" in content
    )
    return not unavailable_marker, {
        "candidate_commit": runtime.get("candidate_commit"),
        "source_sha256": hashlib.sha256(content).hexdigest(),
        "unavailable_marker_present": unavailable_marker,
    }


def probe_declared_fixture_capability(name: str) -> tuple[bool, dict[str, Any]]:
    """Check a case manifest for an explicit high-integrity fixture capability."""
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text(
            encoding="utf-8"
        )
    )
    values = manifest.get("values") or {}
    declarations = {
        "kms-attested-client": values.get("kms_attested_client"),
        "kms-onboard-source": values.get("kms_onboard_source"),
        "cross-platform-attestation": values.get("cross_platform_attestation"),
        "tdx-v2-attestation": values.get("tdx_v2_attestation"),
        "tdx-collateral-matrix": values.get("tdx_collateral_matrix"),
        "simulated-attestation-suite": values.get("simulated_attestation_suite"),
        "simulator-lifecycle-suite": values.get("simulator_lifecycle_suite"),
        "tdx-eventlog-cli-suite": values.get("tdx_eventlog_cli_suite"),
        "quote-cli-suite": values.get("quote_cli_suite"),
        "ra-key-cli-suite": values.get("ra_key_cli_suite"),
        "vtpm-cli-suite": values.get("vtpm_cli_suite"),
        "versioned-attestation-cli-suite": values.get(
            "versioned_attestation_cli_suite"
        ),
        "kms-getkeys-cli-suite": values.get("kms_getkeys_cli_suite"),
        "kms-provider-failover-suite": values.get("kms_provider_failover_suite"),
        "guest-identity-matrix-suite": values.get("guest_identity_matrix_suite"),
        "configuration-materialization-candidate-kms": values.get(
            "configuration_materialization_candidate_kms"
        ),
        "gateway-registration-refresh-suite": values.get(
            "gateway_registration_refresh_suite"
        ),
        "host-api-sealing-suite": values.get("host_api_sealing_suite"),
        "supervisor-client-lifecycle-suite": values.get(
            "supervisor_client_lifecycle_suite"
        ),
        "verifier-image-download-suite": values.get("verifier_image_download_suite"),
        "verifier-acpi-swtpm-suite": values.get("verifier_acpi_swtpm_suite"),
        "measurement-cli-suite": values.get("measurement_cli_suite"),
        "verifier-tcb-policy-suite": values.get("verifier_tcb_policy_suite"),
        "verifier-ra-certificate-suite": values.get("verifier_ra_certificate_suite"),
        "verifier-build-supply-chain-suite": values.get(
            "verifier_build_supply_chain_suite"
        ),
        "verifier-config-precedence-suite": values.get(
            "verifier_config_precedence_suite"
        ),
        "os-artifact-assembly-suite": values.get("os_artifact_assembly_suite"),
        "verifier-platform-strategy-suite": values.get(
            "verifier_platform_strategy_suite"
        ),
    }
    declared = declarations[name]
    present = isinstance(declared, dict) and bool(declared.get("available"))
    return present, {
        "lease_id": manifest.get("lease_id"),
        "profile": manifest.get("profile"),
        "declaration_present": isinstance(declared, dict),
        "available": present,
    }


def probe_kms_attested_client() -> tuple[bool, dict[str, Any]]:
    """Check for an explicitly declared key-bound attested KMS client."""
    return probe_declared_fixture_capability("kms-attested-client")


def probe_kms_onboard_source() -> tuple[bool, dict[str, Any]]:
    """Check for an explicitly declared independent bootstrapped source KMS."""
    return probe_declared_fixture_capability("kms-onboard-source")


def probe_cross_platform_attestation() -> tuple[bool, dict[str, Any]]:
    """Check for the complete fixture-declared cross-platform evidence suite."""
    return probe_declared_fixture_capability("cross-platform-attestation")


def probe_verifier_image_download_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the controlled hash-bound full-TDX image download suite."""
    return probe_declared_fixture_capability("verifier-image-download-suite")


def probe_verifier_acpi_swtpm_suite() -> tuple[bool, dict[str, Any]]:
    """Check for supported-QEMU ACPI fixtures and matching swtpm evidence."""
    return probe_declared_fixture_capability("verifier-acpi-swtpm-suite")


def probe_measurement_cli_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete dstack-mr artifact and configuration matrix."""
    return probe_declared_fixture_capability("measurement-cli-suite")


def probe_verifier_tcb_policy_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete cross-platform TCB policy evidence matrix."""
    return probe_declared_fixture_capability("verifier-tcb-policy-suite")


def probe_verifier_ra_certificate_suite() -> tuple[bool, dict[str, Any]]:
    """Check for complete guest and gateway RA certificate mutation fixtures."""
    return probe_declared_fixture_capability("verifier-ra-certificate-suite")


def probe_verifier_build_supply_chain_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete clean/offline verifier build and mutation suite."""
    return probe_declared_fixture_capability("verifier-build-supply-chain-suite")


def probe_verifier_config_precedence_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete verifier configuration and recovery matrix."""
    return probe_declared_fixture_capability("verifier-config-precedence-suite")


def probe_os_artifact_assembly_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete OS artifact assembly and hash-binding matrix."""
    return probe_declared_fixture_capability("os-artifact-assembly-suite")


def probe_verifier_platform_strategy_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete six-platform image-strategy evidence matrix."""
    return probe_declared_fixture_capability("verifier-platform-strategy-suite")


def probe_simulated_attestation_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete five-platform development-policy evidence suite."""
    return probe_declared_fixture_capability("simulated-attestation-suite")


def probe_simulator_lifecycle_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the isolated five-backend simulator lifecycle fixture."""
    return probe_declared_fixture_capability("simulator-lifecycle-suite")


def probe_tdx_eventlog_cli_suite() -> tuple[bool, dict[str, Any]]:
    """Check for an exclusive resettable TDX event-log CLI fixture."""
    return probe_declared_fixture_capability("tdx-eventlog-cli-suite")


def probe_quote_cli_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the dual-environment quote CLI fault and identity fixture."""
    return probe_declared_fixture_capability("quote-cli-suite")


def probe_ra_key_cli_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the dual-environment RA key CLI fault and identity fixture."""
    return probe_declared_fixture_capability("ra-key-cli-suite")


def probe_vtpm_cli_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the vTPM CLI chain, mutation, fault, and identity fixture."""
    return probe_declared_fixture_capability("vtpm-cli-suite")


def probe_versioned_attestation_cli_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the all-platform versioned-attestation CLI fixture."""
    return probe_declared_fixture_capability("versioned-attestation-cli-suite")


def probe_kms_getkeys_cli_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the controlled attested KMS endpoint and identity matrix."""
    return probe_declared_fixture_capability("kms-getkeys-cli-suite")


def probe_kms_provider_failover_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the KMS, local sealing-key, and TPM provider matrix."""
    return probe_declared_fixture_capability("kms-provider-failover-suite")


def probe_guest_identity_matrix_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete five-guest identity matrix."""
    return probe_declared_fixture_capability("guest-identity-matrix-suite")


def probe_configuration_materialization_candidate_kms() -> tuple[bool, dict[str, Any]]:
    """Check for a KMS that authorizes the candidate materialization guest."""
    return probe_declared_fixture_capability(
        "configuration-materialization-candidate-kms"
    )


def probe_gateway_registration_refresh_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete controlled Gateway refresh and identity matrix."""
    return probe_declared_fixture_capability("gateway-registration-refresh-suite")


def probe_host_api_sealing_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete Host API notification and sealing-key matrix."""
    return probe_declared_fixture_capability("host-api-sealing-suite")


def probe_supervisor_client_lifecycle_suite() -> tuple[bool, dict[str, Any]]:
    """Check for the complete prepared Supervisor client lifecycle matrix."""
    return probe_declared_fixture_capability("supervisor-client-lifecycle-suite")


def probe_tdx_collateral_matrix() -> tuple[bool, dict[str, Any]]:
    """Check for the complete controlled TDX collateral and TCB suite."""
    return probe_declared_fixture_capability("tdx-collateral-matrix")


def probe_tdx_v2_attestation() -> tuple[bool, dict[str, Any]]:
    """Check for signed TDX evidence whose RTMR3 binds V2 runtime events."""
    return probe_declared_fixture_capability("tdx-v2-attestation")


PROBES = {
    "guest-identity-matrix-suite": probe_guest_identity_matrix_suite,
    "gpu-policy": probe_gpu,
    "gpu": probe_gpu,
    "sev-snp": probe_sev_snp,
    "hugepages": probe_hugepages,
    "acme-dns-sandbox": probe_acme_dns_sandbox,
    "gateway-multidomain-caa": probe_gateway_multidomain_caa,
    "kms-attested-client": probe_kms_attested_client,
    "kms-onboard-source": probe_kms_onboard_source,
    "cross-platform-attestation": probe_cross_platform_attestation,
    "tdx-v2-attestation": probe_tdx_v2_attestation,
    "tdx-collateral-matrix": probe_tdx_collateral_matrix,
    "simulated-attestation-suite": probe_simulated_attestation_suite,
    "simulator-lifecycle-suite": probe_simulator_lifecycle_suite,
    "tdx-eventlog-cli-suite": probe_tdx_eventlog_cli_suite,
    "quote-cli-suite": probe_quote_cli_suite,
    "ra-key-cli-suite": probe_ra_key_cli_suite,
    "vtpm-cli-suite": probe_vtpm_cli_suite,
    "versioned-attestation-cli-suite": probe_versioned_attestation_cli_suite,
    "kms-getkeys-cli-suite": probe_kms_getkeys_cli_suite,
    "kms-provider-failover-suite": probe_kms_provider_failover_suite,
    "configuration-materialization-candidate-kms": (
        probe_configuration_materialization_candidate_kms
    ),
    "gateway-registration-refresh-suite": probe_gateway_registration_refresh_suite,
    "host-api-sealing-suite": probe_host_api_sealing_suite,
    "supervisor-client-lifecycle-suite": probe_supervisor_client_lifecycle_suite,
    "verifier-image-download-suite": probe_verifier_image_download_suite,
    "verifier-acpi-swtpm-suite": probe_verifier_acpi_swtpm_suite,
    "measurement-cli-suite": probe_measurement_cli_suite,
    "verifier-tcb-policy-suite": probe_verifier_tcb_policy_suite,
    "verifier-ra-certificate-suite": probe_verifier_ra_certificate_suite,
    "verifier-build-supply-chain-suite": probe_verifier_build_supply_chain_suite,
    "verifier-config-precedence-suite": probe_verifier_config_precedence_suite,
    "os-artifact-assembly-suite": probe_os_artifact_assembly_suite,
    "verifier-platform-strategy-suite": probe_verifier_platform_strategy_suite,
}


def required_capability(plan_root: pathlib.Path, case_id: str) -> str:
    """Resolve the capability the case's fixture profile requires."""
    if case_id in CASE_CAPABILITIES:
        return CASE_CAPABILITIES[case_id]["capability"]
    sys.path.insert(0, str(plan_root / "runner"))
    import render  # noqa: PLC0415

    plan = render.load_plan(plan_root)
    profiles = json.loads(
        (plan_root / "shared" / "fixtures" / "profiles.json").read_text(
            encoding="utf-8"
        )
    )["profiles"]
    for case in plan.cases:
        if case.id != case_id:
            continue
        name = str((case.fixture or {}).get("profile", ""))
        for capability in profiles.get(name, {}).get("required_capabilities", []):
            if capability in PROBES:
                return capability
        raise SystemExit(f"{case_id} profile {name!r} names no probeable capability")
    raise SystemExit(f"{case_id} is not in the index")


def main() -> int:
    """Probe the required capability and finalise the case."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    capability = required_capability(plan_root, case_id)
    step_id = f"{case_id}-step-01"
    print(f"STEP {step_id} START", flush=True)
    present, observed = PROBES[capability]()
    description = CAPABILITIES.get(capability, capability)
    record = {
        "case_id": case_id,
        "action": CASE_CAPABILITIES.get(case_id, {}).get("action"),
        "capability": capability,
        "description": description,
        "present": present,
        "observed": observed,
    }
    atomic_json(artifacts / "capability-probe.json", record)
    print(
        f"EVIDENCE {step_id} - Probes the host for {description} and records "
        "what it found.",
        flush=True,
    )
    print(json.dumps(record, sort_keys=True), flush=True)

    if present:
        # The capability exists, so the case is runnable and must not stay
        # registered as blocked.
        status, summary = (
            "FAIL",
            (
                f"{description} is present, so {case_id} is runnable and must no "
                "longer be recorded as capability-blocked"
            ),
        )
        step_status = "FAIL"
    else:
        status, summary = (
            "BLOCKED",
            (
                f"{description} is not available on this host, so {case_id} cannot "
                "be exercised"
            ),
        )
        step_status = "BLOCKED"
    print(f"STEP {step_id} END - {step_status}", flush=True)

    artifact = {
        "name": "Capability probe",
        "path": "artifacts/capability-probe.json",
        "step_id": step_id,
        "description": (
            "Records the device nodes, tools and counters inspected, proving "
            "whether the required capability is present."
        ),
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [{"id": step_id, "status": step_status, "observed": summary}],
            "artifacts": [artifact],
            "remarks": (
                "Capability-based outcome backed by a probe. This case turns "
                "into a failure the moment the host gains the capability, so "
                "the block cannot silently outlive its reason."
            ),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

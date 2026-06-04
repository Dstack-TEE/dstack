# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Client for dstack-verifier — verifies the KMS's TDX attestation.

The authority does NOT re-implement quote verification in Python. It delegates to
the repo's `dstack-verifier` HTTP service (same verification path as dstack KMS:
dcap-qvl + RTMR replay + OS image hash), then layers the courier-protocol policy
on top: the quote's report_data must bind the transport public key (so an
untrusted CLI cannot substitute its own key and steal the sealed root).
"""

import base64
import hashlib
import struct
from typing import Any, Dict, Optional

import requests


def compute_report_data(nonce: str, transport_pub_b64: str, kms_ts: int) -> bytes:
    """Expected 64-byte TDX report_data binding the courier session.

    report_data = SHA-512( nonce_utf8 || transport_pub(32 raw) || kms_ts(LE i64) )

    The KMS sidecar (key-broker) must compute the identical value when it calls
    getQuote, so verifying report_data proves the quote was produced *by the TEE
    that owns transport_pub*, in response to *this* challenge.
    """
    h = hashlib.sha512()
    h.update(nonce.encode())
    h.update(base64.b64decode(transport_pub_b64))
    h.update(struct.pack("<q", int(kms_ts)))
    return h.digest()


class VerifierError(Exception):
    pass


def verify_attestation(verifier_url: str, attestation_hex: str,
                       vm_config: Optional[str], timeout: int = 120) -> Dict[str, Any]:
    """Call dstack-verifier POST /verify with a full VersionedAttestation
    (TDX + vTPM, from the guest agent's Attest) plus vm_config. Returns the
    parsed response dict. Raises VerifierError on transport failure.
    """
    # dstack-verifier's VerificationRequest has no serde defaults, so every
    # field must be present (null is fine). event_log is carried inside the
    # attestation bundle; vm_config is still needed for the os_image_hash check.
    body: Dict[str, Any] = {
        "quote": None,
        "event_log": None,
        "vm_config": vm_config,
        "attestation": attestation_hex,
        "debug": False,
    }
    try:
        r = requests.post(f"{verifier_url.rstrip('/')}/verify", json=body, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        raise VerifierError(f"verifier call failed: {e}")

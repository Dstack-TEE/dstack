# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Request/response models for the on-prem-lite authority."""

from pydantic import BaseModel
from typing import Any, Dict, List, Optional


# ─── challenge ────────────────────────────────────────────────────────────────

class ChallengeRequest(BaseModel):
    user_id: str


class ChallengeResponse(BaseModel):
    nonce: str
    authority_ts: int


# ─── license (the core endpoint) ──────────────────────────────────────────────

class LicenseRequest(BaseModel):
    user_id: str
    app_id: str                          # which app (gated ∈ tenant's registered apps)
    nonce: str
    transport_pub: str                   # base64 X25519 32 bytes
    kms_ts: int
    attestation: str = ""                # hex dstack VersionedAttestation (TDX+vTPM)
    vm_config: Optional[str] = None      # for dstack-verifier os_image_hash check
    workload_digest: str                 # requested workload image digest (gated)


class LicenseResponse(BaseModel):
    license: Dict[str, Any]              # signed License object (see DESIGN.md)
    sealed_cek: str                      # base64 HPKE-sealed image private key PEM


# ─── admin: tenants & apps ────────────────────────────────────────────────────

class CreateTenantRequest(BaseModel):
    tenant_id: str
    name: Optional[str] = ""


class CreateTenantResponse(BaseModel):
    tenant_id: str
    api_key: str               # plaintext — shown only once at creation
    note: str = "store this api_key now; it is not retrievable later"


class CreateAppRequest(BaseModel):
    app_id: Optional[str] = ""           # authority assigns 40-hex if omitted
    name: Optional[str] = ""


class CreateAppResponse(BaseModel):
    app_id: str


class RegisterWorkloadRequest(BaseModel):
    image: str
    digest: str
    kid: str


# ─── admin: image keys & policy ───────────────────────────────────────────────

class MintKeyRequest(BaseModel):
    kid: Optional[str] = ""              # key id; random hex if omitted


class MintKeyResponse(BaseModel):
    kid: str
    pub_pem: str                         # PEM public key — encrypt with: skopeo --encryption-key jwe:<file>
    created_at: int


class HashRequest(BaseModel):
    hash: str                            # a measurement hash (launcher-compose / os-image)

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class ChallengeRequest(BaseModel):
    user_id: str
    client_ts: int


class ChallengeResponse(BaseModel):
    nonce: str       # hex 32 bytes
    authority_ts: int


class ProvisionRequest(BaseModel):
    user_id: str
    nonce: str
    attestation: str = ""            # hex dstack VersionedAttestation (TDX+vTPM); "" if none
    transport_pub: str               # base64 X25519 32 bytes
    kms_ts: int
    vm_config: Optional[str] = None  # for dstack-verifier os_image_hash check


class MeasureRequest(BaseModel):
    # Read-only measurement discovery — verify the quote's authenticity and
    # report the measured values (no root release, no whitelist enforcement).
    attestation: str = ""
    vm_config: Optional[str] = None


class ProvisionResponse(BaseModel):
    sealed_root: str   # base64 (P0: plaintext root key; TODO: real HPKE)
    auth_bundle: Dict[str, Any]


class UsageReceiptSlot(BaseModel):
    slot_id: str
    app_id: str
    instance_id: str
    compose_hash: str
    last_seen: int


class UsageReceipt(BaseModel):
    user_id: str
    kms_pubkey: str
    report_period: Dict[str, Any]
    active_slots: List[UsageReceiptSlot]
    bundle_seq: int
    kms_sig: str


class SyncAuthRequest(BaseModel):
    user_id: str
    usage_receipt: Optional[UsageReceipt] = None


class SyncAuthResponse(BaseModel):
    auth_bundle: Dict[str, Any]


# ─── admin: multi-user management ─────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    user_id: str           # tenant identifier, becomes the AuthBundle user_id
    name: Optional[str] = ""


class CreateUserResponse(BaseModel):
    user_id: str
    api_key: str               # plaintext — shown only once at creation
    note: str = "store this api_key now; it is not retrievable later"


class UserInfo(BaseModel):
    user_id: str
    name: str
    created_at: int
    bundle_seq: int
    image_count: int
    key_count: int = 0
    has_api_key: bool


class ListUsersResponse(BaseModel):
    users: List[UserInfo]


class RegisterImageRequest(BaseModel):
    app_id: str                                  # workload app id
    allowed_launcher_hashes: List[str] = ["*"]   # launcher compose hashes (gate)
    image_digest: str                            # current encrypted image digest (version pointer)
    cek: Optional[str] = None                    # legacy per-digest CEK; keyring (mint-key) is preferred


class HashRequest(BaseModel):
    hash: str            # a measurement hash (os-image / kms-compose / launcher-compose)


class MintKeyRequest(BaseModel):
    kid: Optional[str] = ""          # key id; random hex if omitted (goes in image annotations)
    not_after: Optional[int] = 0     # unix expiry; 0 = no expiry


class MintKeyResponse(BaseModel):
    kid: str
    pub_pem: str                     # PEM public key — encrypt with: skopeo --encryption-key jwe:<file>
    created_at: int
    not_after: Optional[int] = None

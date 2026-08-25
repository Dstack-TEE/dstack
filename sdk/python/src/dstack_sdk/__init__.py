# SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from .dstack_client_v0 import AsyncDstackClientV0
from .dstack_client_v0 import AsyncTappdClient
from .dstack_client_v0 import AttestResponse
from .dstack_client_v0 import DstackClientV0
from .dstack_client_v0 import EventLog
from .dstack_client_v0 import GetKeyResponse
from .dstack_client_v0 import GetQuoteResponse
from .dstack_client_v0 import GetTlsKeyResponse
from .dstack_client_v0 import InfoResponse
from .dstack_client_v0 import SignResponse
from .dstack_client_v0 import TappdClient
from .dstack_client_v0 import TcbInfo
from .dstack_client_v0 import VerifyResponse
from .dstack_client_v0 import VersionResponse
from .dstack_client_v1 import AsyncDstackClient
from .dstack_client_v1 import AsyncDstackClientV1
from .dstack_client_v1 import AttestGpuResponseV1
from .dstack_client_v1 import AttestResponseV1
from .dstack_client_v1 import DstackClient
from .dstack_client_v1 import DstackClientV1
from .dstack_client_v1 import GetKeyResponseV1
from .dstack_client_v1 import GpuEvidenceBundleV1
from .dstack_client_v1 import InfoResponseV1
from .dstack_client_v1 import IssueCertResponseV1
from .dstack_client_v1 import VersionResponseV1
from .encrypt_env_vars import EnvVar
from .encrypt_env_vars import encrypt_env_vars
from .encrypt_env_vars import encrypt_env_vars_sync
from .get_compose_hash import AppCompose
from .get_compose_hash import DockerConfig
from .get_compose_hash import Requirements
from .get_compose_hash import get_compose_hash
from .verify_env_encrypt_public_key import verify_env_encrypt_public_key
from .verify_env_encrypt_public_key import verify_env_encrypt_public_key_legacy

__all__ = [
    # The default clients: unsuffixed means dstack.guest.v1
    "DstackClient",
    "AsyncDstackClient",
    # The same classes under their explicit names
    "DstackClientV1",
    "AsyncDstackClientV1",
    # Legacy clients for the frozen v0.5.11 surface
    "DstackClientV0",
    "AsyncDstackClientV0",
    "AsyncTappdClient",
    "TappdClient",
    # v0 response types
    "GetKeyResponse",
    "GetTlsKeyResponse",
    "AttestResponse",
    "GetQuoteResponse",
    "InfoResponse",
    "TcbInfo",
    "EventLog",
    "SignResponse",
    "VerifyResponse",
    "VersionResponse",
    # v1 response types
    "IssueCertResponseV1",
    "GetKeyResponseV1",
    "AttestResponseV1",
    "AttestGpuResponseV1",
    "GpuEvidenceBundleV1",
    "InfoResponseV1",
    "VersionResponseV1",
    # Utility functions
    "encrypt_env_vars_sync",
    "encrypt_env_vars",
    "EnvVar",
    "get_compose_hash",
    "AppCompose",
    "DockerConfig",
    "Requirements",
    "verify_env_encrypt_public_key",
    "verify_env_encrypt_public_key_legacy",
]

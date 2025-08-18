# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Compose hash calculation module for dstack SDK.

Provides deterministic JSON serialization and SHA256 hashing of AppCompose configurations,
compatible with the TypeScript implementation.
"""

import hashlib
import json
from typing import Any
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional
from typing import Union

KeyProviderKind = Literal["none", "kms", "local"]


class DockerConfig:
    """Docker configuration for app compose."""

    def __init__(
        self,
        registry: Optional[str] = None,
        username: Optional[str] = None,
        token_key: Optional[str] = None,
    ) -> None:
        """Initialize a new ``DockerConfig`` instance."""
        self.registry = registry
        self.username = username
        self.token_key = token_key

    def to_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation excluding ``None`` fields."""
        result: Dict[str, Any] = {}
        if self.registry is not None:
            result["registry"] = self.registry
        if self.username is not None:
            result["username"] = self.username
        if self.token_key is not None:
            result["token_key"] = self.token_key
        return result


class AppCompose:
    """App compose configuration."""

    def __init__(
        self,
        runner: str,
        manifest_version: Optional[int] = None,
        name: Optional[str] = None,
        features: Optional[List[str]] = None,  # Deprecated
        docker_compose_file: Optional[str] = None,
        docker_config: Optional[DockerConfig] = None,
        public_logs: Optional[bool] = None,
        public_sysinfo: Optional[bool] = None,
        public_tcbinfo: Optional[bool] = None,
        kms_enabled: Optional[bool] = None,
        gateway_enabled: Optional[bool] = None,
        tproxy_enabled: Optional[bool] = None,  # For backward compatibility
        local_key_provider_enabled: Optional[bool] = None,
        key_provider: Optional[KeyProviderKind] = None,
        key_provider_id: Optional[str] = None,
        allowed_envs: Optional[List[str]] = None,
        no_instance_id: Optional[bool] = None,
        secure_time: Optional[bool] = None,
        bash_script: Optional[str] = None,  # Legacy
        pre_launch_script: Optional[str] = None,  # Legacy
        **kwargs: Any,
    ) -> None:
        """Initialize a new ``AppCompose`` instance with arbitrary extra fields."""
        self.runner = runner
        self.manifest_version = manifest_version
        self.name = name
        self.features = features
        self.docker_compose_file = docker_compose_file
        self.docker_config = docker_config
        self.public_logs = public_logs
        self.public_sysinfo = public_sysinfo
        self.public_tcbinfo = public_tcbinfo
        self.kms_enabled = kms_enabled
        self.gateway_enabled = gateway_enabled
        self.tproxy_enabled = tproxy_enabled
        self.local_key_provider_enabled = local_key_provider_enabled
        self.key_provider = key_provider
        self.key_provider_id = key_provider_id
        self.allowed_envs = allowed_envs
        self.no_instance_id = no_instance_id
        self.secure_time = secure_time
        self.bash_script = bash_script
        self.pre_launch_script = pre_launch_script

        # Add any additional fields
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result: Dict[str, Any] = {}

        # Add all attributes that are not None
        for attr_name in dir(self):
            if not attr_name.startswith("_") and not callable(getattr(self, attr_name)):
                value = getattr(self, attr_name)
                if value is not None:
                    if isinstance(value, DockerConfig):
                        result[attr_name] = value.to_dict()
                    else:
                        # Handle special float values
                        if isinstance(value, float):
                            if value != value:  # NaN check
                                result[attr_name] = None
                            elif value == float("inf") or value == float("-inf"):
                                result[attr_name] = None
                            else:
                                result[attr_name] = value
                        else:
                            result[attr_name] = value

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppCompose":
        """Create AppCompose from dictionary."""
        # Handle docker_config
        docker_config: Optional[DockerConfig] = None
        if "docker_config" in data and data["docker_config"] is not None:
            dc = data.pop("docker_config")
            docker_config = DockerConfig(**dc)

        # Handle special float values
        processed_data: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, float):
                if value != value:  # NaN check
                    processed_data[key] = None
                elif value == float("inf") or value == float("-inf"):
                    processed_data[key] = None
                else:
                    processed_data[key] = value
            else:
                processed_data[key] = value

        runner_value = processed_data.pop("runner")
        runner: str = str(runner_value)
        return cls(runner=runner, docker_config=docker_config, **processed_data)


def sort_object(obj: Any) -> Any:
    """Recursively sort object keys lexicographically.

    This is crucial for deterministic JSON.stringify.
    """
    if obj is None:
        return obj
    elif isinstance(obj, list):
        return [sort_object(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: sort_object(value) for key, value in sorted(obj.items())}
    else:
        return obj


def preprocess_app_compose(app_compose: AppCompose) -> AppCompose:
    """Preprocess app compose by removing conflicting fields based on runner."""
    # Create a copy
    data = app_compose.to_dict()

    if data.get("runner") == "bash" and "docker_compose_file" in data:
        del data["docker_compose_file"]
    elif data.get("runner") == "docker-compose" and "bash_script" in data:
        del data["bash_script"]

    if "pre_launch_script" in data and not data["pre_launch_script"]:
        del data["pre_launch_script"]

    return AppCompose.from_dict(data)


def to_deterministic_json(app_compose: AppCompose) -> str:
    """Serialize to deterministic JSON following cross-language standards.

    - Recursively sorts object keys lexicographically
    - Compact output (no spaces)
    - Handles special values (NaN, Infinity) by converting them to null
    - UTF-8 encoding (default in Python)
    """
    data = sort_object(app_compose.to_dict())

    def convert_special_values(obj: Any) -> Any:
        """Convert NaN and Infinity to null for deterministic output."""
        if isinstance(obj, float):
            if obj != obj:  # NaN check
                return None
            if obj == float("inf") or obj == float("-inf"):
                return None
        return obj

    def json_serializer(obj: Any) -> Any:
        """Handle special float values during JSON serialization."""
        return convert_special_values(obj)

    # Convert special values recursively
    def process_data(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {key: process_data(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [process_data(item) for item in obj]
        else:
            return convert_special_values(obj)

    processed_data = process_data(data)
    return json.dumps(processed_data, separators=(",", ":"), ensure_ascii=False)


def get_compose_hash(
    app_compose: Union[AppCompose, Dict[str, Any]], normalize: bool = False
) -> str:
    """Calculate SHA256 hash of app compose configuration.

    Args:
        app_compose: AppCompose object or dictionary
        normalize: Whether to preprocess the compose (remove conflicting fields)

    Returns:
        str: SHA256 hash as hex string

    """
    if isinstance(app_compose, dict):
        app_compose = AppCompose.from_dict(app_compose)

    if normalize:
        app_compose = preprocess_app_compose(app_compose)

    manifest_str = to_deterministic_json(app_compose)
    return hashlib.sha256(manifest_str.encode("utf-8")).hexdigest()

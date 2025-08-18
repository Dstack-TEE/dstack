# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from dstack_sdk.get_compose_hash import AppCompose
from dstack_sdk.get_compose_hash import DockerConfig
from dstack_sdk.get_compose_hash import get_compose_hash
from dstack_sdk.get_compose_hash import sort_object


def test_deterministic_json_key_sorting():
    """Test that object keys are sorted lexicographically."""
    compose1 = AppCompose(
        runner="docker-compose",
        docker_compose_file="docker-compose.yml",
        bash_script="start.sh",
    )

    compose2 = AppCompose(
        bash_script="start.sh",
        docker_compose_file="docker-compose.yml",
        runner="docker-compose",
    )

    # Both should produce the same hash despite different key order
    assert get_compose_hash(compose1) == get_compose_hash(compose2)


def test_nested_object_key_sorting():
    """Test that nested object keys are sorted."""
    config1 = DockerConfig(registry="docker.io", username="user", token_key="token")

    config2 = DockerConfig(token_key="token", username="user", registry="docker.io")

    compose1 = AppCompose(runner="docker-compose", docker_config=config1)

    compose2 = AppCompose(runner="docker-compose", docker_config=config2)

    assert get_compose_hash(compose1) == get_compose_hash(compose2)


def test_array_order_preservation():
    """Test that array order is preserved."""
    compose1 = AppCompose(
        runner="docker-compose", allowed_envs=["NODE_ENV", "PORT", "DB_URL"]
    )

    compose2 = AppCompose(
        runner="docker-compose", allowed_envs=["PORT", "DB_URL", "NODE_ENV"]
    )

    # Different array orders should produce different hashes
    assert get_compose_hash(compose1) != get_compose_hash(compose2)


def test_preprocessing_bash_runner():
    """Test preprocessing removes docker_compose_file when runner is bash."""
    compose = AppCompose(
        runner="bash", bash_script="start.sh", docker_compose_file="docker-compose.yml"
    )

    hash_normalized = get_compose_hash(compose, normalize=True)

    compose2 = AppCompose(runner="bash", bash_script="start.sh")

    assert hash_normalized == get_compose_hash(compose2, normalize=True)


def test_preprocessing_docker_compose_runner():
    """Test preprocessing removes bash_script when runner is docker-compose."""
    compose = AppCompose(
        runner="docker-compose",
        docker_compose_file="docker-compose.yml",
        bash_script="start.sh",
    )

    hash_normalized = get_compose_hash(compose, normalize=True)

    compose2 = AppCompose(
        runner="docker-compose", docker_compose_file="docker-compose.yml"
    )

    assert hash_normalized == get_compose_hash(compose2, normalize=True)


def test_preprocessing_empty_pre_launch_script():
    """Test preprocessing removes empty pre_launch_script."""
    compose1 = AppCompose(
        runner="docker-compose",
        docker_compose_file="docker-compose.yml",
        pre_launch_script="",
    )

    compose2 = AppCompose(
        runner="docker-compose", docker_compose_file="docker-compose.yml"
    )

    assert get_compose_hash(compose1, normalize=True) == get_compose_hash(
        compose2, normalize=True
    )


def test_special_value_handling():
    """Test that NaN and Infinity are converted to null."""
    data_with_nan = {"runner": "docker-compose", "special_value": float("nan")}

    data_with_null = {"runner": "docker-compose", "special_value": None}

    compose1 = AppCompose.from_dict(data_with_nan)
    compose2 = AppCompose.from_dict(data_with_null)

    # Should produce same hash since NaN becomes null
    assert get_compose_hash(compose1) == get_compose_hash(compose2)


def test_cross_language_compatibility():
    """Test deterministic hash for reference data."""
    compose = AppCompose(
        runner="docker-compose",
        docker_compose_file="docker-compose.yml",
        manifest_version=1,
        name="test-app",
        public_logs=True,
        kms_enabled=False,
        allowed_envs=["NODE_ENV"],
    )

    hash_result = get_compose_hash(compose)

    # Should be a deterministic 64-character hex hash
    assert len(hash_result) == 64
    assert all(c in "0123456789abcdef" for c in hash_result)

    # Should be consistent across runs
    assert hash_result == get_compose_hash(compose)


def test_utf8_support():
    """Test handling of non-ASCII characters."""
    compose1 = AppCompose(
        runner="docker-compose", name="测试应用", bash_script="echo '🚀 Deploy'"
    )

    compose2 = AppCompose(
        bash_script="echo '🚀 Deploy'", runner="docker-compose", name="测试应用"
    )

    # Should be same despite key order
    assert get_compose_hash(compose1) == get_compose_hash(compose2)


def test_empty_compose():
    """Test handling of minimal compose."""
    compose = AppCompose(runner="bash")
    hash_result = get_compose_hash(compose)

    assert len(hash_result) == 64
    assert isinstance(hash_result, str)


def test_boolean_values():
    """Test handling of boolean values."""
    compose1 = AppCompose(
        runner="docker-compose", public_logs=True, kms_enabled=False, secure_time=True
    )

    compose2 = AppCompose(
        secure_time=True, public_logs=True, runner="docker-compose", kms_enabled=False
    )

    assert get_compose_hash(compose1) == get_compose_hash(compose2)


def test_normalize_parameter():
    """Test that normalize parameter controls preprocessing."""
    compose = AppCompose(
        runner="bash", bash_script="start.sh", docker_compose_file="docker-compose.yml"
    )

    hash_without_normalize = get_compose_hash(compose, normalize=False)
    hash_with_normalize = get_compose_hash(compose, normalize=True)

    # Should be different because preprocessing is only applied with normalize=True
    assert hash_without_normalize != hash_with_normalize


def test_docker_config():
    """Test DockerConfig handling."""
    config = DockerConfig(
        registry="docker.io", username="testuser", token_key="secret123"
    )

    compose = AppCompose(runner="docker-compose", docker_config=config)

    hash_result = get_compose_hash(compose)
    assert isinstance(hash_result, str)
    assert len(hash_result) == 64


def test_key_provider_fields():
    """Test key provider related fields."""
    compose = AppCompose(
        runner="docker-compose",
        key_provider="kms",
        key_provider_id="abcd1234",
        local_key_provider_enabled=True,
    )

    hash_result = get_compose_hash(compose)
    assert isinstance(hash_result, str)
    assert len(hash_result) == 64


def test_from_dict_conversion():
    """Test AppCompose.from_dict functionality."""
    data = {
        "runner": "docker-compose",
        "manifest_version": 1,
        "name": "test-app",
        "public_logs": True,
        "docker_config": {"registry": "docker.io", "username": "user"},
    }

    compose = AppCompose.from_dict(data)

    assert compose.runner == "docker-compose"
    assert compose.manifest_version == 1
    assert compose.name == "test-app"
    assert compose.public_logs is True
    assert isinstance(compose.docker_config, DockerConfig)
    assert compose.docker_config.registry == "docker.io"


def test_sort_object_function():
    """Test the sort_object utility function."""
    obj = {"gamma": 3, "alpha": 1, "beta": 2, "nested": {"z": 26, "a": 1}}

    sorted_obj = sort_object(obj)
    keys = list(sorted_obj.keys())

    # Keys should be sorted
    assert keys == ["alpha", "beta", "gamma", "nested"]

    # Nested keys should also be sorted
    nested_keys = list(sorted_obj["nested"].keys())
    assert nested_keys == ["a", "z"]

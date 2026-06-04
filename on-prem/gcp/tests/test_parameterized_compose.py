#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Dict
from typing import Tuple


REPO_ROOT = Path(__file__).resolve().parents[3]
TEMPLATE_ROOT = REPO_ROOT / "on-prem" / "gcp" / "deploy-templates"


def app_compose_bytes(template_name: str) -> bytes:
    template = TEMPLATE_ROOT / template_name
    app = json.loads((template / "app.json").read_text())
    compose = (template / "docker-compose.yaml").read_text()
    prelaunch = (template / "prelaunch.sh").read_text()
    app_compose = {
        "manifest_version": 2,
        "name": app["name"],
        "runner": "docker-compose",
        "docker_compose_file": compose,
        "gateway_enabled": app["gateway_enabled"],
        "public_logs": app["public_logs"],
        "public_sysinfo": app["public_sysinfo"],
        "public_tcbinfo": app["public_tcbinfo"],
        "key_provider_id": app["key_provider_id"],
        "allowed_envs": app["allowed_envs"],
        "no_instance_id": app["no_instance_id"],
        "secure_time": app["secure_time"],
        "key_provider": app["key_provider"],
        "storage_fs": app["storage_fs"],
        "pre_launch_script": prelaunch,
    }
    return json.dumps(app_compose, indent=2, ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_prelaunch(
    template_name: str,
    user_config: Dict[str, str],
) -> Tuple[subprocess.CompletedProcess, str]:
    template = TEMPLATE_ROOT / template_name
    with tempfile.TemporaryDirectory() as td:
        workdir = Path(td)
        (workdir / "user_config").write_text(json.dumps(user_config))
        env = os.environ.copy()
        env["PRELAUNCH_SKIP_DOCKER_LOGIN"] = "1"
        result = subprocess.run(
            ["sh", str(template / "prelaunch.sh")],
            cwd=workdir,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        env_text = (workdir / ".env").read_text() if (workdir / ".env").exists() else ""
        return result, env_text


class ParameterizedComposeTests(unittest.TestCase):
    def test_runtime_registry_and_ip_inputs_do_not_change_compose_hash(self) -> None:
        cases = [
            (
                "kms",
                {
                    "DSTACK_REGISTRY": "us-central1-docker.pkg.dev/acme-prod/dstack-private",
                    "SWP_PROXY": "10.128.0.53:80",
                },
                {
                    "DSTACK_REGISTRY": "europe-west4-docker.pkg.dev/other-prod/dstack-private",
                    "SWP_PROXY": "10.42.3.9:8080",
                },
            ),
            (
                "workload",
                {
                    "DSTACK_REGISTRY": "us-central1-docker.pkg.dev/acme-prod/dstack-private",
                    "KMS_HOST": "10.128.15.220",
                },
                {
                    "DSTACK_REGISTRY": "asia-northeast1-docker.pkg.dev/other-prod/dstack-private",
                    "KMS_HOST": "10.8.7.6",
                },
            ),
        ]
        for template_name, first, second in cases:
            with self.subTest(template=template_name):
                first_result, first_env = run_prelaunch(template_name, first)
                second_result, second_env = run_prelaunch(template_name, second)
                self.assertEqual(first_result.returncode, 0, first_result.stderr)
                self.assertEqual(second_result.returncode, 0, second_result.stderr)
                self.assertNotEqual(first_env, second_env)

                first_app_compose = app_compose_bytes(template_name)
                second_app_compose = app_compose_bytes(template_name)
                self.assertEqual(first_app_compose, second_app_compose)
                self.assertEqual(sha256(first_app_compose), sha256(second_app_compose))
                self.assertIn(b"${DSTACK_REGISTRY}", first_app_compose)
                self.assertNotIn(first["DSTACK_REGISTRY"].encode(), first_app_compose)
                self.assertNotIn(second["DSTACK_REGISTRY"].encode(), first_app_compose)

    def test_malformed_dstack_registry_is_rejected_fail_closed(self) -> None:
        bad_registries = [
            "us-central1-docker.pkg.dev/acme-prod/dstack-private@evil",
            "us-central1-docker.pkg.dev/Acme-Prod/dstack-private",
            "us-central1-docker.pkg.dev/acme prod/dstack-private",
        ]
        for registry in bad_registries:
            with self.subTest(registry=registry):
                result, env_text = run_prelaunch(
                    "kms",
                    {
                        "DSTACK_REGISTRY": registry,
                        "SWP_PROXY": "10.128.0.53:80",
                    },
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("prelaunch: invalid DSTACK_REGISTRY", result.stderr)
                self.assertEqual(env_text, "")


if __name__ == "__main__":
    unittest.main()

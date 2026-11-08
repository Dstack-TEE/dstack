# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

"""Focused regression tests for vmm-cli update request construction."""

from __future__ import annotations

import argparse
import base64
import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from eth_keys import keys
from eth_utils import keccak
from pyhpke import AEADId, CipherSuite, KDFId, KEMId


def load_vmm_cli():
    """Load the executable vmm-cli.py as a normal Python module."""
    path = Path(__file__).resolve().parents[1] / "vmm-cli.py"
    spec = importlib.util.spec_from_file_location("dstack_vmm_cli", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VMM_CLI = load_vmm_cli()


class UpdateVmTests(unittest.TestCase):
    """Verify update flags are not silently discarded by the CLI."""

    def test_kms_urls_are_sent_to_upgrade_app(self) -> None:
        """Send both the update flag and requested KMS URL list."""
        cli = VMM_CLI.VmmCLI("http://127.0.0.1:8080")
        calls: list[tuple[str, dict]] = []
        cli.rpc_call = lambda method, params=None: calls.append((method, params)) or {}

        with contextlib.redirect_stdout(io.StringIO()):
            cli.update_vm("vm-id", kms_urls=["https://kms.example:8000"])

        self.assertEqual(
            calls,
            [
                (
                    "UpgradeApp",
                    {
                        "id": "vm-id",
                        "update_kms_urls": True,
                        "kms_urls": ["https://kms.example:8000"],
                    },
                )
            ],
        )


class SealedEnvTests(unittest.TestCase):
    def setUp(self):
        self.app_id = "11" * 20
        self.epoch = 3
        self.timestamp = 1700000000
        self.clock = patch.object(VMM_CLI.time, "time", return_value=self.timestamp)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.signer = keys.PrivateKey(b"\x22" * 32)
        self.pin = self.signer.public_key.to_compressed_bytes().hex()
        self.suite = CipherSuite.new(
            KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
        )
        self.recipient = self.suite.kem.derive_key_pair(b"test recipient key material")
        self.response = {
            "public_key": self.recipient.public_key.to_public_bytes().hex(),
            "root_epoch": self.epoch,
            "timestamp": self.timestamp,
        }
        digest = keccak(
            b"dstack-sealed-env-pubkey-v1:"
            + bytes.fromhex(self.app_id)
            + self.epoch.to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + bytes.fromhex(self.response["public_key"])
            + self.timestamp.to_bytes(8, "big")
        )
        self.response["signature"] = self.signer.sign_msg_hash(digest).to_bytes().hex()
        self.cli = VMM_CLI.VmmCLI("https://vmm.example")
        self.cli.client.request = Mock(return_value=(200, self.response))
        self.cli.get_app_env_encrypt_pub_key = Mock(
            return_value=self.response["public_key"]
        )
        self.pins = patch.object(VMM_CLI, "load_whitelist", return_value=[self.pin])
        self.pins.start()
        self.addCleanup(self.pins.stop)
        self.envs = {"SECRET": "synthetic test value", "UNICODE": "测试"}

    def decrypt(self, payload):
        self.assertNotIn("encrypted_env", payload)
        envelope = json.loads(bytes.fromhex(payload["sealed_env"]))
        self.assertEqual(set(envelope), {"version", "root_epoch", "app_epoch", "enc", "ciphertext"})
        self.assertEqual(envelope["version"], 1)
        self.assertEqual(envelope["root_epoch"], self.epoch)
        enc = base64.b64decode(envelope["enc"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        receiver = self.suite.create_recipient_context(
            enc,
            self.recipient.private_key,
            info=f"dstack-sealed-env-v1:{self.epoch}:0".encode(),
        )
        plaintext = json.loads(receiver.open(ciphertext, aad=b""))
        self.assertEqual(
            plaintext, {"env": [{"key": k, "value": v} for k, v in self.envs.items()]}
        )
        wrong_epoch = self.suite.create_recipient_context(
            enc, self.recipient.private_key, info=b"dstack-sealed-env-v1:0:0"
        )
        with self.assertRaises(Exception):
            wrong_epoch.open(ciphertext, aad=b"")

    def test_sealed_payload_round_trip_and_normalized_pins(self):
        for pin in [self.pin, "0x" + self.pin.upper()]:
            with (
                self.subTest(pin=pin),
                patch.object(VMM_CLI, "load_whitelist", return_value=[pin]),
            ):
                self.decrypt(self.cli.encrypt_env_payload(self.envs, self.app_id, None, True))
        self.cli.get_app_env_encrypt_pub_key.assert_not_called()

    def test_app_epoch_is_signed_and_used_for_sealing(self):
        self.response["app_epoch"] = 2
        digest = keccak(
            b"dstack-sealed-env-pubkey-v1:" + bytes.fromhex(self.app_id)
            + self.epoch.to_bytes(4, "big") + (2).to_bytes(4, "big")
            + bytes.fromhex(self.response["public_key"])
            + self.timestamp.to_bytes(8, "big")
        )
        self.response["signature"] = self.signer.sign_msg_hash(digest).to_bytes().hex()
        payload = self.cli.encrypt_env_payload(self.envs, self.app_id, None, True)
        envelope = json.loads(bytes.fromhex(payload["sealed_env"]))
        self.assertEqual(envelope["version"], 1)
        self.assertEqual(envelope["app_epoch"], 2)
        receiver = self.suite.create_recipient_context(
            base64.b64decode(envelope["enc"]), self.recipient.private_key,
            info=f"dstack-sealed-env-v1:{self.epoch}:2".encode(),
        )
        plaintext = json.loads(receiver.open(base64.b64decode(envelope["ciphertext"])))
        self.assertEqual(plaintext, {"env": [{"key": k, "value": v} for k, v in self.envs.items()]})
        self.response["app_epoch"] = 1
        with self.assertRaises(ValueError):
            self.cli.encrypt_env_payload(self.envs, self.app_id, None, True)

    def test_unpinned_signer_never_becomes_trusted(self):
        for pins in [
            [],
            [keys.PrivateKey(b"\x33" * 32).public_key.to_compressed_bytes().hex()],
        ]:
            with (
                self.subTest(pins=pins),
                patch.object(VMM_CLI, "load_whitelist", return_value=pins),
                patch.object(self.cli, "confirm_untrusted_signer") as confirm,
            ):
                with self.assertRaisesRegex(ValueError, "not pinned"):
                    self.cli.encrypt_env_payload(self.envs, self.app_id, None, True)
                confirm.assert_not_called()
        self.cli.get_app_env_encrypt_pub_key.assert_not_called()

    def test_signature_binds_every_field_and_app(self):
        cases = [
            ("public_key", "44" * 32),
            ("root_epoch", 4),
            ("timestamp", self.timestamp + 1),
            ("signature", "00" * 65),
            ("signature", "00" * 64),
            ("public_key", "00" * 31),
            ("root_epoch", -1),
            ("root_epoch", 2**32),
            ("root_epoch", True),
            ("timestamp", -1),
            ("timestamp", 2**64),
            ("timestamp", True),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.cli.client.request.return_value = (
                    200,
                    {**self.response, field: value},
                )
                with self.assertRaises(Exception):
                    self.cli.encrypt_env_payload(self.envs, self.app_id, None, True)
        self.cli.client.request.return_value = (200, self.response)
        for app_id in ["55" * 20, "11" * 19]:
            with self.assertRaises(ValueError):
                self.cli.encrypt_env_payload(self.envs, app_id, None, True)
        self.cli.get_app_env_encrypt_pub_key.assert_not_called()

    def test_pinned_signed_key_timestamp_window(self):
        for age in [-60, 0, 300]:
            with self.subTest(age=age), patch.object(
                VMM_CLI.time, "time", return_value=self.timestamp + age
            ):
                self.decrypt(self.cli.encrypt_env_payload(self.envs, self.app_id, None, True))
        for age, reason in [(-61, "future"), (301, "stale")]:
            with self.subTest(age=age), patch.object(
                VMM_CLI.time, "time", return_value=self.timestamp + age
            ):
                with self.assertRaisesRegex(ValueError, reason):
                    self.cli.encrypt_env_payload(self.envs, self.app_id, None, True)
        self.cli.get_app_env_encrypt_pub_key.assert_not_called()

    def test_public_key_request_contains_only_app_id(self):
        response = self.cli.get_sealed_env_pub_key(self.app_id)
        self.assertEqual(
            self.cli.client.request.call_args.kwargs["body"],
            {"app_id": self.app_id},
        )
        self.assertEqual(response["root_epoch"], self.epoch)

    def test_missing_rpc_cannot_replay_a_legacy_recipient(self):
        legacy_digest = keccak(
            b"dstack-env-encrypt-pubkey:" + bytes.fromhex(self.app_id)
            + bytes.fromhex(self.response["public_key"])
        )
        legacy = {
            "public_key": self.response["public_key"],
            "signature": self.signer.sign_msg_hash(legacy_digest).to_bytes().hex(),
        }
        missing = {"error": "Service not found: GetSealedEnvPubKey"}
        errors = [(status, missing) for status in [400, 404]]
        errors += [
            (400, {"error": f"Request failed with status={status}, error={json.dumps(missing)}"})
            for status in ["400 Bad Request", "404 Not Found"]
        ]
        for error in errors:
            with self.subTest(error=error), patch.object(VMM_CLI, "VmmClient") as client:
                client.return_value.request.side_effect = [error, (200, legacy)]
                with self.assertRaises(RuntimeError):
                    self.cli.encrypt_env_payload(self.envs, self.app_id, "https://kms.example", True)
                client.return_value.request.assert_called_once()
        self.cli.get_app_env_encrypt_pub_key.assert_not_called()

    def test_errors_and_bad_responses_do_not_downgrade(self):
        for status, body in [
            (401, {"error": "Service not found: GetSealedEnvPubKey"}),
            (403, {"error": "forbidden"}),
            (404, "Not Found"),
            (400, {"error": "invalid app"}),
            (500, {"error": "unavailable"}),
            (400, {"error": 'Request failed with status=500 Internal Server Error, error={"error":"Service not found: GetSealedEnvPubKey"}'}),
            (400, {"error": 'Request failed with status=404 Not Found, error={"error":"other service"}'}),
            (400, {"error": 'Request failed with status=404 Not Found, error=invalid'}),
            (200, {}),
            (200, "invalid JSON"),
        ]:
            with self.subTest(status=status, body=body):
                self.cli.client.request.return_value = (status, body)
                with self.assertRaises(Exception):
                    self.cli.encrypt_env_payload(self.envs, self.app_id, None, True)
        self.cli.client.request.side_effect = TimeoutError("test timeout")
        with self.assertRaises(TimeoutError):
            self.cli.encrypt_env_payload(self.envs, self.app_id, None, True)
        self.cli.get_app_env_encrypt_pub_key.assert_not_called()

    def test_direct_kms_verifies_pin_and_does_not_forward_vmm_credentials(self):
        with patch.object(VMM_CLI, "VmmClient") as client:
            client.return_value.request.return_value = (200, self.response)
            self.decrypt(
                self.cli.encrypt_env_payload(
                    self.envs, self.app_id, "https://kms.example", True
                )
            )
            client.assert_called_once_with("https://kms.example", verify_tls=False)
        self.cli.get_app_env_encrypt_pub_key.assert_not_called()

    def test_image_downgrade_and_env_replacement_share_one_request(self):
        def rpc(method, params=None):
            if method == "GetInfo":
                return {"found": True, "info": {"app_id": self.app_id, "configuration": {
                    "image": "new", "compose_file": '{"kms_enabled":true}',
                }}}
            if method == "ListImages":
                return {"images": [{"name": "new", "sealed_env": True}, {"name": "old"}]}
            return {}
        self.cli.rpc_call = Mock(side_effect=rpc)
        with patch.object(VMM_CLI, "parse_env_file", return_value=self.envs), contextlib.redirect_stdout(io.StringIO()):
            self.cli.update_vm("vm", image="old", env_file="env", kms_urls=["https://kms.example"])
        calls = self.cli.rpc_call.call_args_list
        self.assertNotIn("ResizeVm", [call.args[0] for call in calls])
        method, payload = calls[-1].args
        self.assertEqual(method, "UpgradeApp")
        self.assertEqual(payload["image"], "old")
        self.assertIn("encrypted_env", payload)
        self.assertNotIn("sealed_env", payload)
        self.cli.client.request.assert_not_called()

    def test_create_update_and_update_env_send_only_the_negotiated_field(self):
        compose = json.dumps({"kms_enabled": True})
        args = argparse.Namespace(
            compose="compose.json",
            env_file="env",
            name="vm",
            image="image",
            vcpu=1,
            memory=1024,
            disk=10,
            app_id=self.app_id,
            user_config=None,
            port=None,
            hugepages=False,
            pin_numa=False,
            stopped=False,
            no_tee=False,
            annotation=None,
            disk_prealloc=None,
            simulated_tee=None,
            swap=None,
            ppcie=False,
            gpu=None,
            kms_url=["https://kms.example"],
            gateway_url=None,
            net_queues=None,
            net=None,
            net_vhost=None,
            kms_encrypt_url=None,
        )

        def rpc(method, params=None):
            if method == "ListImages":
                return {"images": [{"name": "image", **capability}]}
            if method == "GetInfo":
                return {
                    "found": True,
                    "info": {
                        "app_id": self.app_id,
                        "configuration": {"compose_file": compose, "image": "image"},
                    },
                }
            return {"id": "vm"}

        self.cli.rpc_call = Mock(side_effect=rpc)
        with (
            patch.object(VMM_CLI.os.path, "exists", return_value=True),
            patch.object(VMM_CLI, "read_utf8", return_value=compose),
            patch.object(VMM_CLI, "parse_env_file", return_value=self.envs),
            patch.object(VMM_CLI, "VmmClient") as client,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            for capability in [{"sealed_env": True}, {"sealed_env": False}, {}]:
                client.return_value.request.return_value = (200, self.response)
                for action in [
                    lambda: self.cli.create_vm(args),
                    lambda: self.cli.update_vm(
                        "vm", env_file="env", kms_urls=args.kms_url
                    ),
                    lambda: self.cli.update_vm_env("vm", self.envs, args.kms_url),
                ]:
                    with self.subTest(capability=capability, action=action):
                        self.cli.rpc_call.reset_mock()
                        action()
                        method, payload = self.cli.rpc_call.call_args.args
                        self.assertIn(method, ["CreateVm", "UpgradeApp"])
                        if capability.get("sealed_env"):
                            self.decrypt(payload)
                        else:
                            self.assertIn("encrypted_env", payload)
                            self.assertNotIn("sealed_env", payload)


if __name__ == "__main__":
    unittest.main()

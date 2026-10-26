# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dstack-cloud AWS EBS Direct helpers."""

import base64
import hashlib
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPT_PATH = Path(__file__).parents[1] / "bin" / "dstack-cloud"
LOADER = SourceFileLoader("dstack_cloud", str(SCRIPT_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT_PATH}")
DSTACK_CLOUD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DSTACK_CLOUD
SPEC.loader.exec_module(DSTACK_CLOUD)


def aws_result(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess:
    """Build a mocked AWS CLI result."""
    return subprocess.CompletedProcess(
        args=["aws"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class AwsEbsDirectTests(unittest.TestCase):
    """Verify RAW-to-EBS snapshot behavior."""

    def setUp(self) -> None:
        """Create an isolated deployment manager."""
        self.manager = DSTACK_CLOUD.CloudDeploymentManager()

    def test_upload_skips_zero_blocks_and_pads_final_block(self) -> None:
        """Only non-zero blocks should be uploaded with 512-KiB alignment."""
        block_size = DSTACK_CLOUD.AWS_EBS_BLOCK_SIZE
        with tempfile.TemporaryDirectory() as tmpdir:
            raw = Path(tmpdir) / "disk.raw"
            with raw.open("wb") as raw_file:
                raw_file.write(b"A" + bytes(block_size - 1))
                raw_file.write(bytes(block_size))
                raw_file.write(b"final")
            self.manager._aws_put_snapshot_block = Mock()

            changed = self.manager._aws_upload_snapshot_blocks(
                "us-west-2",
                "snap-1234567890abcdef0",
                raw,
            )

        self.assertEqual(changed, 2)
        calls = sorted(
            self.manager._aws_put_snapshot_block.call_args_list,
            key=lambda call: call.args[2],
        )
        self.assertEqual([call.args[2] for call in calls], [0, 2])
        self.assertEqual(len(calls[0].args[3]), block_size)
        self.assertEqual(len(calls[1].args[3]), block_size)
        self.assertTrue(calls[1].args[3].startswith(b"final"))
        self.assertEqual(calls[1].args[3][5:], bytes(block_size - 5))

    def test_put_block_passes_path_and_sha256_checksum(self) -> None:
        """The AWS CLI should receive a raw path and matching checksum."""
        block = b"x" * DSTACK_CLOUD.AWS_EBS_BLOCK_SIZE
        expected_checksum = base64.b64encode(hashlib.sha256(block).digest()).decode()
        self.manager._aws_ebs_call = Mock(return_value=aws_result())

        self.manager._aws_put_snapshot_block(
            "us-west-2",
            "snap-1234567890abcdef0",
            7,
            block,
        )

        command = self.manager._aws_ebs_call.call_args.args[0]
        block_path = command[command.index("--block-data") + 1]
        checksum = command[command.index("--checksum") + 1]
        self.assertFalse(block_path.startswith("file://"))
        self.assertFalse(block_path.startswith("fileb://"))
        self.assertFalse(Path(block_path).exists())
        self.assertEqual(checksum, expected_checksum)

    def test_snapshot_rounds_volume_size_and_completes(self) -> None:
        """A RAW file should be rounded to GiB and completed with its block count."""
        config = DSTACK_CLOUD.AwsConfig(region="us-west-2")
        start = aws_result(
            stdout=(
                '{"SnapshotId":"snap-1234567890abcdef0",'
                f'"BlockSize":{DSTACK_CLOUD.AWS_EBS_BLOCK_SIZE}}}'
            )
        )
        self.manager._aws_ebs_call = Mock(side_effect=[start, aws_result()])
        self.manager._aws_upload_snapshot_blocks = Mock(return_value=3)
        self.manager._run_aws = Mock(side_effect=[aws_result(), aws_result()])

        with tempfile.TemporaryDirectory() as tmpdir:
            raw = Path(tmpdir) / "disk.raw"
            with raw.open("wb") as raw_file:
                raw_file.truncate(1024 * 1024 * 1024 + 1)
            snapshot_id = self.manager._aws_create_snapshot_from_raw(
                config,
                raw,
                "test snapshot",
                "test-token",
            )

        self.assertEqual(snapshot_id, "snap-1234567890abcdef0")
        start_command = self.manager._aws_ebs_call.call_args_list[0].args[0]
        complete_command = self.manager._aws_ebs_call.call_args_list[1].args[0]
        self.assertEqual(
            start_command[start_command.index("--volume-size") + 1],
            "2",
        )
        self.assertEqual(
            complete_command[complete_command.index("--changed-blocks-count") + 1],
            "3",
        )

    def test_upload_failure_deletes_partial_snapshot(self) -> None:
        """A failed upload must remove the pending snapshot."""
        config = DSTACK_CLOUD.AwsConfig(region="us-west-2")
        start = aws_result(
            stdout=(
                '{"SnapshotId":"snap-1234567890abcdef0",'
                f'"BlockSize":{DSTACK_CLOUD.AWS_EBS_BLOCK_SIZE}}}'
            )
        )
        self.manager._aws_ebs_call = Mock(return_value=start)
        self.manager._aws_upload_snapshot_blocks = Mock(
            side_effect=RuntimeError("upload failed")
        )
        self.manager._run_aws = Mock(return_value=aws_result())

        with tempfile.TemporaryDirectory() as tmpdir:
            raw = Path(tmpdir) / "disk.raw"
            raw.write_bytes(b"raw")
            with self.assertRaisesRegex(RuntimeError, "upload failed"):
                self.manager._aws_create_snapshot_from_raw(
                    config,
                    raw,
                    "test snapshot",
                    "test-token",
                )

        cleanup_command = self.manager._run_aws.call_args.args[0]
        self.assertEqual(cleanup_command[:2], ["ec2", "delete-snapshot"])

    def test_permission_error_is_actionable_and_sanitized(self) -> None:
        """Access failures should name one permission without raw metadata."""
        self.manager._run_aws = Mock(
            return_value=aws_result(
                returncode=1,
                stderr=(
                    "An error occurred (AccessDeniedException) when calling "
                    "StartSnapshot: private request metadata"
                ),
            )
        )

        with self.assertRaises(PermissionError) as raised:
            self.manager._aws_ebs_call(
                ["ebs", "start-snapshot", "--region", "us-west-2"],
                "StartSnapshot",
            )

        message = str(raised.exception)
        self.assertIn("ebs:StartSnapshot", message)
        self.assertIn("AccessDeniedException", message)
        self.assertNotIn("private request metadata", message)

    def test_transient_error_is_retried(self) -> None:
        """Throttled EBS requests should retry with backoff."""
        self.manager._run_aws = Mock(
            side_effect=[
                aws_result(
                    returncode=1,
                    stderr=(
                        "An error occurred (RequestThrottledException) when calling "
                        "PutSnapshotBlock"
                    ),
                ),
                aws_result(),
            ]
        )

        with patch.object(DSTACK_CLOUD.time, "sleep") as sleep:
            result = self.manager._aws_ebs_call(
                ["ebs", "put-snapshot-block", "--region", "us-west-2"],
                "PutSnapshotBlock",
            )

        self.assertEqual(result.returncode, 0)
        sleep.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()

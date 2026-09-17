#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 - "$ROOT" "$work" <<'PY'
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

root, work = map(Path, sys.argv[1:])


def check(script, *args, success=True, message=None, env=None):
    result = subprocess.run(
        [str(root / script), *map(str, args)],
        env=env,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    assert (result.returncode == 0) == success, output
    assert message is None or message in output, output


# Validate the actual assembler's optional artifact contract without image tools.
payload = work / "payload"
payload.write_bytes(b"fixture\n")
manifest = {
    "schema_version": 1,
    "backend": "mkosi",
    "image": {"name": "dstack", "version": "test", "flavor": "prod", "is_dev": False},
    "source": {"git_revision": "fixture"},
    "boot": {"ovmf_variant": "tdx"},
    "verity": {"root_hash": "0" * 64, "data_size": 4096},
    "artifacts": dict.fromkeys(
        ("initramfs", "kernel", "firmware", "rootfs_verity"), "payload"
    ),
}
manifest["artifacts"].update(firmware_sev=None, uki=None)
manifest_path = work / "artifact-manifest.json"
manifest_path.write_text(json.dumps(manifest))
check("os/image/assemble.sh", "--manifest", manifest_path, "--validate-only")
for value, success in (
    (None, True),
    ("payload", True),
    (str(payload), False),
    ("../payload", False),
    ("missing", False),
):
    manifest["artifacts"]["kernel_devel"] = value
    manifest_path.write_text(json.dumps(manifest))
    check(
        "os/image/assemble.sh",
        "--manifest",
        manifest_path,
        "--validate-only",
        success=success,
    )

# Only partition inspection is stubbed; checksums, tar, grep and the output
# checker run for real. The fixture deliberately is not a bootable disk image.
bin_dir = work / "bin"
bin_dir.mkdir()
sgdisk = bin_dir / "sgdisk"
sgdisk.write_text("#!/bin/sh\nprintf 'dstack-rootfs\\n'\n")
sgdisk.chmod(0o755)
env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", DSTACK_TAR_RELEASE="1")
out = work / "dstack-test"
out.mkdir()
for name in (
    "bzImage",
    "initramfs.cpio.gz",
    "ovmf.fd",
    "ovmf-sev.fd",
    "rootfs.img.parted.verity",
    "measurement.tdx.cbor",
    "measurement.snp.cbor",
    "digest.txt",
):
    (out / name).write_bytes(payload.read_bytes())
metadata = dict.fromkeys(
    (
        "bios",
        "kernel",
        "cmdline",
        "initrd",
        "rootfs",
        "version",
        "git_revision",
        "ovmf_variant",
    ),
    "fixture",
)
metadata.update({"bios-sev": "ovmf-sev.fd", "builder": "mkosi", "is_dev": False})
(out / "metadata.json").write_text(json.dumps(metadata))
hashes = "".join(
    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
    for path in sorted(out.iterdir())
)
(out / "sha256sum.txt").write_text(hashes)
archive = work / "dstack-test-kernel-devel.tar.gz"


def write_archive(with_metadata):
    prefix = "dstack-test-kernel-devel/"
    with tarfile.open(archive, "w:gz") as tar:
        if with_metadata:
            data = b'{"kernel_release": "test"}\n'
            member = tarfile.TarInfo(prefix + "kernel-devel.json")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        # Exceed pipe capacity after the match to expose grep -q's SIGPIPE.
        for index in range(3000):
            tar.addfile(
                tarfile.TarInfo(
                    prefix + f"linux-headers-test/include/header-{index:04}.h"
                )
            )


checker = "os/mkosi/tests/check-output.sh"
write_archive(True)
check(checker, out, env=env)
valid_archive = archive.read_bytes()
write_archive(False)
check(checker, out, env=env, success=False, message="does not declare its kernel")
archive.write_bytes(valid_archive[: len(valid_archive) // 2])
check(checker, out, env=env, success=False)
archive.unlink()
check(checker, out, env=env, success=False, message="missing kernel build tree archive")
check(checker, out, env=dict(env, DSTACK_TAR_RELEASE="0"))
archive.write_bytes(valid_archive)

# A valid checksum must not make a developer artifact part of image identity.
name = "kernel-devel.tar.gz"
(out / name).write_bytes(valid_archive)
(out / "sha256sum.txt").write_text(
    hashes + f"{hashlib.sha256(valid_archive).hexdigest()}  {name}\n"
)
check(
    checker,
    out,
    env=env,
    success=False,
    message="must not be part of the image identity",
)
print("kernel-devel artifact tests passed")
PY

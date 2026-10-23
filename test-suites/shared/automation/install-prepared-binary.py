#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Install a rebuilt binary into the exact prepared path from runtime-manifest.

Why this exists
---------------
`prepare-run.sh` content-addresses binaries under
`${DSTACK_TEST_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack-test}/<key>`.
Operators may later relocate that directory (for example to
`~/.cache/dstack-test-relocated/...` and symlink from `/tmp/dstack-test-cache/...`).
Fixtures always start from `runtime-manifest.json` paths and then `Path.resolve()`.

Guessing only `/tmp/dstack-test-cache/...` or only `~/.cache/...` causes the
classic failure mode: a new binary lands on one path while fixtures keep using
the old file on the resolved path, and the manifest sha256 drifts.

Usage
-----
  install-prepared-binary.py \
      --manifest /path/to/runtime-manifest.json \
      --key dstack_gateway \
      --source /path/to/new/dstack-gateway \
      [--chmod 0555]

  # print resolved destination without installing
  install-prepared-binary.py --manifest ... --key dstack_gateway --print-path

  # verify on-disk sha matches manifest (and optional --expect-sha256)
  install-prepared-binary.py --manifest ... --key dstack_gateway --verify

Rules encoded here (cross-machine)
----------------------------------
1. Always read destination from runtime-manifest prepared_binaries.<key>.path
2. Always install through realpath of that path (follow symlinks/relocations)
3. Atomically replace the prepared binary (write temp + os.replace)
4. Update prepared_binaries.<key>.sha256 in the same manifest
5. Never invent a parallel cache root; never hardcode /tmp vs $HOME/.cache
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path) -> dict:
    """Load and validate a runtime-manifest JSON object."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"manifest must be a JSON object: {path}")
    return data


def resolve_entry(manifest: dict, key: str) -> tuple[Path, str | None]:
    """Return resolved destination path and manifest sha for *key*."""
    binaries = manifest.get("prepared_binaries")
    if not isinstance(binaries, dict):
        raise SystemExit("manifest missing prepared_binaries object")
    entry = binaries.get(key)
    if not isinstance(entry, dict) or not entry.get("path"):
        known = ", ".join(sorted(binaries)) or "(none)"
        raise SystemExit(
            f"manifest has no prepared_binaries.{key}.path; known: {known}"
        )
    declared = Path(str(entry["path"]))
    # Follow symlinks/relocations so install hits the file fixtures will exec.
    if declared.exists() or declared.is_symlink():
        dest = declared.resolve()
    else:
        parent = declared.parent
        if parent.exists() or parent.is_symlink():
            dest = parent.resolve() / declared.name
        else:
            dest = declared.absolute()
    sha = entry.get("sha256")
    return dest, str(sha) if sha else None


def atomic_install(source: Path, dest: Path, mode: int) -> str:
    """Atomically install *source* to *dest* and return the sha256."""
    if not source.is_file():
        raise SystemExit(f"source binary not found: {source}")
    digest = sha256_file(source)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{dest.name}.",
        suffix=".tmp",
        dir=str(dest.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, source.open("rb") as inp:
            while True:
                chunk = inp.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, mode)
        if dest.exists():
            try:
                dest.chmod(stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
            except OSError:
                pass
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
    actual = sha256_file(dest)
    if actual != digest:
        raise SystemExit(
            f"post-install sha mismatch for {dest}: expected {digest}, got {actual}"
        )
    if not os.access(dest, os.X_OK):
        raise SystemExit(f"installed binary is not executable: {dest}")
    return actual


def update_manifest_sha(manifest_path: Path, key: str, digest: str, dest: Path) -> None:
    """Rewrite prepared_binaries sha256/resolved_path for *key*."""
    manifest = load_manifest(manifest_path)
    entry = manifest.setdefault("prepared_binaries", {}).setdefault(key, {})
    # Keep the declared path string stable (may be the symlink path). Only
    # refresh sha256 so shared/fixtures/operators that check it stay consistent.
    if "path" not in entry:
        entry["path"] = str(dest)
    entry["sha256"] = digest
    entry["resolved_path"] = str(dest.resolve())
    text = json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{manifest_path.name}.",
        suffix=".tmp",
        dir=str(manifest_path.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, manifest_path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--manifest",
        required=True,
        type=Path,
        help="Path to runtime-manifest.json for the active run",
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Key present in the manifest prepared_binaries object",
    )
    parser.add_argument(
        "--source",
        type=Path,
        help="Newly built binary to install (release target or other)",
    )
    parser.add_argument(
        "--chmod",
        default="0555",
        help="mode for installed binary (default 0555, matches prepare-run)",
    )
    parser.add_argument(
        "--print-path",
        action="store_true",
        help="Print resolved destination path and exit",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify on-disk sha matches manifest (and optional --expect-sha256)",
    )
    parser.add_argument(
        "--expect-sha256",
        help="Optional full sha256 that on-disk binary must match",
    )
    parser.add_argument(
        "--no-manifest-update",
        action="store_true",
        help="Install without rewriting runtime-manifest sha256 (discouraged)",
    )
    args = parser.parse_args(argv)

    manifest_path = args.manifest.resolve()
    if not manifest_path.is_file():
        raise SystemExit(f"runtime manifest not found: {manifest_path}")
    manifest = load_manifest(manifest_path)
    dest, manifest_sha = resolve_entry(manifest, args.key)

    if args.print_path:
        print(dest)
        print(
            f"declared_path={manifest['prepared_binaries'][args.key]['path']}",
            file=sys.stderr,
        )
        print(f"resolved_path={dest}", file=sys.stderr)
        print(f"manifest_sha256={manifest_sha}", file=sys.stderr)
        if dest.is_file():
            print(f"on_disk_sha256={sha256_file(dest)}", file=sys.stderr)
        return 0

    if args.verify:
        if not dest.is_file():
            raise SystemExit(f"binary missing at resolved path: {dest}")
        actual = sha256_file(dest)
        problems = []
        if manifest_sha and actual != manifest_sha:
            problems.append(f"manifest sha256={manifest_sha} but on-disk={actual}")
        if args.expect_sha256 and actual != args.expect_sha256:
            problems.append(f"expect sha256={args.expect_sha256} but on-disk={actual}")
        print(
            json.dumps(
                {
                    "key": args.key,
                    "declared_path": manifest["prepared_binaries"][args.key]["path"],
                    "resolved_path": str(dest),
                    "on_disk_sha256": actual,
                    "manifest_sha256": manifest_sha,
                    "ok": not problems,
                    "problems": problems,
                },
                indent=2,
            )
        )
        return 1 if problems else 0

    if not args.source:
        raise SystemExit("--source is required unless --print-path/--verify")

    mode = int(args.chmod, 8)
    digest = atomic_install(args.source.resolve(), dest, mode)
    # Reload declared path after possible prior state.
    declared = manifest["prepared_binaries"][args.key]["path"]
    if not args.no_manifest_update:
        update_manifest_sha(manifest_path, args.key, digest, dest)

    print(
        json.dumps(
            {
                "status": "installed",
                "key": args.key,
                "source": str(args.source.resolve()),
                "declared_path": declared,
                "resolved_path": str(Path(dest).resolve()),
                "sha256": digest,
                "manifest_updated": not args.no_manifest_update,
                "manifest": str(manifest_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

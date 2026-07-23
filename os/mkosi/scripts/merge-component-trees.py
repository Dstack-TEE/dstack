#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge component install trees while rejecting every non-directory clash."""

import os
import shutil
import stat
import sys
from pathlib import Path


def exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def merge(component: str, source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise SystemExit(f"{component}: missing install tree: {source}")
    for root, directories, files in os.walk(source):
        directories.sort()
        files.sort()
        relative = Path(root).relative_to(source)
        target_root = destination / relative
        target_root.mkdir(parents=True, exist_ok=True)
        for name in directories:
            src = Path(root) / name
            dst = target_root / name
            if src.is_symlink():
                files.append(name)
                continue
            if exists(dst) and not dst.is_dir():
                raise SystemExit(f"component install conflict: {component}: {dst}")
            dst.mkdir(exist_ok=True)
        for name in files:
            src = Path(root) / name
            dst = target_root / name
            if exists(dst):
                raise SystemExit(f"component install conflict: {component}: {dst}")
            mode = src.lstat().st_mode
            if stat.S_ISLNK(mode):
                dst.symlink_to(os.readlink(src))
            elif stat.S_ISREG(mode):
                shutil.copy2(src, dst, follow_symlinks=False)
            else:
                raise SystemExit(f"{component}: unsupported install entry: {src}")


def main() -> None:
    destination = Path(sys.argv[1])
    destination.mkdir(parents=True, exist_ok=True)
    for specification in sys.argv[2:]:
        component, source = specification.split("=", 1)
        merge(component, Path(source), destination)


if __name__ == "__main__":
    main()

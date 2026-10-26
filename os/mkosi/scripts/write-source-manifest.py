#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Describe Git-owned and untracked source paths for development cache keys."""

import os
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
output = pathlib.Path(sys.argv[2]).resolve()
entries = subprocess.check_output(
    ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
).split(b"\0")
stage = subprocess.check_output(
    ["git", "-C", root, "ls-files", "-z", "--stage", "--cached"]
).split(b"\0")
gitlinks = {
    record.split(b"\t", 1)[1]: record.split(b" ", 1)[1].split(b" ", 1)[0]
    for record in stage
    if record.startswith(b"160000 ")
}

output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
with temporary.open("wb") as manifest:
    for encoded in sorted(filter(None, entries)):
        path = root / os.fsdecode(encoded)
        if encoded in gitlinks and path.is_dir():
            revision = subprocess.check_output(
                ["git", "-C", path, "rev-parse", "HEAD"]
            ).strip()
            kind, value = b"gitlink", revision
        elif path.is_file():
            kind, value = b"file", b""
        else:
            kind, value = b"missing", b""
        manifest.write(kind + b"\0" + encoded + b"\0" + value + b"\0")
temporary.replace(output)

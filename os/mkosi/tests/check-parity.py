#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify Yocto-visible functional parity in an assembled mkosi tree."""

import glob
import json
import os
import subprocess
import sys

spec_path, rootfs, kernel_tree, flavor = sys.argv[1:]
with open(spec_path, encoding="utf-8") as f:
    spec = json.load(f)
missing = []
for component, paths in spec["required_rootfs_paths"].items():
    for path in paths:
        if not os.path.lexists(os.path.join(rootfs, path)):
            missing.append(f"{component}:/{path}")
for component, patterns in spec.get("required_rootfs_globs", {}).items():
    for pattern in patterns:
        if not glob.glob(os.path.join(rootfs, pattern)):
            missing.append(f"{component}:/{pattern}")
for component, patterns in spec["required_kernel_globs"].items():
    for pattern in patterns:
        if not glob.glob(os.path.join(kernel_tree, pattern)):
            missing.append(f"{component}: kernel module ({pattern})")
configs = glob.glob(os.path.join(kernel_tree, "usr/lib/modules/*/config"))
if len(configs) != 1:
    missing.append("kernel-config: expected exactly one installed config")
else:
    with open(configs[0], encoding="utf-8") as f:
        config = set(f.read().splitlines())
    for setting in spec.get("required_kernel_config", []):
        symbol, value = setting.split("=", 1)
        effective = f"# {symbol} is not set" if value == "n" else setting
        if effective not in config:
            missing.append(f"kernel-config: {setting}")
if flavor == "dev":
    for path in spec["dev_only_paths"]:
        if not os.path.lexists(os.path.join(rootfs, path)):
            missing.append(f"dev:/{path}")
else:
    for path in spec.get("prod_forbidden_paths", []):
        if os.path.lexists(os.path.join(rootfs, path)):
            missing.append(f"prod contains dev-only path:/{path}")
for path in spec.get("runtime_link_paths", []):
    result = subprocess.run(
        ["lddtree", "-R", rootfs, f"/{path}"],
        capture_output=True,
        check=False,
        text=True,
    )
    output = result.stdout + result.stderr
    if result.returncode or "not found" in output or "did not match" in output:
        missing.append(f"runtime linkage:/{path}")
if missing:
    raise SystemExit("Yocto parity check failed:\n  " + "\n  ".join(missing))
print("Yocto functional parity paths accepted")

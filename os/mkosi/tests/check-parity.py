#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify Yocto-visible functional parity in an assembled mkosi tree."""

import glob
import json
import os
import subprocess
import sys


def resolve_in_rootfs(root: str, path: str, depth: int = 0):
    """Return the rootfs-relative path a symlink chain ends at, or None.

    os.path.lexists() is true for a dangling symlink, so a versioned library
    whose target was never installed would satisfy the parity check and then
    fail at runtime. Symlinks are followed with absolute targets treated as
    rootfs-relative, since the image is not mounted at / on the build host --
    os.path.realpath() would instead escape into the build host's own
    filesystem and report on whatever binary happens to sit at that path there.
    """
    if depth > 16:
        return None
    rel = os.path.normpath(path.lstrip("/"))
    full = os.path.join(root, rel)
    if not os.path.lexists(full):
        return None
    if not os.path.islink(full):
        return rel
    target = os.readlink(full)
    if not os.path.isabs(target):
        target = os.path.join(os.path.dirname(rel), target)
    return resolve_in_rootfs(root, target, depth + 1)


def resolves_in_rootfs(root: str, path: str) -> bool:
    """Return whether a path exists in the image and its symlinks resolve."""
    return resolve_in_rootfs(root, path) is not None


spec_path, rootfs, kernel_tree, flavor = sys.argv[1:]
with open(spec_path, encoding="utf-8") as f:
    spec = json.load(f)
missing = []
for component, paths in spec["required_rootfs_paths"].items():
    for path in paths:
        if not resolves_in_rootfs(rootfs, path):
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
        if not resolves_in_rootfs(rootfs, path):
            missing.append(f"dev:/{path}")
else:
    # Deliberately lexists(): a forbidden path must be absent outright, and a
    # dangling symlink to a removed binary still counts as present.
    for path in spec.get("prod_forbidden_paths", []):
        if os.path.lexists(os.path.join(rootfs, path)):
            missing.append(f"prod contains forbidden path:/{path}")
for path, expected in spec.get("required_symlink_resolutions", {}).items():
    # Which netfilter frontend the image programs is decided by a symlink, and
    # on this backend that symlink comes from the distribution's default rather
    # than from anything dstack states. That default is what silently put the
    # two guest images on different rulesets, so assert it instead of
    # inheriting it: os/yocto builds the equivalent links explicitly in
    # iptables_%.bbappend, and here the build fails if Debian ever flips.
    resolved = resolve_in_rootfs(rootfs, path)
    if resolved is None:
        missing.append(f"netfilter frontend missing or dangling:/{path}")
        continue
    target = os.path.basename(resolved)
    if target != expected:
        missing.append(
            f"netfilter frontend:/{path} resolves to {target}, wanted {expected}"
        )
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

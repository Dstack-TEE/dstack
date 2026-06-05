#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""sca — self-contained dstack app builder.

build a dstack `app-compose.json` whose application is embedded directly inside
it, with NO docker and NO registry pull. you lay out a `rootfs/` directory that
mirrors the CVM filesystem; `sca build` packs the whole tree (tar+gzip+base64)
into app-compose.json. at boot the measured `bash_script` extracts the tree onto
the CVM root and starts your systemd service(s), so systemd supervises the app
the way docker would.

why this is secure: the whole app-compose.json (including the embedded rootfs)
is hashed into the compose-hash and extended to RTMR3, so the exact bytes you
ship are covered by remote attestation and gated by the on-chain whitelist.

subcommands:
  new <dir>     scaffold a project (config.json + rootfs/ defaults + README)
  build         pack rootfs/ and emit app-compose.json

constraints baked in from the dstack guest runtime (verified on a live CVM):
  - guest userland is busybox: no `base64`, but `openssl`, `tar`, `gzip` exist.
  - `/run`, `/tmp`, `/dev/shm` are tmpfs and mounted exec; `/etc`, `/usr` are
    writable overlays. extracting the tree onto `/` therefore works.
  - init is systemd; `systemctl` is available.
  - cwd of the script is /dstack, where `app-compose.json` is symlinked.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import shlex
import sys
import tarfile
from pathlib import Path

# the guest copies app-compose.json into the CVM with this hard cap
# (dstack-util HostShared::copy). the rootfs is gzip-compressed before base64,
# but base64 still adds ~33% on top of the compressed size.
APP_COMPOSE_MAX_BYTES = 50 * 1024 * 1024

# systemd unit names we allow in `services` (these reach a root shell at boot
# via `systemctl start <name>`, so keep the alphabet strict).
UNIT_RE = re.compile(r"^[A-Za-z0-9@:._-]+\.(service|socket|target|timer|path|mount)$")

# app-compose flags this tool exposes, both as config.json `compose` keys and as
# CLI options on `new`/`build`. `key_provider` is the modern enum field
# (matches dstack-types KeyProviderKind) that replaces the legacy kms_enabled /
# local_key_provider_enabled booleans; gateway is independent of the provider.
KEY_PROVIDERS = ("none", "kms", "local", "tpm")

COMPOSE_DEFAULTS = {
    "key_provider": "none",
    "gateway_enabled": False,
    "public_logs": True,
    "public_sysinfo": True,
    "secure_time": False,
    "no_instance_id": False,
    "allowed_envs": [],
    "key_provider_id": "",
}

# compose keys overridable from the CLI (argparse dest == compose key)
_COMPOSE_KEYS = (
    "key_provider", "gateway_enabled", "public_logs", "public_sysinfo",
    "secure_time", "no_instance_id", "allowed_envs", "key_provider_id",
)


def _add_bool_pair(group, name: str, dest: str, help_on: str) -> None:
    # tri-state: --flag -> True, --no-flag -> False, absent -> None (keep base)
    group.add_argument(f"--{name}", dest=dest, action="store_const",
                       const=True, default=None, help=help_on)
    group.add_argument(f"--no-{name}", dest=dest, action="store_const",
                       const=False, help=f"disable {name}")


def add_compose_args(parser: "argparse.ArgumentParser") -> None:
    """attach the app-compose options (shared by `new` and `build`).

    every option defaults to None so an unset flag keeps the config/default
    value while an explicit flag overrides it.
    """
    g = parser.add_argument_group("app-compose options")
    g.add_argument("--key-provider", choices=KEY_PROVIDERS, default=None,
                   help="key provider (default: none); gateway requires kms")
    _add_bool_pair(g, "gateway", "gateway_enabled",
                   "expose the app via dstack-gateway (needs --key-provider kms)")
    _add_bool_pair(g, "public-logs", "public_logs", "allow public access to logs")
    _add_bool_pair(g, "public-sysinfo", "public_sysinfo", "allow public sysinfo")
    _add_bool_pair(g, "secure-time", "secure_time", "require secure time at boot")
    g.add_argument("--no-instance-id", dest="no_instance_id", action="store_const",
                   const=True, default=None, help="don't derive a per-instance id")
    g.add_argument("--instance-id", dest="no_instance_id", action="store_const",
                   const=False, help="derive a per-instance id (default)")
    g.add_argument("--allowed-env", dest="allowed_envs", action="append",
                   default=None, metavar="NAME",
                   help="env var name the app may receive (repeatable)")
    g.add_argument("--key-provider-id", dest="key_provider_id", default=None,
                   help="hex key-provider id (KMS app contract)")


def resolve_compose(base: dict, args) -> dict:
    """layer CLI overrides (non-None values) on top of a base compose dict."""
    out = dict(base)
    for key in _COMPOSE_KEYS:
        val = getattr(args, key, None)
        if val is not None:
            out[key] = val
    return out


def validate_compose(compose: dict) -> None:
    kp = compose.get("key_provider", "none")
    if kp not in KEY_PROVIDERS:
        die(f"key_provider must be one of {KEY_PROVIDERS} (got {kp!r})")
    for key in ("gateway_enabled", "public_logs", "public_sysinfo",
                "secure_time", "no_instance_id"):
        if not isinstance(compose.get(key, False), bool):
            die(f"compose.{key} must be a JSON boolean (got {compose.get(key)!r})")
    if compose.get("gateway_enabled") and kp != "kms":
        print("  warning: gateway_enabled but key_provider is not 'kms'; the "
              "gateway will reject the app (it needs a KMS identity)",
              file=sys.stderr)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def die(msg: str) -> "None":
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.strip()).strip("-")
    return slug or "app"


def human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{int(f)} B" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{n} B"


# --------------------------------------------------------------------------- #
# rootfs packing (deterministic tar.gz so the compose-hash is reproducible)
# --------------------------------------------------------------------------- #
def _normalized_mode(info: "tarfile.TarInfo") -> int:
    """force modes so the archive doesn't depend on the builder's umask.

    directories -> 0755, symlinks -> 0777 (ignored on extract), regular files
    keep only the executable intent (0755 if any exec bit was set, else 0644).
    """
    if info.isdir():
        return 0o755
    if info.issym():
        return 0o777
    return 0o755 if (info.mode & 0o111) else 0o644


def pack_rootfs(rootfs: Path) -> tuple[bytes, int, int]:
    """tar+gzip the rootfs tree deterministically.

    returns (gzip_bytes, file_count, uncompressed_total_bytes).

    note: the whole archive is built in memory (tar + gzip + later base64 + json
    blob), so a very large rootfs is bounded by available RAM, not just the
    50 MiB compose cap. that's fine for the intended small self-contained apps.
    """
    paths = sorted(rootfs.rglob("*"), key=lambda p: p.relative_to(rootfs).as_posix())
    if not paths:
        die(f"rootfs is empty: {rootfs}")

    tar_buf = io.BytesIO()
    nfiles = 0
    raw_total = 0
    # pin GNU format so the bytes don't change with the Python version (the
    # default flipped from GNU to PAX in 3.8, which would shift the compose-hash).
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for p in paths:
            rel = p.relative_to(rootfs).as_posix()
            info = tar.gettarinfo(str(p), arcname=rel)
            if info is None:
                die(f"unsupported file type in rootfs: {p} "
                    "(only regular files, directories, and symlinks are allowed)")
            # normalize all metadata for a reproducible archive
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.mode = _normalized_mode(info)
            if info.isreg():
                with open(p, "rb") as fh:
                    tar.addfile(info, fh)
                nfiles += 1
                raw_total += info.size
            else:
                tar.addfile(info)

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0, compresslevel=9) as gz:
        gz.write(tar_buf.getvalue())
    return gz_buf.getvalue(), nfiles, raw_total


# --------------------------------------------------------------------------- #
# bash_script generation
# --------------------------------------------------------------------------- #
def render_bash_script(services: list[str]) -> str:
    # shell-quote (not json.dumps): service names land in a root shell at boot,
    # and they're already validated against UNIT_RE before we get here.
    start_lines = "\n".join(f"systemctl start {shlex.quote(s)}" for s in services)
    # runs via `jq -r '.bash_script' app-compose.json | bash` from /dstack.
    return f"""# generated by sca — do not edit by hand
set -euo pipefail

COMPOSE_FILE=app-compose.json
note() {{ dstack-util notify-host -e boot.progress -d "$1" || true; }}

note "sca: extracting rootfs"
# the guest has no `base64`; openssl decodes, busybox tar/gzip unpack onto /.
jq -r '.sca_rootfs' "$COMPOSE_FILE" | openssl base64 -d -A | tar -xz -C /

note "sca: starting services"
systemctl daemon-reload
# `start` returns immediately so the oneshot app-compose.service completes and
# boot is marked done; systemd then supervises the app (Restart=always).
{start_lines}
note "sca: started"
"""


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #
def build_app_compose(cfg: dict, compose: dict, rootfs_b64: str,
                      services: list[str]) -> dict:
    out: dict = {
        "manifest_version": cfg.get("manifest_version", 2),
        "name": cfg["name"],
        "runner": "bash",
        # modern key-provider enum (none|kms|local|tpm); gateway is separate
        "key_provider": compose.get("key_provider", "none"),
        "gateway_enabled": bool(compose.get("gateway_enabled", False)),
        "public_logs": bool(compose.get("public_logs", True)),
        "public_sysinfo": bool(compose.get("public_sysinfo", True)),
        "no_instance_id": bool(compose.get("no_instance_id", False)),
        "secure_time": bool(compose.get("secure_time", False)),
        "allowed_envs": list(compose.get("allowed_envs") or []),
    }
    kp_id = compose.get("key_provider_id") or ""
    if kp_id:
        out["key_provider_id"] = kp_id
    if compose.get("swap_size_mb"):
        out["swap_size"] = int(compose["swap_size_mb"]) * 1024 * 1024

    out["bash_script"] = render_bash_script(services)
    out["sca_rootfs"] = rootfs_b64
    return out


def cmd_build(args) -> None:
    cfg_path = Path(args.config).resolve()
    if not cfg_path.is_file():
        die(f"config not found: {cfg_path} (run `sca new <dir>` first)")
    try:
        cfg = json.loads(cfg_path.read_text())
    except json.JSONDecodeError as exc:
        die(f"invalid JSON in {cfg_path}: {exc}")
    if not cfg.get("name"):
        die("config is missing required key 'name'")

    base_dir = cfg_path.parent
    rootfs = (base_dir / cfg.get("rootfs", "rootfs")).resolve()
    if not rootfs.is_dir():
        die(f"rootfs directory not found: {rootfs}")

    services = cfg.get("services") or ["sca.service"]
    if not isinstance(services, list) or not services:
        die("config 'services' must be a non-empty list of unit names")
    for s in services:
        if not isinstance(s, str) or not UNIT_RE.match(s):
            die(f"invalid service unit name: {s!r} "
                f"(must match {UNIT_RE.pattern})")

    compose_cfg = cfg.get("compose", {})
    if not isinstance(compose_cfg, dict):
        die("config 'compose' must be an object")
    # precedence: built-in defaults < config.json < CLI flags
    compose = resolve_compose({**COMPOSE_DEFAULTS, **compose_cfg}, args)
    validate_compose(compose)

    gz, nfiles, raw_total = pack_rootfs(rootfs)
    rootfs_b64 = base64.b64encode(gz).decode("ascii")

    app_compose = build_app_compose(cfg, compose, rootfs_b64, services)
    blob = json.dumps(app_compose, indent=2, ensure_ascii=False).encode("utf-8")

    digest = hashlib.sha256(blob).hexdigest()
    size = len(blob)
    slug = slugify(cfg["name"])

    # check the cap BEFORE writing so a failed build never leaves an
    # oversized, undeployable app-compose.json behind.
    if size > APP_COMPOSE_MAX_BYTES:
        die(f"app-compose.json would be {human(size)}, over the "
            f"{human(APP_COMPOSE_MAX_BYTES)} guest copy limit; shrink the rootfs")

    out_path = Path(args.output).resolve()
    out_path.write_bytes(blob)

    print(f"wrote {out_path}")
    print(f"  rootfs      : {nfiles} file(s), {human(raw_total)} raw "
          f"-> {human(len(gz))} packed (tar.gz)")
    print(f"  services    : {', '.join(services)}")
    print(f"  key provider: {compose['key_provider']}  |  "
          f"gateway: {str(compose['gateway_enabled']).lower()}")
    print(f"  size        : {human(size)} / {human(APP_COMPOSE_MAX_BYTES)} cap "
          f"({100 * size / APP_COMPOSE_MAX_BYTES:.1f}%)")
    print(f"  compose-hash: {digest}")
    print(f"  app-id      : {digest[:40]}")
    if size > APP_COMPOSE_MAX_BYTES * 0.9:
        print("  warning: within 10% of the size cap", file=sys.stderr)
    print()
    print("next: deploy with vmm-cli, e.g.")
    print(f"  ./vmm-cli.py deploy --name {slug} --image <os-image> \\")
    print(f"      --compose {out_path.name} --vcpu 1 --memory 1024 --disk 10")


# --------------------------------------------------------------------------- #
# new (scaffold)
# --------------------------------------------------------------------------- #
def config_json_template(name: str, compose: dict) -> str:
    cfg = {
        "name": name,
        "manifest_version": 2,
        # rootfs tree to embed (relative to this file). defaults to "rootfs".
        "rootfs": "rootfs",
        # systemd units to start after the rootfs is extracted.
        "services": ["sca.service"],
        # app-compose options; key_provider is none|kms|local|tpm
        # (gateway requires kms).
        "compose": compose,
    }
    return json.dumps(cfg, indent=2) + "\n"


ENTRYPOINT_SH = """#!/bin/sh
# sca entrypoint — runs inside the CVM under systemd (sca.service).
# put your prebuilt binary at rootfs/run/sca/bin/app, or edit this script.
set -e
exec /run/sca/bin/app "$@"
"""

SCA_SERVICE = """[Unit]
Description=sca self-contained app
After=dstack-guest-agent.service

[Service]
ExecStart=/run/sca/bin/entrypoint.sh
Restart=always
RestartSec=2
# decrypted env from KMS (optional; '-' means don't fail if absent).
EnvironmentFile=-/dstack/.host-shared/.decrypted-env

[Install]
WantedBy=multi-user.target
"""

README_TEMPLATE = """# {name}

self-contained dstack app: a `rootfs/` tree is embedded in `app-compose.json`
and extracted onto the CVM at boot, then run under systemd — no docker, no
registry pull.

## layout

    config.json                          build config (edit this)
    rootfs/                              mirrors the CVM filesystem; whole tree
                                         is packed into app-compose.json
      run/sca/bin/entrypoint.sh          what the service runs (edit/extend)
      run/sca/bin/app                    <-- drop your prebuilt binary here
      etc/systemd/system/sca.service     the systemd unit (Restart=always)

anything you add under `rootfs/` lands at the same path inside the CVM (paths
like /run, /etc, /usr are writable). file modes are preserved, so keep
executables `chmod +x`.

## build

    sca build                 # packs rootfs/, writes app-compose.json

prints the compose-hash and app-id. add the compose-hash to your on-chain
DstackApp whitelist before deploying.

## options

app-compose options live under `compose` in config.json and can also be set on
`sca new` / `sca build` (CLI overrides config):

    --key-provider none|kms|local|tpm   key provider (gateway requires kms)
    --gateway / --no-gateway            expose via dstack-gateway
    --public-logs / --no-public-logs
    --public-sysinfo / --no-public-sysinfo
    --secure-time / --no-secure-time
    --no-instance-id / --instance-id
    --allowed-env NAME                  (repeatable)
    --key-provider-id HEX

## deploy

    ./vmm-cli.py deploy --name {slug} --image <os-image> \\
        --compose app-compose.json --vcpu 1 --memory 1024 --disk 10

## notes

- the whole rootfs is measured into RTMR3 via the compose-hash, so the exact
  bytes are attested. changing any file changes the compose-hash (re-whitelist).
- size cap: app-compose.json must stay under 50 MiB. the rootfs is gzip'd before
  base64, so the practical budget is roughly the *compressed* tree under ~37 MB.
- the app can reach the guest-agent socket at /var/run/dstack.sock — don't add
  heavy unit sandboxing that would hide it.
"""


def write_file(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    if mode is not None:
        path.chmod(mode)


def cmd_new(args) -> None:
    target = Path(args.dir).resolve()
    name = args.name or target.name
    slug = slugify(name)

    if target.exists() and any(target.iterdir()):
        die(f"directory '{target}' exists and is not empty")

    compose = resolve_compose(dict(COMPOSE_DEFAULTS), args)
    validate_compose(compose)

    write_file(target / "config.json", config_json_template(name, compose))
    write_file(target / "README.md", README_TEMPLATE.format(name=name, slug=slug))
    write_file(target / "rootfs" / "run" / "sca" / "bin" / "entrypoint.sh",
               ENTRYPOINT_SH, mode=0o755)
    write_file(target / "rootfs" / "etc" / "systemd" / "system" / "sca.service",
               SCA_SERVICE)

    print(f"scaffolded self-contained app '{name}' at {target}")
    print("  config.json")
    print("  rootfs/run/sca/bin/entrypoint.sh   (0755)")
    print("  rootfs/etc/systemd/system/sca.service")
    print("  README.md")
    print()
    print("next:")
    print(f"  cp <your-binary> {target}/rootfs/run/sca/bin/app")
    print(f"  cd {target} && sca build")


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #
def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="sca",
        description="build self-contained dstack apps (no docker, no registry)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_new = sub.add_parser("new", help="scaffold a new self-contained app project")
    p_new.add_argument("dir", help="target directory to create")
    p_new.add_argument("--name", help="app name (defaults to directory name)")
    add_compose_args(p_new)
    p_new.set_defaults(func=cmd_new)

    p_build = sub.add_parser("build", help="pack rootfs/ into app-compose.json")
    p_build.add_argument(
        "-c", "--config", default="config.json",
        help="path to config.json (default: ./config.json)",
    )
    p_build.add_argument(
        "-o", "--output", default="app-compose.json",
        help="output path (default: ./app-compose.json)",
    )
    add_compose_args(p_build)
    p_build.set_defaults(func=cmd_build)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

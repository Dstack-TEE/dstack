#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""kms-ctl — operator CLI for GCP private KMS provisioning.

Runs on the bastion VM inside GCP VPC, where it can reach both:
  - the KMS sidecar  (VPC-internal, e.g. http://10.0.0.5:8001)
  - the vendor authority (internet, e.g. https://authority.example.com)

Usage:
  kms-ctl attest    --kms-url URL --authority-url URL --user-id ID
  kms-ctl sync-auth --kms-url URL --authority-url URL --user-id ID
  kms-ctl status    --kms-url URL
  kms-ctl receipt   --kms-url URL

Environment variable equivalents (override with flags):
  KMS_URL          sidecar HTTP URL
  AUTHORITY_URL     vendor authority URL
  AUTHORITY_API_KEY API key for vendor authority (Bearer token)
  USER_ID          user identifier
"""

import argparse
import json
import os
import sys
import time

import requests

# ─── output helpers ──────────────────────────────────────────────────────────

def _c(code: str, msg: str) -> str:
    return f"\033[{code}m{msg}\033[0m" if sys.stdout.isatty() else msg

def step(msg: str):  print(f"\n{_c('1;36', '▶')} {msg}")
def ok(msg: str):    print(f"  {_c('0;32', '✓')} {msg}")
def info(msg: str):  print(f"  {_c('1;33', msg)}")
def die(msg: str):   print(f"  {_c('0;31', '✗')} {msg}", file=sys.stderr); sys.exit(1)

# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    if api_key:
        s.headers["Authorization"] = f"Bearer {api_key}"
    return s


def _post(session: requests.Session, url: str, body: dict) -> dict:
    try:
        r = session.post(url, json=body, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        die(f"HTTP {e.response.status_code} from {url}: {e.response.text[:300]}")
    except requests.ConnectionError:
        die(f"cannot connect to {url}")


def _get(session: requests.Session, url: str) -> dict | str:
    try:
        r = session.get(url, timeout=10)
        r.raise_for_status()
        ct = r.headers.get("content-type", "")
        return r.json() if "json" in ct else r.text
    except requests.HTTPError as e:
        die(f"HTTP {e.response.status_code} from {url}: {e.response.text[:300]}")
    except requests.ConnectionError:
        die(f"cannot connect to {url}")

# ─── commands ─────────────────────────────────────────────────────────────────

def cmd_status(args):
    """Show sidecar health and current bundle info."""
    s = _session("")
    step("healthz")
    health = _get(s, f"{args.kms_url}/healthz")
    ok(f"status: {health}")

    step("auth info")
    info_data = _get(s, f"{args.kms_url}/")
    ok(json.dumps(info_data, indent=2) if isinstance(info_data, dict) else info_data)


def cmd_receipt(args):
    """Fetch signed usage receipt from sidecar."""
    s = _session("")
    step("usage-receipt")
    receipt = _get(s, f"{args.kms_url}/usage-receipt")
    print(json.dumps(receipt, indent=2))


def cmd_attest(args):
    """Full courier attest: provision KMS with sealed root key + AuthBundle.

    Step 1  challenge      → nonce from vendor authority
    Step 2  courier/init   → transport keypair + TDX quote from sidecar
    Step 3  provision      → authority verifies quote, returns sealed root + bundle
    Step 4  courier/install→ sidecar installs root key, activates bundle
    """
    kms   = args.kms_url.rstrip("/")
    plat  = args.authority_url.rstrip("/")
    cid   = args.user_id
    s_kms = _session("")
    s_plt = _session(args.api_key)

    # 1. challenge
    step("1/4  challenge → vendor authority")
    ch = _post(s_plt, f"{plat}/api/v1/challenge",
               {"user_id": cid, "client_ts": int(time.time())})
    nonce = ch["nonce"]
    ok(f"nonce: {nonce[:16]}…")

    # 2. courier init
    step("2/4  courier/init → sidecar")
    init = _post(s_kms, f"{kms}/courier/init", {"nonce": nonce})
    transport_pub = init["transport_pub"]
    kms_ts        = init["kms_ts"]
    attestation   = init.get("attestation", "")
    vm_config     = init.get("vm_config", "")
    ok(f"transport_pub: {transport_pub[:20]}…  kms_ts: {kms_ts}")
    if attestation:
        ok(f"attestation: {len(attestation)//2} bytes (TDX+vTPM)")
    else:
        info("note: attestation is empty (guest agent unavailable)")

    # 3. provision
    step("3/4  provision → vendor authority")
    prov = _post(s_plt, f"{plat}/api/v1/provision", {
        "user_id":       cid,
        "nonce":         nonce,
        "attestation":   attestation,
        "transport_pub": transport_pub,
        "kms_ts":        kms_ts,
        "vm_config":     vm_config,
    })
    sealed_root  = prov["sealed_root"]
    auth_bundle  = prov["auth_bundle"]
    bundle_seq   = auth_bundle.get("bundle_seq", "?")
    slot_quota   = auth_bundle.get("slot_quota", "?")
    ok(f"sealed_root len={len(sealed_root)}  bundle_seq={bundle_seq}  slot_quota={slot_quota}")

    # 4. install
    step("4/4  courier/install → sidecar")
    inst = _post(s_kms, f"{kms}/courier/install", {
        "sealed_root": sealed_root,
        "auth_bundle": auth_bundle,
    })
    if not inst.get("ok"):
        die(f"install rejected: {inst}")
    ok("sidecar provisioned and ready")

    # verify
    health = _get(s_kms, f"{kms}/healthz")
    ok(f"healthz: {health}")


def cmd_measure(args):
    """Read-only: print the KMS instance's MEASURED values (no root release).

    Use this to discover EXPECTED_OS_IMAGE_HASH for a new OS image. It runs
    challenge + courier/init to obtain the attestation, then asks the authority's
    read-only /measure endpoint to verify the quote and report the measurements.
    """
    kms  = args.kms_url.rstrip("/")
    plat = args.authority_url.rstrip("/")
    cid  = args.user_id
    s_kms = _session("")
    s_plt = _session(args.api_key)

    step("1/3  challenge → vendor authority")
    ch = _post(s_plt, f"{plat}/api/v1/challenge",
               {"user_id": cid, "client_ts": int(time.time())})
    nonce = ch["nonce"]

    step("2/3  courier/init → sidecar (fetch attestation)")
    init = _post(s_kms, f"{kms}/courier/init", {"nonce": nonce})
    attestation = init.get("attestation", "")
    vm_config   = init.get("vm_config", "")
    if not attestation:
        die("no attestation from sidecar (guest agent unavailable)")
    ok(f"attestation: {len(attestation)//2} bytes")

    step("3/3  measure → vendor authority (read-only, no root release)")
    m = _post(s_plt, f"{plat}/api/v1/measure",
              {"attestation": attestation, "vm_config": vm_config})
    ok(f"quote_verified={m['quote_verified']}  tcb={m.get('tcb_status')}")
    print(f"  os_image_hash : {m.get('os_image_hash')}")
    print(f"  compose_hash  : {m.get('compose_hash')}")
    print(f"  mr_aggregated : {m.get('mr_aggregated')}")
    print(f"  key_provider  : {m.get('key_provider')}")
    info("set EXPECTED_OS_IMAGE_HASH=<os_image_hash> on the authority, then provision.")


def cmd_create_user(args):
    """Admin: create a user with its own independent root key."""
    s = _session(args.admin_token)
    step(f"create user → {args.user_id}")
    resp = _post(s, f"{args.authority_url.rstrip('/')}/api/v1/admin/users",
                 {"user_id": args.user_id, "name": args.name or ""})
    ok(f"user_id: {resp['user_id']}")
    print(f"\n  API KEY (store now, shown once):\n    {resp['api_key']}\n")


def cmd_list_users(args):
    """Admin: list all users (metadata only)."""
    s = _session(args.admin_token)
    step("list users")
    resp = _get(s, f"{args.authority_url.rstrip('/')}/api/v1/admin/users")
    users = resp.get("users", []) if isinstance(resp, dict) else []
    if not users:
        info("no users")
        return
    for u in users:
        ok(f"{u['user_id']:20s} seq={u['bundle_seq']} images={u['image_count']} "
           f"name={u.get('name','')!r}")


def cmd_rotate_key(args):
    """Admin: issue a fresh API key for a user (root key unchanged)."""
    s = _session(args.admin_token)
    step(f"rotate api key → {args.user_id}")
    resp = _post(s, f"{args.authority_url.rstrip('/')}/api/v1/admin/users/{args.user_id}/rotate-key", {})
    print(f"\n  NEW API KEY (store now, shown once):\n    {resp['api_key']}\n")


def cmd_sync_auth(args):
    """Push updated AuthBundle to sidecar without re-provisioning root key.

    Collects usage receipt from sidecar, sends to authority, installs new bundle.
    """
    kms   = args.kms_url.rstrip("/")
    plat  = args.authority_url.rstrip("/")
    cid   = args.user_id
    s_kms = _session("")
    s_plt = _session(args.api_key)

    # 1. collect usage receipt
    step("1/3  usage-receipt ← sidecar")
    receipt = _get(s_kms, f"{kms}/usage-receipt")
    active  = len(receipt.get("active_slots", []))
    old_seq = receipt.get("bundle_seq", "?")
    ok(f"active_slots={active}  bundle_seq={old_seq}")

    # 2. sync-auth
    step("2/3  sync-auth → vendor authority")
    sync = _post(s_plt, f"{plat}/api/v1/sync-auth", {
        "user_id":   cid,
        "usage_receipt": receipt,
    })
    auth_bundle = sync["auth_bundle"]
    new_seq     = auth_bundle.get("bundle_seq", "?")
    ok(f"new bundle_seq={new_seq}")

    # 3. install
    step("3/3  courier/install → sidecar")
    inst = _post(s_kms, f"{kms}/courier/install", {"auth_bundle": auth_bundle})
    if not inst.get("ok"):
        die(f"install rejected: {inst}")
    ok(f"bundle updated  {old_seq} → {new_seq}")

# ─── arg parsing ─────────────────────────────────────────────────────────────

def _common(p: argparse.ArgumentParser, need_authority=False):
    p.add_argument("--kms-url",
                   default=os.getenv("KMS_URL", "http://localhost:8001"),
                   help="KMS sidecar URL (env: KMS_URL)")
    if need_authority:
        p.add_argument("--authority-url",
                       default=os.getenv("AUTHORITY_URL", ""),
                       help="vendor authority URL (env: AUTHORITY_URL)")
        p.add_argument("--user-id",
                       default=os.getenv("USER_ID", ""),
                       help="customer ID (env: USER_ID)")
        p.add_argument("--api-key",
                       default=os.getenv("AUTHORITY_API_KEY", ""),
                       help="authority API key (env: AUTHORITY_API_KEY)")


def main():
    parser = argparse.ArgumentParser(
        prog="kms-ctl",
        description="Operator CLI for GCP private KMS provisioning",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_status = sub.add_parser("status", help="show sidecar health and bundle info")
    _common(p_status)

    p_receipt = sub.add_parser("receipt", help="fetch signed usage receipt")
    _common(p_receipt)

    p_attest = sub.add_parser("attest",
        help="provision KMS: full courier attest (4-step)")
    _common(p_attest, need_authority=True)

    p_sync = sub.add_parser("sync-auth",
        help="push updated AuthBundle without re-provisioning root key")
    _common(p_sync, need_authority=True)

    p_measure = sub.add_parser("measure",
        help="read-only: print measured os_image_hash/compose_hash (no root release)")
    _common(p_measure, need_authority=True)

    # admin: multi-user management
    def _admin(p):
        p.add_argument("--authority-url", default=os.getenv("AUTHORITY_URL", ""),
                       help="vendor authority URL (env: AUTHORITY_URL)")
        p.add_argument("--admin-token", default=os.getenv("AUTHORITY_ADMIN_TOKEN", ""),
                       help="authority admin token (env: AUTHORITY_ADMIN_TOKEN)")

    p_cu = sub.add_parser("create-user", help="admin: create a user + independent root key")
    _admin(p_cu)
    p_cu.add_argument("--user-id", required=True)
    p_cu.add_argument("--name", default="")

    p_lu = sub.add_parser("list-users", help="admin: list users")
    _admin(p_lu)

    p_rk = sub.add_parser("rotate-key", help="admin: rotate a user's API key")
    _admin(p_rk)
    p_rk.add_argument("--user-id", required=True)

    args = parser.parse_args()

    # validate required authority args
    if args.cmd in ("attest", "sync-auth", "measure"):
        if not args.authority_url:
            die("--authority-url / AUTHORITY_URL required")
        if not args.user_id:
            die("--user-id / USER_ID required")
    if args.cmd in ("create-user", "list-users", "rotate-key"):
        if not args.authority_url:
            die("--authority-url / AUTHORITY_URL required")
        if not args.admin_token:
            die("--admin-token / AUTHORITY_ADMIN_TOKEN required")

    dispatch = {
        "status":      cmd_status,
        "receipt":     cmd_receipt,
        "attest":      cmd_attest,
        "measure":     cmd_measure,
        "sync-auth":   cmd_sync_auth,
        "create-user": cmd_create_user,
        "list-users":  cmd_list_users,
        "rotate-key":  cmd_rotate_key,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()

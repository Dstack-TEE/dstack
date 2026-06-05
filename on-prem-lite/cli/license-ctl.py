#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""license-ctl — operator courier CLI for on-prem-lite (KMS-less single CVM).

Untrusted relay that bridges the vendor Authority (internet) and the workload
launcher's plain-HTTP courier port (reached over an IAP tunnel). It moves opaque
blobs between the two; it is never a trust anchor. The launcher terminates the
courier, attests, verifies the License against its pinned AUTHORITY_PUBKEY, and
HPKE-opens the per-image CEK.

Usage:
  license-ctl attest  --launcher-url URL --authority-url URL --user-id ID \
                      --app-id ID --workload-digest sha256:… --api-key KEY
  license-ctl renew   (same args/flow as attest — issues a fresh License)
  license-ctl status  --launcher-url URL
  license-ctl healthz --launcher-url URL

Environment variable equivalents (override with flags):
  LAUNCHER_URL       launcher courier HTTP URL   (default http://localhost:9000)
  AUTHORITY_URL      vendor authority URL
  AUTHORITY_API_KEY  api key for vendor authority (Bearer token)
  USER_ID            tenant / user identifier
  APP_ID             workload app id (40 hex)
  WORKLOAD_DIGEST    encrypted workload image digest (sha256:…)
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
        die(f"http {e.response.status_code} from {url}: {e.response.text[:300]}")
    except requests.ConnectionError:
        die(f"cannot connect to {url}")


def _get(session: requests.Session, url: str) -> dict | str:
    try:
        r = session.get(url, timeout=10)
        r.raise_for_status()
        ct = r.headers.get("content-type", "")
        return r.json() if "json" in ct else r.text
    except requests.HTTPError as e:
        die(f"http {e.response.status_code} from {url}: {e.response.text[:300]}")
    except requests.ConnectionError:
        die(f"cannot connect to {url}")

# ─── commands ─────────────────────────────────────────────────────────────────

def cmd_attest(args):
    """full courier flow: issue + install a License for one workload.

    step 1  challenge       → nonce from vendor authority
    step 2  courier/init    → transport keypair + TDX+vTPM attestation from launcher
    step 3  license         → authority verifies quote, returns {license, sealed_cek}
    step 4  courier/install → launcher verifies sig, opens CEK, decrypts + runs workload
    """
    launcher = args.launcher_url.rstrip("/")
    authority = args.authority_url.rstrip("/")
    uid = args.user_id
    s_lnch = _session("")
    s_auth = _session(args.api_key)

    # 1. challenge
    step("1/4  challenge → vendor authority")
    ch = _post(s_auth, f"{authority}/api/v1/challenge",
               {"user_id": uid, "client_ts": int(time.time())})
    nonce = ch["nonce"]
    ok(f"nonce: {nonce[:16]}…")

    # 2. courier init → launcher attests
    step("2/4  courier/init → launcher")
    init = _post(s_lnch, f"{launcher}/courier/init", {"nonce": nonce})
    transport_pub = init["transport_pub"]
    kms_ts        = init["kms_ts"]
    attestation   = init.get("attestation", "")
    vm_config     = init.get("vm_config", "")
    ok(f"transport_pub: {transport_pub[:20]}…  kms_ts: {kms_ts}")
    if attestation:
        ok(f"attestation: {len(attestation)//2} bytes (TDX+vTPM)")
    else:
        info("note: attestation is empty (guest agent unavailable)")

    # 3. license → authority verifies + signs
    step("3/4  license → vendor authority")
    resp = _post(s_auth, f"{authority}/api/v1/license", {
        "user_id":         uid,
        "app_id":          args.app_id,
        "nonce":           nonce,
        "transport_pub":   transport_pub,
        "kms_ts":          kms_ts,
        "attestation":     attestation,
        "vm_config":       vm_config,
        "workload_digest": args.workload_digest,
    })
    license_obj = resp["license"]
    sealed_cek  = resp["sealed_cek"]
    seq      = license_obj.get("seq", "?")
    expires  = license_obj.get("expires_at", "?")
    wl       = license_obj.get("workload", {})
    ok(f"license seq={seq}  expires_at={expires}  digest={wl.get('digest', '?')}")
    ok(f"sealed_cek: {len(sealed_cek)} bytes (HPKE → transport_pub)")

    # 4. install → launcher verifies, opens CEK, runs workload
    step("4/4  courier/install → launcher")
    inst = _post(s_lnch, f"{launcher}/courier/install", {
        "sealed_cek": sealed_cek,
        "license":    license_obj,
    })
    if not inst.get("ok"):
        die(f"install rejected: {inst}")
    ok("launcher licensed: workload decrypted and running")

    # verify
    health = _get(s_lnch, f"{launcher}/healthz")
    ok(f"healthz: {health}")


def cmd_status(args):
    """show launcher status (license seq / expiry / workload)."""
    s = _session("")
    step("status")
    st = _get(s, f"{args.launcher_url.rstrip('/')}/status")
    print(json.dumps(st, indent=2) if isinstance(st, dict) else st)


def cmd_healthz(args):
    """show launcher health."""
    s = _session("")
    step("healthz")
    health = _get(s, f"{args.launcher_url.rstrip('/')}/healthz")
    ok(f"status: {health}")

# ─── arg parsing ─────────────────────────────────────────────────────────────

def _launcher(p: argparse.ArgumentParser):
    p.add_argument("--launcher-url",
                   default=os.getenv("LAUNCHER_URL", "http://localhost:9000"),
                   help="launcher courier URL (env: LAUNCHER_URL)")


def _issue(p: argparse.ArgumentParser):
    _launcher(p)
    p.add_argument("--authority-url",
                   default=os.getenv("AUTHORITY_URL", ""),
                   help="vendor authority URL (env: AUTHORITY_URL)")
    p.add_argument("--user-id",
                   default=os.getenv("USER_ID", ""),
                   help="tenant / user id (env: USER_ID)")
    p.add_argument("--app-id",
                   default=os.getenv("APP_ID", ""),
                   help="workload app id, 40 hex (env: APP_ID)")
    p.add_argument("--workload-digest",
                   default=os.getenv("WORKLOAD_DIGEST", ""),
                   help="encrypted workload image digest sha256:… (env: WORKLOAD_DIGEST)")
    p.add_argument("--api-key",
                   default=os.getenv("AUTHORITY_API_KEY", ""),
                   help="authority api key (env: AUTHORITY_API_KEY)")


def main():
    parser = argparse.ArgumentParser(
        prog="license-ctl",
        description="operator courier CLI for on-prem-lite (KMS-less licensed workload)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_attest = sub.add_parser("attest", aliases=["issue"],
        help="issue + install a License (full 4-step courier flow)")
    _issue(p_attest)

    p_renew = sub.add_parser("renew",
        help="issue a fresh License (higher seq / later expiry); same flow as attest")
    _issue(p_renew)

    p_status = sub.add_parser("status", help="show launcher status (license/workload)")
    _launcher(p_status)

    p_healthz = sub.add_parser("healthz", help="show launcher health")
    _launcher(p_healthz)

    args = parser.parse_args()

    # validate required authority args for the issuing flow
    if args.cmd in ("attest", "issue", "renew"):
        if not args.authority_url:
            die("--authority-url / AUTHORITY_URL required")
        if not args.user_id:
            die("--user-id / USER_ID required")
        if not args.app_id:
            die("--app-id / APP_ID required")
        if not args.workload_digest:
            die("--workload-digest / WORKLOAD_DIGEST required")

    dispatch = {
        "attest":  cmd_attest,
        "issue":   cmd_attest,
        "renew":   cmd_attest,
        "status":  cmd_status,
        "healthz": cmd_healthz,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()

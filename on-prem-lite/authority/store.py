# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""File-backed store for the on-prem-lite authority.

Forked from on-prem/authority/store.py and simplified for the KMS-less profile:
no per-tenant KMS root material. A single JSON file holds tenants (each with
apps → allowed_workloads + a monotonic license_seq), the image-key keystore
(EC P-256 keypairs), and the runtime-managed policy (launcher compose hashes +
optional os-image whitelist).

Schema (AUTHORITY_LITE_STORE, default ~/.config/authority-lite/store.json):
{
  "tenants": {
    "<tenant_id>": {
      "name": "<str>",
      "api_key_hash": "<sha256 hex>",
      "license_ttl": <int|absent>,            # per-tenant TTL override (secs)
      "created_at": <unix>,
      "apps": {
        "<app_id>": {
          "name": "<str>",
          "allowed_workloads": [{"image","digest","kid"}],
          "license_seq": <int>
        }
      }
    }
  },
  "image_keys": [{"kid","priv_pem","pub_pem","created_at"}],
  "policy": {"launcher_compose_hashes": [], "os_images": []}
}
"""

import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional

from crypto import (
    generate_keypair,
    generate_api_key,
    hash_api_key,
    api_key_matches,
)

_STORE_PATH = os.path.expanduser(
    os.getenv("AUTHORITY_LITE_STORE", "~/.config/authority-lite/store.json")
)


class Store:
    """Single-file store for tenants, apps, image keys, and policy. Challenge
    nonces are stateless (HMAC, see crypto.issue_challenge), so nothing
    nonce-related is kept here."""

    def __init__(self) -> None:
        self.data: Dict[str, Any] = {
            "tenants": {},
            "image_keys": [],
            "policy": {"launcher_compose_hashes": [], "os_images": []},
        }
        self._load()

    # ─── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if os.path.exists(_STORE_PATH):
            try:
                with open(_STORE_PATH) as f:
                    loaded = json.load(f)
                self.data["tenants"] = loaded.get("tenants", {})
                self.data["image_keys"] = loaded.get("image_keys", [])
                pol = loaded.get("policy", {})
                self.data["policy"] = {
                    "launcher_compose_hashes": [h.lower() for h in pol.get("launcher_compose_hashes", [])],
                    "os_images": [h.lower() for h in pol.get("os_images", [])],
                }
                return  # persisted store is authoritative — do NOT re-seed from env
            except (json.JSONDecodeError, OSError):
                pass
        # first run only (no store file): seed policy from legacy env vars so a
        # fresh deployment can boot pre-configured; thereafter manage via admin API.
        for h in (x.strip().lower() for x in
                  os.getenv("ALLOWED_LAUNCHER_COMPOSE_HASHES", "").split(",") if x.strip()):
            self.data["policy"]["launcher_compose_hashes"].append(h)
        env_os = os.getenv("EXPECTED_OS_IMAGE_HASH", "").strip().lower()
        if env_os:
            self.data["policy"]["os_images"].append(env_os)
        self._save()

    def _save(self) -> None:
        os.makedirs(os.path.dirname(_STORE_PATH), exist_ok=True)
        with open(_STORE_PATH, "w") as f:
            json.dump(self.data, f, indent=2)

    # ─── tenants ──────────────────────────────────────────────────────────────

    def create_tenant(self, tenant_id: str, name: str = "") -> str:
        """Create a tenant. Returns the plaintext API key (shown once).
        Raises ValueError if the tenant already exists."""
        if tenant_id in self.data["tenants"]:
            raise ValueError(f"tenant already exists: {tenant_id}")
        api_key = generate_api_key()
        self.data["tenants"][tenant_id] = {
            "name": name,
            "api_key_hash": hash_api_key(api_key),
            "created_at": int(time.time()),
            "apps": {},
        }
        self._save()
        return api_key

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        return self.data["tenants"].get(tenant_id)

    def find_tenant_by_api_key(self, api_key: str) -> Optional[str]:
        """Resolve a bearer API key to its tenant_id, or None if no match."""
        if not api_key:
            return None
        for tid, rec in self.data["tenants"].items():
            stored = rec.get("api_key_hash")
            if stored and api_key_matches(api_key, stored):
                return tid
        return None

    def license_ttl(self, tenant_id: str, default_ttl: int) -> int:
        """Per-tenant license TTL override, else the supplied default (env)."""
        rec = self.data["tenants"].get(tenant_id) or {}
        ttl = rec.get("license_ttl")
        return int(ttl) if ttl else int(default_ttl)

    # ─── apps (per tenant) ────────────────────────────────────────────────────

    def create_app(self, tenant_id: str, app_id: str = "", name: str = "") -> str:
        """Register an app under a tenant. If app_id is omitted the authority
        assigns a 40-hex id (matching the verifier's app_info.app_id shape).
        Returns the app_id. Raises ValueError on unknown tenant / collision."""
        rec = self.data["tenants"].get(tenant_id)
        if rec is None:
            raise ValueError(f"unknown tenant: {tenant_id}")
        if not app_id:
            app_id = secrets.token_hex(20)   # 40 hex chars
        app_id = app_id.lower()
        apps: Dict[str, Any] = rec.setdefault("apps", {})
        if app_id in apps:
            raise ValueError(f"app already exists: {app_id}")
        apps[app_id] = {"name": name, "allowed_workloads": [], "license_seq": 0}
        self._save()
        return app_id

    def get_app(self, tenant_id: str, app_id: str) -> Optional[Dict[str, Any]]:
        rec = self.data["tenants"].get(tenant_id)
        if rec is None:
            return None
        return (rec.get("apps") or {}).get((app_id or "").lower())

    def is_registered_app(self, tenant_id: str, app_id: str) -> bool:
        """True iff app_id is a registered app under this tenant (fail-closed)."""
        return self.get_app(tenant_id, app_id) is not None

    def register_workload(self, tenant_id: str, app_id: str,
                          image: str, digest: str, kid: str) -> dict:
        """Append (image,digest,kid) to an app's allowed_workloads and record it
        as the current workload. Raises ValueError on unknown tenant/app."""
        app = self.get_app(tenant_id, app_id)
        if app is None:
            raise ValueError(f"app not found: {app_id} (create it first)")
        wl: List[Dict[str, str]] = app.setdefault("allowed_workloads", [])
        entry = {"image": image, "digest": digest, "kid": kid}
        if not any(w.get("digest") == digest for w in wl):
            wl.append(entry)
        app["current_workload"] = entry
        self._save()
        return entry

    def find_allowed_workload(self, tenant_id: str, app_id: str, digest: str) -> Optional[dict]:
        """Return the {image,digest,kid} entry for `digest` if it is in THIS
        app's allowed_workloads, else None (fail-closed: empty list ⇒ None)."""
        app = self.get_app(tenant_id, app_id)
        if app is None:
            return None
        for w in app.get("allowed_workloads", []):
            if w.get("digest") == digest:
                return w
        return None

    def bump_license_seq(self, tenant_id: str, app_id: str) -> int:
        """Monotonically bump and return the license seq for (tenant, app_id)."""
        app = self.get_app(tenant_id, app_id)
        if app is None:
            raise ValueError(f"app not found: {app_id}")
        app["license_seq"] = int(app.get("license_seq", 0)) + 1
        self._save()
        return app["license_seq"]

    # ─── image-key keystore (EC P-256 keypairs) ───────────────────────────────
    # Each entry {kid, priv_pem, pub_pem, created_at}. Images are encrypted to
    # pub_pem; priv_pem is the CEK, HPKE-sealed to attested launchers and never
    # returned by the API.

    def mint_key(self, kid: str = "") -> dict:
        """Mint a new image keypair into the keystore. Persists the private key;
        returns {kid, pub_pem, created_at} — the PRIVATE key is never returned."""
        if not kid:
            kid = secrets.token_hex(8)
        if any(k.get("kid") == kid for k in self.data["image_keys"]):
            raise ValueError(f"kid already exists: {kid}")
        kp = generate_keypair()
        entry = {
            "kid": kid,
            "priv_pem": kp["priv_pem"],
            "pub_pem": kp["pub_pem"],
            "created_at": int(time.time()),
        }
        self.data["image_keys"].append(entry)
        self._save()
        return {"kid": kid, "pub_pem": kp["pub_pem"], "created_at": entry["created_at"]}

    def get_key(self, kid: str) -> Optional[dict]:
        """Return the full keystore entry (incl. priv_pem) for kid, or None."""
        for k in self.data["image_keys"]:
            if k.get("kid") == kid:
                return k
        return None

    def list_keys(self) -> List[dict]:
        """List the keystore (kid + public key only; private keys never echoed)."""
        return [{"kid": k["kid"], "pub_pem": k["pub_pem"], "created_at": k.get("created_at", 0)}
                for k in self.data["image_keys"]]

    # ─── runtime-managed policy ───────────────────────────────────────────────
    # launcher_compose_hashes gates which launcher build (G6); os_images is an
    # OPTIONAL os-image whitelist (G4). Hashes stored lowercase.

    def _policy_add(self, key: str, h: str) -> list:
        h = (h or "").strip().lower()
        if not h:
            raise ValueError("empty hash")
        if h not in self.data["policy"][key]:
            self.data["policy"][key].append(h)
            self._save()
        return list(self.data["policy"][key])

    def _policy_remove(self, key: str, h: str) -> bool:
        h = (h or "").strip().lower()
        before = len(self.data["policy"][key])
        self.data["policy"][key] = [x for x in self.data["policy"][key] if x != h]
        removed = len(self.data["policy"][key]) < before
        if removed:
            self._save()
        return removed

    def add_launcher_compose_hash(self, h: str) -> list:
        return self._policy_add("launcher_compose_hashes", h)

    def remove_launcher_compose_hash(self, h: str) -> bool:
        return self._policy_remove("launcher_compose_hashes", h)

    def get_launcher_compose_hashes(self) -> list:
        return list(self.data["policy"]["launcher_compose_hashes"])

    def add_os_image(self, h: str) -> list:
        return self._policy_add("os_images", h)

    def remove_os_image(self, h: str) -> bool:
        return self._policy_remove("os_images", h)

    def get_os_images(self) -> list:
        return list(self.data["policy"]["os_images"])

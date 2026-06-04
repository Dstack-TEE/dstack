# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional

from crypto import (
    generate_root_material,
    generate_cek,
    generate_keypair,
    generate_api_key,
    hash_api_key,
    api_key_matches,
)

_USERS_PATH = os.path.expanduser(
    os.getenv("VENDOR_AUTHORITY_STORE", "~/.config/authority/users.json")
)
# The image-decryption keyring is GLOBAL (vendor-wide), not per-user: the vendor
# ships one encrypted image artifact to every tenant, so one keypair must
# decrypt it everywhere. Stored separately from per-user records (whose
# root_material stays strictly per-user — those derive tenant-specific keys).
_KEYRING_PATH = os.path.expanduser(
    os.getenv("VENDOR_KEYRING_STORE", "~/.config/authority/keyring.json")
)
# GLOBAL, runtime-managed attestation policy (vendor-wide): which OS-image
# hashes and which KMS compose hashes are allowed. Managed via the admin API
# (POST/DELETE) — no restart needed — and seeded once from the legacy env vars
# EXPECTED_OS_IMAGE_HASH / ALLOWED_KMS_COMPOSE_HASHES. (launcher compose hashes
# stay per-app in the user records.)
_POLICY_PATH = os.path.expanduser(
    os.getenv("AUTHORITY_POLICY_STORE", "~/.config/authority/policy.json")
)


class Store:
    """File-backed store for customer records. Challenge nonces are stateless
    (HMAC, see crypto.issue_challenge), so nothing nonce-related is kept here."""

    def __init__(self) -> None:
        self.users: Dict[str, Dict[str, Any]] = {}
        self.keyring: List[Dict[str, Any]] = []   # global image-decryption keyring
        self.policy: Dict[str, List[str]] = {"os_images": [], "kms_compose_hashes": []}
        self._load_customers()
        self._load_keyring()
        self._load_policy()

    def _load_customers(self) -> None:
        if os.path.exists(_USERS_PATH):
            try:
                with open(_USERS_PATH) as f:
                    self.users = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

    def _save_customers(self) -> None:
        os.makedirs(os.path.dirname(_USERS_PATH), exist_ok=True)
        with open(_USERS_PATH, "w") as f:
            json.dump(self.users, f, indent=2)

    def get_or_create_user(self, user_id: str) -> Dict[str, Any]:
        if user_id not in self.users:
            self.users[user_id] = {
                "root_material": generate_root_material(),
                "bundle_seq": 0,
                "ceks": {},
            }
            self._save_customers()
        else:
            # migrate legacy records (root_key / RSA root_bundle) to root_material.
            # The old RSA CA is incompatible with the dstack-kms P-256 KDF, so we
            # regenerate; a re-provision re-derives the full key set on the KMS side.
            c = self.users[user_id]
            if "root_material" not in c:
                c.pop("root_key", None)
                c.pop("root_bundle", None)
                c["root_material"] = generate_root_material()
                c.setdefault("ceks", {})
                c.setdefault("bundle_seq", 0)
                self._save_customers()
        return self.users[user_id]

    def get_or_create_cek(self, user_id: str, app_id: str, image_digest: str) -> str:
        """Return existing CEK for the digest, or generate and persist a new one."""
        c = self.get_or_create_user(user_id)
        ceks: Dict[str, str] = c.setdefault("ceks", {})
        if image_digest not in ceks:
            ceks[image_digest] = generate_cek()
            self._save_customers()
        return ceks[image_digest]

    def bump_bundle_seq(self, user_id: str) -> int:
        c = self.get_or_create_user(user_id)
        c["bundle_seq"] += 1
        self._save_customers()
        return c["bundle_seq"]

    # ─── real authorization data (per-app whitelist + image CEKs) ─────────────

    @staticmethod
    def _migrate_app(app: dict) -> dict:
        """Normalise an app record to the current schema (two per-app digest
        whitelists), migrating older field names in place."""
        if "allowed_launcher_hashes" in app:
            app["allowed_launcher_digests"] = app.pop("allowed_launcher_hashes")
        app.setdefault("allowed_launcher_digests", [])
        if "allowed_workload_digests" not in app:
            wl = [i["digest"] for i in app.get("allowed_images", []) if i.get("digest")]
            cur = app.get("current_image_digest")
            if cur and cur not in wl:
                wl.append(cur)
            app["allowed_workload_digests"] = wl
        app.pop("allowed_images", None)
        return app

    def register_app_image(self, user_id: str, app_id: str, launcher_digests,
                           image_digest: str, cek: str = "") -> dict:
        """Register a workload app: which launcher (compose digest) may run it and
        which workload-image digest it may decrypt+run.

        Carries into the AuthBundle's app_whitelist:
          - allowed_launcher_digests: the launcher's measured compose_hash(es)
          - allowed_workload_digests: the payload image digest(s) the launcher may
            request a keyring lease for (key-broker enforces req.image_digest ∈)
          - current_image_digest: the active version the launcher should run
        (`cek` is accepted for call-compat and ignored — the global JWE keyring
        replaced per-digest CEKs.)
        """
        c = self.get_or_create_user(user_id)
        apps: Dict[str, Any] = c.setdefault("apps", {})
        app = self._migrate_app(apps.setdefault(app_id, {"app_id": app_id}))
        for h in (launcher_digests if isinstance(launcher_digests, list) else [launcher_digests]):
            if h and h not in app["allowed_launcher_digests"]:
                app["allowed_launcher_digests"].append(h)
        if image_digest and image_digest not in app["allowed_workload_digests"]:
            app["allowed_workload_digests"].append(image_digest)
        if image_digest:
            app["current_image_digest"] = image_digest
        self._save_customers()
        return app

    def get_apps(self, user_id: str) -> list:
        """Real app_whitelist for a user (empty if none registered)."""
        c = self.get_or_create_user(user_id)
        return [self._migrate_app(a) for a in c.get("apps", {}).values()]

    # ─── GLOBAL image-decryption keyring (ocicrypt native JWE) ────────────────
    # Vendor-wide, NOT per-user: the vendor encrypts one image to the current
    # global PUBLIC key and ships it to every tenant; each tenant's AuthBundle
    # carries the global PRIVATE keys, so any authorized launcher (of any tenant)
    # decrypts the same artifact. A keypair is used for a period across many
    # images. Rotation = mint a new kid and encrypt to its pubkey (no
    # re-register); revocation = drop a kid (then re-encrypt + re-ship the images
    # that used it). Per-user isolation lives in root_material, not here.

    def _load_keyring(self) -> None:
        if os.path.exists(_KEYRING_PATH):
            try:
                with open(_KEYRING_PATH) as f:
                    self.keyring = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

    def _save_keyring(self) -> None:
        os.makedirs(os.path.dirname(_KEYRING_PATH), exist_ok=True)
        with open(_KEYRING_PATH, "w") as f:
            json.dump(self.keyring, f, indent=2)

    def mint_key(self, kid: str = "", not_after: int = 0) -> dict:
        """Mint a new image keypair into the GLOBAL keyring. Persists the private
        key; returns {kid, pub_pem, created_at[, not_after]} — the PRIVATE key is
        never returned (it only leaves via AuthBundles to attested TEEs)."""
        if not kid:
            kid = secrets.token_hex(8)
        if any(k.get("kid") == kid for k in self.keyring):
            raise ValueError(f"kid already exists: {kid}")
        kp = generate_keypair()
        entry = {
            "kid": kid,
            "priv_pem": kp["priv_pem"],
            "pub_pem": kp["pub_pem"],
            "created_at": int(time.time()),
        }
        if not_after:
            entry["not_after"] = int(not_after)
        self.keyring.append(entry)
        self._save_keyring()
        # caller-facing view: public key only
        out = {"kid": kid, "pub_pem": kp["pub_pem"], "created_at": entry["created_at"]}
        if not_after:
            out["not_after"] = int(not_after)
        return out

    def get_keyring(self) -> list:
        """The global keyring (each {kid, priv_pem, pub_pem, created_at[, not_after]})."""
        return list(self.keyring)

    def revoke_key(self, kid: str) -> bool:
        """Drop a kid from the global keyring. Returns True if something was removed."""
        kept = [k for k in self.keyring if k.get("kid") != kid]
        removed = len(kept) < len(self.keyring)
        self.keyring = kept
        if removed:
            self._save_keyring()
        return removed

    # ─── GLOBAL attestation policy: allowed os-image / KMS-compose hashes ──────
    # Runtime-managed (admin API), seeded once from env. Hashes stored lowercase.

    def _load_policy(self) -> None:
        if os.path.exists(_POLICY_PATH):
            try:
                with open(_POLICY_PATH) as f:
                    p = json.load(f)
                self.policy["os_images"] = [h.lower() for h in p.get("os_images", [])]
                self.policy["kms_compose_hashes"] = [h.lower() for h in p.get("kms_compose_hashes", [])]
                return  # persisted policy is authoritative — do NOT re-seed from env
                        # (else an explicitly-removed hash would come back on restart)
            except (json.JSONDecodeError, OSError):
                pass
        # first run only (no policy file): seed from legacy env vars so existing
        # deployments keep working; thereafter manage via the admin API.
        env_os = os.getenv("EXPECTED_OS_IMAGE_HASH", "").strip().lower()
        if env_os:
            self.policy["os_images"].append(env_os)
        for h in (x.strip().lower() for x in os.getenv("ALLOWED_KMS_COMPOSE_HASHES", "").split(",") if x.strip()):
            self.policy["kms_compose_hashes"].append(h)
        self._save_policy()

    def _save_policy(self) -> None:
        os.makedirs(os.path.dirname(_POLICY_PATH), exist_ok=True)
        with open(_POLICY_PATH, "w") as f:
            json.dump(self.policy, f, indent=2)

    def _policy_add(self, key: str, h: str) -> list:
        h = (h or "").strip().lower()
        if not h:
            raise ValueError("empty hash")
        if h not in self.policy[key]:
            self.policy[key].append(h)
            self._save_policy()
        return list(self.policy[key])

    def _policy_remove(self, key: str, h: str) -> bool:
        h = (h or "").strip().lower()
        before = len(self.policy[key])
        self.policy[key] = [x for x in self.policy[key] if x != h]
        removed = len(self.policy[key]) < before
        if removed:
            self._save_policy()
        return removed

    def add_os_image(self, h: str) -> list: return self._policy_add("os_images", h)
    def remove_os_image(self, h: str) -> bool: return self._policy_remove("os_images", h)
    def get_os_images(self) -> list: return list(self.policy["os_images"])

    def add_kms_compose_hash(self, h: str) -> list: return self._policy_add("kms_compose_hashes", h)
    def remove_kms_compose_hash(self, h: str) -> bool: return self._policy_remove("kms_compose_hashes", h)
    def get_kms_compose_hashes(self) -> list: return list(self.policy["kms_compose_hashes"])

    # ─── per-app digest whitelist management (dynamic) ────────────────────────
    # field ∈ {"allowed_launcher_digests", "allowed_workload_digests"}
    def _app(self, user_id: str, app_id: str) -> dict:
        app = self.get_or_create_user(user_id).get("apps", {}).get(app_id)
        if not app:
            raise ValueError(f"app not found: {app_id} (register it first)")
        return self._migrate_app(app)

    def add_app_digest(self, user_id: str, app_id: str, field: str, h: str) -> list:
        app = self._app(user_id, app_id)
        if h and h not in app[field]:
            app[field].append(h)
            self._save_customers()
        return list(app[field])

    def remove_app_digest(self, user_id: str, app_id: str, field: str, h: str) -> list:
        app = self._app(user_id, app_id)
        app[field] = [x for x in app[field] if x != h]
        self._save_customers()
        return list(app[field])

    def get_app_digests(self, user_id: str, app_id: str, field: str) -> list:
        return list(self._app(user_id, app_id)[field])

    # ─── multi-user management ────────────────────────────────────────────────
    # A "user" is a customer that owns an API key. Each user gets its own
    # independently-generated root key material (root_material) at creation,
    # so one user can never derive another user's keys.

    def create_user(self, user_id: str, name: str = "") -> str:
        """Create a new user with an independent root key. Returns the plaintext
        API key (shown once). Raises ValueError if the user already exists."""
        if user_id in self.users:
            raise ValueError(f"user already exists: {user_id}")
        api_key = generate_api_key()
        self.users[user_id] = {
            "name": name,
            "api_key_hash": hash_api_key(api_key),
            "created_at": int(time.time()),
            "root_material": generate_root_material(),  # independent per user
            "bundle_seq": 0,
            "ceks": {},
        }
        self._save_customers()
        return api_key

    def find_user_by_api_key(self, api_key: str) -> Optional[str]:
        """Resolve a bearer API key to its user_id, or None if no match."""
        if not api_key:
            return None
        for cid, rec in self.users.items():
            stored = rec.get("api_key_hash")
            if stored and api_key_matches(api_key, stored):
                return cid
        return None

    def rotate_api_key(self, user_id: str) -> str:
        """Issue a fresh API key for an existing user. Returns the plaintext key."""
        if user_id not in self.users:
            raise ValueError(f"unknown user: {user_id}")
        api_key = generate_api_key()
        self.users[user_id]["api_key_hash"] = hash_api_key(api_key)
        self._save_customers()
        return api_key

    def delete_user(self, user_id: str) -> bool:
        if user_id in self.users:
            del self.users[user_id]
            self._save_customers()
            return True
        return False

    def list_users(self) -> List[Dict[str, Any]]:
        """Public metadata for every user (no secrets / key material)."""
        out: List[Dict[str, Any]] = []
        for cid, rec in self.users.items():
            out.append({
                "user_id": cid,
                "name": rec.get("name", ""),
                "created_at": rec.get("created_at", 0),
                "bundle_seq": rec.get("bundle_seq", 0),
                "image_count": len(rec.get("ceks", {})),
                "has_api_key": bool(rec.get("api_key_hash")),
            })
        return out

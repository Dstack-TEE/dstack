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


class Store:
    """File-backed store for customer records. Challenge nonces are stateless
    (HMAC, see crypto.issue_challenge), so nothing nonce-related is kept here."""

    def __init__(self) -> None:
        self.users: Dict[str, Dict[str, Any]] = {}
        self.keyring: List[Dict[str, Any]] = []   # global image-decryption keyring
        self._load_customers()
        self._load_keyring()

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

    def register_app_image(self, user_id: str, app_id: str, launcher_hashes,
                           image_digest: str, cek: str = "") -> dict:
        """Register a real workload app + an encrypted image's CEK for a user.

        Replaces the placeholder app_whitelist with real data the AuthBundle will
        carry: the app_id, the allowed launcher compose hashes, and the
        {digest → CEK} the launcher needs to decrypt the image. Generates a CEK
        if one isn't supplied. Returns the app entry (incl. the CEK).
        """
        c = self.get_or_create_user(user_id)
        apps: Dict[str, Any] = c.setdefault("apps", {})
        app = apps.setdefault(app_id, {
            "app_id": app_id,
            "allowed_launcher_hashes": [],
            "allowed_images": [],
        })
        # launcher hashes (dedup, "*" allowed for dev)
        for h in (launcher_hashes if isinstance(launcher_hashes, list) else [launcher_hashes]):
            if h and h not in app["allowed_launcher_hashes"]:
                app["allowed_launcher_hashes"].append(h)
        # image + CEK
        if not cek:
            cek = generate_cek()
        existing = next((i for i in app["allowed_images"] if i["digest"] == image_digest), None)
        if existing:
            existing["cek"] = cek
        else:
            app["allowed_images"].append({"digest": image_digest, "cek": cek})
        app["current_image_digest"] = image_digest
        self._save_customers()
        return app

    def get_apps(self, user_id: str) -> list:
        """Real app_whitelist for a user (empty if none registered)."""
        c = self.get_or_create_user(user_id)
        return list(c.get("apps", {}).values())

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

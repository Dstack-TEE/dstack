#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Persistent fixture leases and exact resource ownership journals."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = Path(output.name)
    temporary.replace(path)


@dataclass
class OwnedResource:
    type: str
    identity: dict[str, Any]
    cleanup: dict[str, Any]
    created_at: str = field(default_factory=now)
    state: str = "OWNED"


@dataclass
class Lease:
    schema_version: str
    lease_id: str
    run_id: str
    case_id: str
    provider: str
    profile: str
    created_at: str
    expires_at: str
    state: str = "ALLOCATED"
    resources: list[OwnedResource] = field(default_factory=list)
    error: str | None = None
    cleanup_started_at: str | None = None
    cleanup_finished_at: str | None = None


class LeaseJournal:
    """Write-through journal used for crash-safe cleanup reconciliation."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, lease_id: str) -> Path:
        if not lease_id or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in lease_id
        ):
            raise ValueError(f"invalid lease ID: {lease_id!r}")
        return self.root / f"{lease_id}.json"

    def create(
        self,
        lease_id: str,
        run_id: str,
        case_id: str,
        provider: str,
        profile: str,
        ttl_seconds: int,
    ) -> Lease:
        created = datetime.now(UTC)
        lease = Lease(
            schema_version="1.0",
            lease_id=lease_id,
            run_id=run_id,
            case_id=case_id,
            provider=provider,
            profile=profile,
            created_at=created.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            expires_at=(created + timedelta(seconds=ttl_seconds))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
        )
        if self.path(lease_id).exists():
            raise ValueError(f"lease already exists: {lease_id}")
        self.save(lease)
        return lease

    def save(self, lease: Lease) -> None:
        atomic_json(self.path(lease.lease_id), asdict(lease))

    def load(self, lease_id: str) -> Lease:
        value = json.loads(self.path(lease_id).read_text(encoding="utf-8"))
        value["resources"] = [
            OwnedResource(**resource) for resource in value.get("resources", [])
        ]
        return Lease(**value)

    def add_resource(self, lease: Lease, resource: OwnedResource) -> None:
        lease.resources.append(resource)
        self.save(lease)

    def set_state(self, lease: Lease, state: str, error: str | None = None) -> None:
        lease.state = state
        lease.error = error
        if state == "CLEANING":
            lease.cleanup_started_at = now()
        if state in ("RELEASED", "CLEANUP_ERROR"):
            lease.cleanup_finished_at = now()
        self.save(lease)

    def unfinished(self) -> list[Lease]:
        leases = []
        for path in sorted(self.root.glob("*.json")):
            lease = self.load(path.stem)
            if lease.state not in ("RELEASED",):
                leases.append(lease)
        return leases


def process_identity(pid: int) -> dict[str, Any]:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
    return {"pid": pid, "pgid": os.getpgid(pid), "start_ticks": int(fields[21])}

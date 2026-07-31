#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Guest-image provenance checks shared by central fixture providers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def require_image_backend(image_store: str | Path, image_name: str) -> dict[str, Any]:
    """Load image metadata and require the configured build backend."""
    expected = os.environ.get("DSTACK_TEST_GUEST_IMAGE_BACKEND", "mkosi").strip()
    if not expected:
        raise RuntimeError("DSTACK_TEST_GUEST_IMAGE_BACKEND must not be empty")
    metadata_path = Path(image_store).resolve() / image_name / "metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"guest image metadata is unavailable for {image_name}: {error}"
        ) from error
    actual = metadata.get("backend")
    if actual != expected:
        raise RuntimeError(
            f"guest image {image_name} backend is {actual!r}, expected {expected!r}"
        )
    return {
        "name": image_name,
        "backend": actual,
        "version": metadata.get("version"),
        "git_revision": metadata.get("git_revision"),
        "is_dev": metadata.get("is_dev"),
    }

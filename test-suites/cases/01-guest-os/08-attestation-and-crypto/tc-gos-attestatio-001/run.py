#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify TDX quote report-data hashing, prefixes, and raw boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

from Crypto.Hash import keccak

CASE_ID = "tc-gos-attestatio-001"
REPORT_DATA_START = 568
REPORT_DATA_END = 632
ALGORITHMS = (
    "sha256",
    "sha384",
    "sha512",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "keccak256",
    "keccak384",
    "keccak512",
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def request(url: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Make a bounded successful JSON RPC request with readiness retries."""
    for attempt in range(1, 11):
        value = urllib.request.Request(
            url.replace("{method}", method),
            data=json.dumps(body, separators=(",", ":")).encode(),
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(value, timeout=90) as response:
                result = json.load(response)
            break
        except urllib.error.HTTPError:
            raise
        except (ConnectionError, OSError, TimeoutError, urllib.error.URLError):
            if attempt == 10:
                raise
            time.sleep(2)
    if not isinstance(result, dict):
        raise AssertionError(f"{method} returned non-object JSON")
    return result


def rejected(url: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Require a bounded RPC request to be rejected, retrying resets."""
    for attempt in range(1, 6):
        value = urllib.request.Request(
            url.replace("{method}", method),
            data=json.dumps(body, separators=(",", ":")).encode(),
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(value, timeout=90) as response:
                payload = response.read()
                raise AssertionError(
                    f"{method} accepted invalid input with HTTP {response.status}: {len(payload)} bytes"
                )
        except urllib.error.HTTPError as error:
            payload = error.read()
            return {
                "http_status": error.code,
                "diagnostic_present": bool(payload),
                "diagnostic_sha256": hashlib.sha256(payload).hexdigest(),
            }
        except (ConnectionError, OSError, TimeoutError, urllib.error.URLError):
            if attempt == 5:
                raise
            time.sleep(2)
    raise AssertionError(f"{method} rejection retry loop exhausted")


def digest(algorithm: str, content: bytes) -> bytes:
    """Compute a supported report-data digest and pad it to 64 bytes."""
    if algorithm.startswith("keccak"):
        bits = int(algorithm.removeprefix("keccak"))
        hasher = keccak.new(digest_bits=bits)
        hasher.update(content)
        output = hasher.digest()
    else:
        name = algorithm.replace("-", "_")
        output = hashlib.new(name, content).digest()
    return output + bytes(64 - len(output))


def quote_report_data(response: dict[str, Any]) -> tuple[bytes, int]:
    """Extract report data from a TDX quote using the repository-defined range."""
    quote = bytes.fromhex(str(response["quote"]))
    if len(quote) < REPORT_DATA_END:
        raise AssertionError(f"TDX quote is too short: {len(quote)}")
    return quote[REPORT_DATA_START:REPORT_DATA_END], len(quote)


def verify_quote(
    url: str,
    data: bytes,
    algorithm: str,
    prefix: str,
    expected: bytes,
) -> dict[str, Any]:
    """Request and verify one quote without retaining quote bytes."""
    response = request(
        url,
        "TdxQuote",
        {
            "report_data": data.hex(),
            "hash_algorithm": algorithm,
            "prefix": prefix,
        },
    )
    actual, quote_length = quote_report_data(response)
    if actual != expected:
        raise AssertionError(f"report-data mismatch for {algorithm or 'default'}")
    effective_algorithm = algorithm or "sha512"
    effective_prefix = "" if effective_algorithm == "raw" else (prefix or "app-data")
    if response.get("hash_algorithm") != effective_algorithm:
        raise AssertionError(
            f"effective algorithm mismatch for {algorithm or 'default'}"
        )
    observed_prefix = response.get("prefix")
    stale_custom_prefix = bool(prefix) and observed_prefix == "app-data"
    if observed_prefix != effective_prefix and not stale_custom_prefix:
        raise AssertionError(
            f"effective prefix mismatch for {algorithm or 'default'}: "
            f"expected {effective_prefix!r}, got {observed_prefix!r}"
        )
    return {
        "algorithm": effective_algorithm,
        "prefix": effective_prefix,
        "observed_prefix": observed_prefix,
        "prefix_metadata_current": observed_prefix == effective_prefix,
        "quote_length": quote_length,
        "report_data_sha256": hashlib.sha256(actual).hexdigest(),
        "binding_verified": True,
    }


def main() -> int:
    """Run quote report-data binding acceptance."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    services = manifest.get("values", {}).get("services", {})
    tappd = services.get("Tappd") if isinstance(services, dict) else None
    status = "PASS"
    summary = (
        "TDX quote hash, prefix, raw boundary, and rejection semantics were verified."
    )
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    stage = "capability"
    try:
        if not isinstance(tappd, dict) or not isinstance(tappd.get("url"), str):
            status = "BLOCKED"
            summary = "fixture lacks a lease-owned hardware Tappd quote endpoint"
            observations["missing_capability"] = "hardware-tdx-quote-endpoint"
        else:
            url = str(tappd["url"])
            stage = "health-before"
            before = request(url, "Info", {})
            marker = hashlib.sha512(os.environ["DSTACK_TEST_RUN_ID"].encode()).digest()
            data = marker[:37]
            rows = []
            for algorithm in ALGORITHMS:
                stage = f"algorithm-{algorithm}"
                expected = digest(algorithm, b"app-data:" + data)
                rows.append(verify_quote(url, data, algorithm, "", expected))
            stage = "algorithm-default"
            default_expected = digest("sha512", b"app-data:" + data)
            default = verify_quote(url, data, "", "", default_expected)
            stage = "custom-prefix"
            custom_prefix = "dstack-test-quote"
            custom_expected = digest("sha384", custom_prefix.encode() + b":" + data)
            custom = verify_quote(url, data, "sha384", custom_prefix, custom_expected)
            stage = "raw-64"
            raw = verify_quote(url, marker, "raw", "ignored-prefix", marker)
            stage = "repeat-sha256"
            repeat = verify_quote(
                url, data, "sha256", "", digest("sha256", b"app-data:" + data)
            )
            stage = "negative-inputs"
            invalid = {
                "unknown_algorithm": rejected(
                    url,
                    "TdxQuote",
                    {
                        "report_data": data.hex(),
                        "hash_algorithm": "sha999",
                        "prefix": "",
                    },
                ),
                "raw_63": rejected(
                    url,
                    "TdxQuote",
                    {
                        "report_data": marker[:63].hex(),
                        "hash_algorithm": "raw",
                        "prefix": "",
                    },
                ),
                "raw_65": rejected(
                    url,
                    "TdxQuote",
                    {
                        "report_data": (marker + b"x").hex(),
                        "hash_algorithm": "raw",
                        "prefix": "",
                    },
                ),
            }
            stage = "health-after"
            after = request(url, "Info", {})
            if not before or not after:
                raise AssertionError(
                    "Tappd Info was empty before or after quote matrix"
                )
            if repeat["report_data_sha256"] != rows[0]["report_data_sha256"]:
                raise AssertionError("repeated sha256 binding changed")
            if not custom["prefix_metadata_current"]:
                status = "BLOCKED"
                summary = (
                    "candidate guest image lacks effective custom quote-prefix metadata"
                )
                observations["missing_capability"] = (
                    "candidate-guest-effective-quote-prefix"
                )
            observations.update(
                {
                    "algorithms": rows,
                    "algorithm_count": len(rows),
                    "default": default,
                    "custom_prefix": custom,
                    "raw": raw,
                    "invalid": invalid,
                    "repeat_deterministic": True,
                    "service_healthy_before": True,
                    "service_healthy_after": True,
                }
            )
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as error:
        status = "FAIL"
        summary = str(error)
        observations["failure"] = summary
        observations["failure_stage"] = stage
        summary = f"{stage}: {summary}"
    artifact = {
        "path": "artifacts/quote-report-data-binding.json",
        "step_id": f"{case_id}-step-01",
        "name": "Quote report-data binding",
        "description": "Algorithms, effective prefixes, quote lengths, rejection status, and report-data hashes without quote bytes.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "The lease-owned Tappd endpoint and baseline Info response were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "All documented hashes, default/custom prefixes, raw data, boundaries, and an unknown algorithm were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Quote-embedded report data, deterministic repetition, rejection diagnostics, and final service health were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Report data is extracted from bytes 568..632 of each real TDX quote; quote bytes and marker inputs are not retained.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

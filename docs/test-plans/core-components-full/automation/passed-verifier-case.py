#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic harnesses for promoted dstack-verifier behaviour cases.

The verifier owns no pRPC service, so it has no entry in `api-inventory.json`.
Its whole interface is one HTTP listener (`POST /verify`, `GET /health`) plus
two one-shot CLI modes, and the chapter's cases each assert a different
property of that small surface rather than one method's field matrix. The
shared plumbing -- fixture-manifest resolution, the committed attestation
corpus, request and response recording, result and artifact emission -- lives
here once; `CASES` dispatches each case to the scenario that reproduces what
that case claims to test.

Two properties of this component make the assertions safe to pin. A `/verify`
response carries no timestamp, request id, or counter, so identical input
yields a byte-identical body and determinism can be asserted rather than
assumed. And the one-shot mode writes its result next to the *input* file, so
every scenario copies the committed corpus into the lease workspace first and
checks afterwards that the candidate checkout was not written to.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

# Committed non-production evidence in the candidate checkout. `quote-report`
# is full TDX and needs the image server; the other three carry authenticated
# measurement material and verify offline.
CORPUS = (
    "tdx-lite-attestation.json",
    "tdx-lite-getquote.json",
    "sev-snp-attestation.json",
    "quote-report.json",
)
OFFLINE_VALID = (
    "tdx-lite-attestation.json",
    "tdx-lite-getquote.json",
    "sev-snp-attestation.json",
)

# Fields the verification result projects for every accepted platform. Used to
# compare two results without pinning the whole body.
DETAIL_FIELDS = (
    "quote_verified",
    "event_log_verified",
    "os_image_hash_verified",
    "acpi_tables_verified",
    "tee_variant",
    "tcb_status",
    "advisory_ids",
)
APP_FIELDS = (
    "app_id",
    "compose_hash",
    "instance_id",
    "device_id",
    "mr_system",
    "mr_aggregated",
    "os_image_hash",
)
# Substrings that would mean the component leaked private material into a
# response, a log, or a diagnostic.
SECRET_MARKERS = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY")


class CaseFailure(AssertionError):
    """A tested expectation did not hold."""


def require(condition: object, message: str) -> None:
    """Fail the case when a tested expectation does not hold."""
    if not condition:
        raise CaseFailure(message)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def sha256_file(path: pathlib.Path) -> str:
    """Return the hex SHA-256 of a file without holding it all in memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class Context:
    """Everything a scenario needs from the lease, resolved once."""

    def __init__(self) -> None:
        """Resolve the lease-owned substrate, corpus, and case work area."""
        self.case_id = os.environ["DSTACK_TEST_CASE_ID"]
        self.result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
        self.artifacts = self.result_dir / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        manifest_path = os.environ.get("DSTACK_TEST_CASE_MANIFEST")
        require(manifest_path, "case manifest is required for a verifier case")
        self.manifest = json.loads(pathlib.Path(str(manifest_path)).read_text())
        self.values = self.manifest.get("values") or {}
        self.substrate = self.values.get("component_substrate") or {}
        require(
            self.substrate.get("case_owned") is True,
            "fixture did not report a case-owned component substrate",
        )
        self.workspace = pathlib.Path(str(self.substrate["workspace"]))
        self.ports = {
            str(k): int(v) for k, v in (self.substrate.get("ports") or {}).items()
        }
        self.loopback = str(self.substrate.get("loopback", "127.0.0.1"))
        runtime_path = os.environ.get("DSTACK_TEST_RUNTIME_MANIFEST")
        runtime = (
            json.loads(pathlib.Path(runtime_path).read_text()) if runtime_path else {}
        )
        self.repository = pathlib.Path(
            str(self.values.get("repository") or runtime.get("repository") or "")
        )
        binaries = (
            self.values.get("prepared_binaries")
            or runtime.get("prepared_binaries")
            or {}
        )
        self.binary_record = dict(binaries.get("dstack_verifier") or {})
        self.binary = pathlib.Path(str(self.binary_record.get("path", "")))
        self.verifier = dict(self.values.get("verifier") or {})
        # Case-scoped work area inside the lease workspace. Never the candidate
        # checkout: one-shot mode writes a sidecar next to its input file.
        self.workdir = self.workspace / "run" / f"case-{self.case_id}"
        shutil.rmtree(self.workdir, ignore_errors=True)
        self.workdir.mkdir(parents=True)
        self.fixtures_src = self.repository / "dstack/verifier/fixtures"
        self.corpus: dict[str, pathlib.Path] = {}
        self.corpus_source_sha: dict[str, str] = {}
        # Every verifier this harness starts, so a failed assertion in the
        # middle of a lifecycle scenario cannot orphan a listener on a
        # lease-reserved port.
        self.owned: list[subprocess.Popen[bytes]] = []

    def load_corpus(self) -> None:
        """Copy the committed evidence corpus into the case work area."""
        require(
            self.fixtures_src.is_dir(),
            f"committed verifier fixtures are absent: {self.fixtures_src}",
        )
        target = self.workdir / "fixtures"
        target.mkdir(exist_ok=True)
        for name in CORPUS:
            source = self.fixtures_src / name
            require(source.is_file(), f"committed fixture is absent: {source}")
            self.corpus_source_sha[name] = sha256_file(source)
            destination = target / name
            shutil.copyfile(source, destination)
            self.corpus[name] = destination

    def payload(self, name: str) -> bytes:
        """Return the raw request body of a committed fixture."""
        return self.corpus[name].read_bytes()

    def attestation(self, name: str) -> str:
        """Return the hex attestation blob carried by a committed fixture."""
        return str(json.loads(self.corpus[name].read_text())["attestation"])

    def port(self, name: str) -> int:
        """Return a port the lease reserved for this case."""
        require(name in self.ports, f"lease reserved no {name} port")
        return self.ports[name]


def verify_url(ctx: Context) -> str:
    """Return the lease-owned verifier `/verify` route."""
    url = ctx.verifier.get("verify_url") or (
        (ctx.values.get("services") or {}).get("rpc") or {}
    ).get("url")
    require(url, "fixture manifest declares no verifier verify_url")
    return str(url)


def health_url(ctx: Context) -> str:
    """Return the lease-owned verifier `/health` route."""
    url = ctx.verifier.get("health_url")
    require(url, "fixture manifest declares no verifier health_url")
    return str(url)


# A body the server refuses by size is rejected while the client is still
# writing it, so the client sees EPIPE instead of the 413 response. That is the
# size limit working, not a transport fault, so it is recorded as its own
# outcome rather than raised: status 0 means "the server refused the body".
REFUSED = 0


def http_post(
    url: str, body: bytes, headers: dict[str, str] | None = None, timeout: int = 90
) -> dict[str, Any]:
    """POST a body and record status, payload, elapsed time, and refusal."""
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    started = time.monotonic()
    error_text = ""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, payload = int(response.status), response.read()
    except urllib.error.HTTPError as error:
        status, payload = int(error.code), error.read()
    except (urllib.error.URLError, OSError) as error:
        status, payload, error_text = REFUSED, b"", repr(error)
    return {
        "status": status,
        "payload": payload,
        "error": error_text,
        "elapsed_s": round(time.monotonic() - started, 3),
    }


def http_get(url: str, timeout: int = 30) -> dict[str, Any]:
    """GET a URL and record status and payload."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return {"status": int(response.status), "payload": response.read()}
    except urllib.error.HTTPError as error:
        return {"status": int(error.code), "payload": error.read()}


def result_json(response: dict[str, Any]) -> dict[str, Any]:
    """Decode a `/verify` response body as JSON."""
    return json.loads(response["payload"].decode())


def projection(document: dict[str, Any]) -> dict[str, Any]:
    """Project the measured registers and verdict of a verification result."""
    details = document.get("details") or {}
    app = details.get("app_info") or {}
    out: dict[str, Any] = {
        "is_valid": document.get("is_valid"),
        "reason": document.get("reason"),
    }
    for field in DETAIL_FIELDS:
        out[field] = details.get(field)
    for field in APP_FIELDS:
        out[field] = app.get(field)
    return out


def digest(payload: bytes) -> str:
    """Return the hex SHA-256 of a response body."""
    return hashlib.sha256(payload).hexdigest()


def no_secret(text: str, extra: tuple[str, ...] = ()) -> bool:
    """Report whether a captured string is free of private material."""
    return not any(marker in text for marker in SECRET_MARKERS + extra)


def cache_state(cache: pathlib.Path) -> dict[str, Any]:
    """Describe the measurement cache as entries, not just a top-level listing.

    A failed image download leaves the cache scaffolding (`images/`,
    `images/tmp/`) behind but no content. Comparing only the top-level names
    would call that a leak; comparing only names would miss a partially written
    image. Files and their total size are what "no trusted cache entry" means.
    """
    if not cache.is_dir():
        return {"files": [], "directories": [], "file_bytes": 0}
    files = sorted(
        str(path.relative_to(cache)) for path in cache.rglob("*") if path.is_file()
    )
    directories = sorted(
        str(path.relative_to(cache)) for path in cache.rglob("*") if path.is_dir()
    )
    total = sum((cache / name).stat().st_size for name in files)
    return {"files": files, "directories": directories, "file_bytes": total}


def run_oneshot(
    ctx: Context,
    config: pathlib.Path,
    target: pathlib.Path,
    mode: str = "--verify",
    timeout: int = 180,
    argument: str | None = None,
) -> dict[str, Any]:
    """Run the prepared verifier in one-shot mode and record its observation.

    `argument` is the literal token handed to the CLI when it differs from
    the resolved path -- the `-` row exists precisely to observe how the
    interface treats a conventional stdin sentinel.
    """
    started = time.monotonic()
    completed = subprocess.run(
        [str(ctx.binary), "--config", str(config), mode, argument or str(target)],
        cwd=str(target.parent),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    elapsed = round(time.monotonic() - started, 3)
    document: dict[str, Any] | None = None
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        document = None
    sidecar = target.with_name(target.name + ".verification.json")
    return {
        "input": target.name,
        "mode": mode,
        "returncode": completed.returncode,
        "elapsed_s": elapsed,
        "stdout_is_json": document is not None,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_tail": completed.stderr[-600:],
        "panicked": "panicked at" in completed.stderr,
        "sidecar_written": sidecar.is_file(),
        "document": document,
    }


def write_config(
    path: pathlib.Path,
    port: int,
    cache: pathlib.Path,
    *,
    insecure: bool = False,
    root_ca: str = "",
    timeout_secs: int = 2,
) -> pathlib.Path:
    """Write a verifier configuration file for a case-owned instance."""
    cache.mkdir(parents=True, exist_ok=True)
    path.write_text(
        config_text(
            port, cache, insecure=insecure, root_ca=root_ca, timeout_secs=timeout_secs
        ),
        encoding="utf-8",
    )
    return path


def port_is_free(host: str, port: int) -> bool:
    """Report whether nothing is listening on a lease-reserved port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1.0)
        return probe.connect_ex((host, port)) != 0


def start_instance(
    ctx: Context,
    config: pathlib.Path,
    port: int,
    log: pathlib.Path,
    deadline: float = 30.0,
) -> tuple[subprocess.Popen[bytes], dict[str, Any]]:
    """Start a case-owned verifier and wait for its health route."""
    with log.open("wb") as handle:
        process = subprocess.Popen(
            [str(ctx.binary), "--config", str(config)],
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    ctx.owned.append(process)
    url = f"http://127.0.0.1:{port}/health"
    limit = time.monotonic() + deadline
    observation: dict[str, Any] = {"status": 0, "payload": b""}
    while time.monotonic() < limit:
        if process.poll() is not None:
            break
        try:
            observation = http_get(url, timeout=5)
        except urllib.error.URLError:
            time.sleep(0.2)
            continue
        if observation["status"] == 200:
            break
        time.sleep(0.2)
    return process, {
        "config": str(config),
        "port": port,
        "health_status": observation["status"],
        "health_body": observation["payload"].decode(errors="replace")[:200],
        "log": str(log),
    }


def stop_instance(process: subprocess.Popen[bytes], ctx: Context | None = None) -> int:
    """Stop a verifier this harness started and report its exit status."""
    if process.poll() is None:
        process.terminate()
    try:
        code = int(process.wait(timeout=20))
    except subprocess.TimeoutExpired:
        process.kill()
        code = int(process.wait(timeout=10))
    if ctx is not None and process in ctx.owned:
        ctx.owned.remove(process)
    return code


def atomic_config(path: pathlib.Path, text: str) -> str:
    """Replace a configuration file in one step and return its digest.

    A running process must never be able to read half of an update, so the new
    text is written beside the target and renamed over it.
    """
    temporary = path.with_name(path.name + ".incoming")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
    return hashlib.sha256(text.encode()).hexdigest()


def config_text(
    port: int,
    cache: pathlib.Path,
    *,
    insecure: bool = False,
    root_ca: str = "",
    timeout_secs: int = 2,
) -> str:
    """Render a verifier configuration without writing it."""
    lines = [
        'address = "127.0.0.1"',
        f"port = {port}",
        f'image_cache_dir = "{cache}"',
        'image_download_url = "http://127.0.0.1:1/mr_{OS_IMAGE_HASH}.tar.gz"',
        f"image_download_timeout_secs = {timeout_secs}",
        "[attestation]",
        f"insecure_allow_external_trust_anchors = {str(insecure).lower()}",
    ]
    if root_ca:
        lines += ["[attestation.root_ca]", f'tdx = "{root_ca}"']
    return "\n".join(lines) + "\n"


def start_failure(
    ctx: Context, config: pathlib.Path, timeout: int = 60
) -> dict[str, Any]:
    """Run a verifier configuration expected to fail at startup."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(ctx.binary), "--config", str(config)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # A configuration that should have been rejected instead kept the
        # process alive; report that rather than failing on the timeout.
        return {
            "config": config.name,
            "returncode": 0,
            "elapsed_s": round(time.monotonic() - started, 3),
            "stderr_tail": "configuration was accepted and the process kept running",
            "stdout_tail": "",
        }
    return {
        "config": config.name,
        "returncode": completed.returncode,
        "elapsed_s": round(time.monotonic() - started, 3),
        "stderr_tail": completed.stderr[-400:],
        "stdout_tail": completed.stdout[-200:],
    }


# --------------------------------------------------------------------------
# Scenario: measurement computation determinism (tc-ver-image-meas-002)
# --------------------------------------------------------------------------


def meas002_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Record listener health and the empty measurement-cache baseline."""
    ctx.load_corpus()
    health = http_get(health_url(ctx))
    require(health["status"] == 200, f"verifier health returned {health['status']}")
    cache = pathlib.Path(str(ctx.substrate["data_dir"])) / "image-cache"
    baseline = cache_state(cache)
    evidence = {
        "verify_url": verify_url(ctx),
        "health": {"status": health["status"], "body": health["payload"].decode()},
        "config": str(ctx.verifier.get("config", "")),
        "image_cache_dir": str(cache),
        "image_cache_state": baseline,
        "corpus_sha256": ctx.corpus_source_sha,
    }
    require(
        not [name for name in baseline["files"] if ctx.case_id in name],
        "baseline already contained a run-scoped measurement-cache object",
    )
    return (
        "The lease-owned verifier was healthy on its configured listener and the "
        "measurement cache held no run-scoped object before the case ran.",
        evidence,
    )


def meas002_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Repeat identical measurement input and change the measured source."""
    url = verify_url(ctx)
    first = http_post(url, ctx.payload("tdx-lite-attestation.json"))
    second = http_post(url, ctx.payload("tdx-lite-attestation.json"))
    encoded = http_post(url, ctx.payload("tdx-lite-getquote.json"))
    changed = http_post(url, ctx.payload("sev-snp-attestation.json"))
    for label, response in (
        ("first", first),
        ("repeat", second),
        ("re-encoded", encoded),
        ("changed", changed),
    ):
        require(
            response["status"] == 200,
            f"{label} measurement request returned HTTP {response['status']}",
        )
    require(
        first["payload"] == second["payload"],
        "identical measurement input produced a different response body",
    )
    base = projection(result_json(first))
    same_input_other_encoding = projection(result_json(encoded))
    require(
        base == same_input_other_encoding,
        "the same evidence submitted through the quote/event-log encoding produced different registers",
    )
    other = projection(result_json(changed))
    require(
        base["is_valid"] is True and other["is_valid"] is True,
        "a committed fixture stopped verifying",
    )
    differing = sorted(field for field in APP_FIELDS if base[field] != other[field])
    require(
        set(differing) == set(APP_FIELDS),
        f"changing the measured evidence left registers unchanged: {sorted(set(APP_FIELDS) - set(differing))}",
    )
    require(
        base["tee_variant"] != other["tee_variant"],
        "the result did not report the platform source of the changed measurement",
    )
    evidence = {
        "identical_input": {
            "first_sha256": digest(first["payload"]),
            "repeat_sha256": digest(second["payload"]),
            "byte_identical": first["payload"] == second["payload"],
            "registers": base,
        },
        "same_evidence_other_encoding": {
            "input": "tdx-lite-getquote.json",
            "registers_equal": base == same_input_other_encoding,
        },
        "changed_input": {
            "input": "sev-snp-attestation.json",
            "registers": other,
            "changed_registers": differing,
            "reported_source": {
                "from": base["tee_variant"],
                "to": other["tee_variant"],
            },
        },
    }
    return (
        "Identical evidence reproduced every measured register byte for byte, the same "
        "evidence in the quote/event-log encoding produced the identical projection, and "
        "changed evidence changed every measured register while reporting its platform source.",
        evidence,
    )


def meas002_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Re-query determinism, reject invalid input, and confirm health."""
    url = verify_url(ctx)
    repeat = http_post(url, ctx.payload("tdx-lite-attestation.json"))
    require(
        repeat["status"] == 200,
        f"third identical request returned HTTP {repeat['status']}",
    )
    non_hex = http_post(url, b'{"attestation": "zzzz"}')
    empty = http_post(url, b"{}")
    require(
        non_hex["status"] == 422,
        f"non-hex attestation returned HTTP {non_hex['status']}",
    )
    require(empty["status"] == 200, f"empty request returned HTTP {empty['status']}")
    empty_document = result_json(empty)
    require(
        empty_document["is_valid"] is False, "an empty request produced a valid verdict"
    )
    require(empty_document["reason"], "an empty request produced no diagnostic")
    health = http_get(health_url(ctx))
    require(health["status"] == 200, "verifier health was lost after invalid input")
    log_text = pathlib.Path(str(ctx.verifier["log"])).read_text(errors="replace")
    require(no_secret(log_text), "the verifier log contained private key material")
    evidence = {
        "third_repeat_sha256": digest(repeat["payload"]),
        "invalid_inputs": {
            "non_hex_attestation": non_hex["status"],
            "empty_request": {
                "status": empty["status"],
                "is_valid": empty_document["is_valid"],
                "reason": empty_document["reason"],
            },
        },
        "health_after": health["status"],
        "log_secret_free": True,
        "log_bytes": len(log_text),
    }
    return (
        "A third identical request reproduced the same body, invalid input was rejected with "
        "a specific diagnostic and no secret disclosure, and the listener stayed available.",
        evidence,
    )


# --------------------------------------------------------------------------
# Scenario: concurrent API isolation (tc-ver-tools-004)
# --------------------------------------------------------------------------


def tools004_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Record the listener, configuration, and sequential per-input baseline."""
    ctx.load_corpus()
    health = http_get(health_url(ctx))
    require(health["status"] == 200, f"verifier health returned {health['status']}")
    config = pathlib.Path(str(ctx.verifier["config"]))
    require(config.is_file(), "the lease-owned verifier configuration is absent")
    url = verify_url(ctx)
    baseline = {}
    for name in OFFLINE_VALID:
        response = http_post(url, ctx.payload(name))
        require(
            response["status"] == 200,
            f"{name} baseline returned HTTP {response['status']}",
        )
        baseline[name] = digest(response["payload"])
    ctx.baseline = baseline  # type: ignore[attr-defined]
    evidence = {
        "health": {"status": health["status"], "body": health["payload"].decode()},
        "config": str(config),
        "config_sha256": sha256_file(config),
        "sequential_baseline_sha256": baseline,
        "listener": verify_url(ctx),
    }
    return (
        "The lease-owned verifier was healthy with its recorded configuration and each "
        "committed input produced a recorded sequential baseline response.",
        evidence,
    )


def tools004_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Drive mixed inputs concurrently and require request-scoped results."""
    url = verify_url(ctx)
    tampered_hex = flip_hex(ctx.attestation("tdx-lite-attestation.json"), 100)
    inputs: dict[str, bytes] = {name: ctx.payload(name) for name in OFFLINE_VALID}
    inputs["tampered"] = json.dumps({"attestation": tampered_hex}).encode()
    inputs["boundary_empty"] = b"{}"
    sequential = {
        name: digest(http_post(url, body)["payload"]) for name, body in inputs.items()
    }
    order = list(inputs) * 3
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(order)) as pool:
        observed = list(
            pool.map(lambda name: (name, http_post(url, inputs[name])), order)
        )
    elapsed = round(time.monotonic() - started, 3)
    seen: dict[str, set[str]] = {}
    for name, response in observed:
        require(
            response["status"] == 200,
            f"concurrent {name} returned HTTP {response['status']}",
        )
        seen.setdefault(name, set()).add(digest(response["payload"]))
    for name, digests in seen.items():
        require(
            len(digests) == 1,
            f"concurrent responses for {name} disagreed with each other",
        )
        require(
            digests == {sequential[name]},
            f"a concurrent {name} response did not match the same request run alone",
        )
    evidence = {
        "concurrency": len(order),
        "distinct_inputs": sorted(inputs),
        "elapsed_s": elapsed,
        "sequential_sha256": sequential,
        "concurrent_sha256": {name: sorted(values) for name, values in seen.items()},
        "cross_request_leak": False,
    }
    return (
        "Fifteen concurrent requests over five distinct inputs, mixing valid platforms with a "
        "tampered and a boundary input, each returned exactly the response that input produces "
        "alone: no task observed another request's input or policy.",
        evidence,
    )


def tools004_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Fail closed on invalid input and on the configured image dependency."""
    url = verify_url(ctx)
    invalid = http_post(url, b'{"attestation": "zzzz"}')
    require(
        invalid["status"] == 422, f"invalid input returned HTTP {invalid['status']}"
    )
    outage = http_post(url, ctx.payload("quote-report.json"))
    require(
        outage["status"] == 200,
        f"image-dependent input returned HTTP {outage['status']}",
    )
    outage_document = result_json(outage)
    require(
        outage_document["is_valid"] is False,
        "an unreachable image server still produced a valid verdict",
    )
    reason = str(outage_document["reason"])
    require(
        "image" in reason.lower(),
        f"the failure did not identify the image dependency: {reason[:120]}",
    )
    require(no_secret(reason), "the diagnostic disclosed private material")
    require(
        outage["elapsed_s"] < 60,
        f"the image dependency failure was not bounded: {outage['elapsed_s']}s",
    )
    recovered = http_post(url, ctx.payload("tdx-lite-attestation.json"))
    require(recovered["status"] == 200, "the valid control did not recover")
    require(
        digest(recovered["payload"]) == ctx.baseline["tdx-lite-attestation.json"],  # type: ignore[attr-defined]
        "the valid control changed after the failure paths ran",
    )
    evidence = {
        "invalid_input_status": invalid["status"],
        "image_dependency": {
            "status": outage["status"],
            "is_valid": outage_document["is_valid"],
            "elapsed_s": outage["elapsed_s"],
            "reason_excerpt": reason[:200],
            "secret_free": True,
        },
        "valid_control_after_recovery_sha256": digest(recovered["payload"]),
    }
    return (
        "Invalid input was rejected and the unreachable image dependency failed closed within "
        "its configured bound with an actionable, redacted diagnostic; the valid control then "
        "reproduced its baseline exactly once.",
        evidence,
    )


def tools004_step04(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Prove no request-crossing state survives in the process or on disk."""
    url = verify_url(ctx)
    persisted = {
        name: digest(http_post(url, ctx.payload(name))["payload"])
        for name in OFFLINE_VALID
    }
    require(
        persisted == ctx.baseline,  # type: ignore[attr-defined]
        "an input's result changed after the concurrent and failure phases",
    )
    # A second, case-owned instance started from the same configuration must
    # agree with the loaded one: a result that depended on accumulated process
    # state would diverge here.
    config = write_config(
        ctx.workdir / "isolation.toml",
        ctx.port("aux1"),
        ctx.workdir / "isolation-cache",
    )
    process, observation = start_instance(
        ctx, config, ctx.port("aux1"), ctx.workdir / "isolation.log"
    )
    try:
        require(
            observation["health_status"] == 200,
            "the case-owned verifier instance did not become healthy",
        )
        fresh_url = f"http://127.0.0.1:{ctx.port('aux1')}/verify"
        fresh = {
            name: digest(http_post(fresh_url, ctx.payload(name))["payload"])
            for name in OFFLINE_VALID
        }
    finally:
        exit_code = stop_instance(process, ctx)
    require(
        fresh == persisted,
        "a freshly started verifier disagreed with the long-running one: results carry process state",
    )
    require(
        port_is_free(ctx.loopback, ctx.port("aux1")),
        "the case-owned instance left a listener behind",
    )
    log_text = pathlib.Path(str(ctx.verifier["log"])).read_text(errors="replace")
    require(no_secret(log_text), "the verifier log contained private key material")
    evidence = {
        "persisted_sha256": persisted,
        "fresh_instance": {
            **observation,
            "exit_after_stop": exit_code,
            "sha256": fresh,
        },
        "listener_released": True,
        "log_secret_free": True,
    }
    return (
        "Every input reproduced its baseline after the concurrent and failure phases, a freshly "
        "started case-owned instance produced identical results, and stopping it released the "
        "listener without leaving credentials in any log.",
        evidence,
    )


# --------------------------------------------------------------------------
# Scenario: denial-of-service input limits (tc-ver-tools-006)
# --------------------------------------------------------------------------


def tools006_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Record health, the effective request limits, and the disk baseline."""
    ctx.load_corpus()
    health = http_get(health_url(ctx))
    require(health["status"] == 200, f"verifier health returned {health['status']}")
    log_text = pathlib.Path(str(ctx.verifier["log"])).read_text(errors="replace")
    limits = ""
    for line in log_text.splitlines():
        if "limits=" in line:
            limits = line.split("limits=", 1)[1][:200]
            break
    require(limits, "the verifier did not record its effective request limits")
    cache = pathlib.Path(str(ctx.substrate["data_dir"])) / "image-cache"
    baseline = cache_state(cache)
    control = http_post(verify_url(ctx), ctx.payload("tdx-lite-attestation.json"))
    require(control["status"] == 200, "the valid control was not available at baseline")
    ctx.control_digest = digest(control["payload"])  # type: ignore[attr-defined]
    evidence = {
        "health": {"status": health["status"], "body": health["payload"].decode()},
        "effective_limits": limits,
        "image_cache_state": baseline,
        "control_sha256": ctx.control_digest,  # type: ignore[attr-defined]
        "log_secret_free": no_secret(log_text),
    }
    ctx.cache_baseline = baseline  # type: ignore[attr-defined]
    require(
        evidence["log_secret_free"], "the baseline log contained private key material"
    )
    return (
        "The listener was healthy, its effective request limits were recorded from the component's "
        "own configuration log, the measurement cache baseline was captured, and the fixture-backed "
        "valid control succeeded.",
        evidence,
    )


def tools006_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Submit hostile-shaped inputs concurrently with a valid control."""
    url = verify_url(ctx)
    events = json.dumps(
        [
            {
                "imr": 3,
                "event_type": 134217729,
                "digest": "aa" * 48,
                "event": "probe",
                "event_payload": "bb" * 32,
            }
            for _ in range(2000)
        ]
    )
    certificate = (
        "-----BEGIN CERTIFICATE-----\n"
        + ("A" * 64 + "\n") * 40
        + "-----END CERTIFICATE-----\n"
    )
    probes: dict[str, tuple[bytes, dict[str, str]]] = {
        "oversized_2mib": (
            json.dumps({"attestation": "00" * (1024 * 1024)}).encode(),
            {},
        ),
        "oversized_8mib": (
            json.dumps({"attestation": "00" * (4 * 1024 * 1024)}).encode(),
            {},
        ),
        "deeply_nested": (b'{"attestation":' + b"[" * 500 + b"]" * 500 + b"}", {}),
        "compressed_body": (
            b"\x1f\x8b\x08\x00" + b"\x00" * 64,
            {"Content-Encoding": "gzip"},
        ),
        "event_heavy": (
            json.dumps({"quote": "00" * 64, "event_log": events}).encode(),
            {},
        ),
        "certificate_heavy": (
            json.dumps(
                {"quote": "00" * 64, "event_log": "[]", "vm_config": certificate * 300}
            ).encode(),
            {},
        ),
        "near_limit": (json.dumps({"attestation": "00" * 450000}).encode(), {}),
        "slow_image_evidence": (ctx.payload("quote-report.json"), {}),
        "valid_control": (ctx.payload("tdx-lite-attestation.json"), {}),
    }
    order = list(probes) * 2
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(order)) as pool:
        observed = list(
            pool.map(
                lambda name: (name, http_post(url, probes[name][0], probes[name][1])),
                order,
            )
        )
    elapsed = round(time.monotonic() - started, 3)
    rows: dict[str, dict[str, Any]] = {}
    for name, response in observed:
        row = rows.setdefault(
            name,
            {
                "statuses": set(),
                "max_elapsed_s": 0.0,
                "refused_mid_body": False,
                "request_bytes": len(probes[name][0]),
            },
        )
        row["statuses"].add(response["status"])
        row["max_elapsed_s"] = max(row["max_elapsed_s"], response["elapsed_s"])
        if response["error"]:
            row["refused_mid_body"] = True
        if name == "valid_control":
            require(
                response["status"] == 200,
                f"the valid control returned HTTP {response['status']} under load",
            )
            require(
                digest(response["payload"]) == ctx.control_digest,  # type: ignore[attr-defined]
                "the valid control changed while hostile inputs were in flight",
            )
        else:
            require(
                response["status"] != 200 or result_json(response)["is_valid"] is False,
                f"hostile input {name} produced a valid verdict",
            )
    for name in ("oversized_2mib", "oversized_8mib"):
        require(
            rows[name]["statuses"].issubset({413, REFUSED}),
            f"an over-limit request was not rejected by size: {sorted(rows[name]['statuses'])}",
        )
        require(
            rows[name]["max_elapsed_s"] < 5,
            f"the over-limit rejection of {name} was not bounded",
        )
    require(
        rows["deeply_nested"]["statuses"] == {422},
        "a deeply nested request was accepted",
    )
    require(
        rows["compressed_body"]["statuses"].issubset({400, 422}),
        "an undecodable compressed body was accepted",
    )
    for name in (
        "event_heavy",
        "certificate_heavy",
        "near_limit",
        "slow_image_evidence",
    ):
        require(rows[name]["max_elapsed_s"] < 60, f"{name} was not bounded in time")
    health = http_get(health_url(ctx))
    require(
        health["status"] == 200, "health was lost while hostile inputs were in flight"
    )
    evidence = {
        "concurrency": len(order),
        "batch_elapsed_s": elapsed,
        "rows": {
            name: {
                "request_bytes": row["request_bytes"],
                "statuses": sorted(row["statuses"]),
                "refused_mid_body": row["refused_mid_body"],
                "max_elapsed_s": round(row["max_elapsed_s"], 3),
            }
            for name, row in rows.items()
        },
        "health_during": health["status"],
    }
    return (
        "Deeply nested, oversized, compressed, event-heavy, certificate-heavy, near-limit and "
        "image-dependent inputs were submitted concurrently with a valid control: each was bounded "
        "by a configured size or time limit, none produced a valid verdict, and health and the "
        "valid control remained available throughout.",
        evidence,
    )


def tools006_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Inject malformed and oversized input, then repeat the valid control."""
    url = verify_url(ctx)
    malformed = http_post(url, b"{not json")
    oversized = http_post(
        url, json.dumps({"attestation": "00" * (2 * 1024 * 1024)}).encode()
    )
    require(
        malformed["status"] == 400,
        f"malformed input returned HTTP {malformed['status']}",
    )
    require(
        oversized["status"] in (413, REFUSED),
        f"oversized input was not rejected by size: HTTP {oversized['status']}",
    )
    for label, response in (("malformed", malformed), ("oversized", oversized)):
        text = response["payload"].decode(errors="replace")
        require(no_secret(text), f"the {label} diagnostic disclosed private material")
        require(response["elapsed_s"] < 10, f"the {label} rejection was not bounded")
    control = http_post(url, ctx.payload("tdx-lite-attestation.json"))
    require(control["status"] == 200, "the fixture-backed control did not recover")
    require(
        digest(control["payload"]) == ctx.control_digest,  # type: ignore[attr-defined]
        "the fixture-backed control changed after the injected failures",
    )
    evidence = {
        "malformed": {
            "status": malformed["status"],
            "elapsed_s": malformed["elapsed_s"],
        },
        "oversized": {
            "status": oversized["status"],
            "refused_mid_body": bool(oversized["error"]),
            "elapsed_s": oversized["elapsed_s"],
        },
        "control_after_recovery_sha256": digest(control["payload"]),
        "injected_dependency_fault": "none: the baseline names no restorable case-owned dependency",
    }
    return (
        "Malformed and oversized input failed closed within bounded time with redacted diagnostics, "
        "and the fixture-backed valid control reproduced its baseline afterwards.",
        evidence,
    )


def tools006_step04(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Check that hostile input left no state and no adjacent identity moved."""
    cache = pathlib.Path(str(ctx.substrate["data_dir"])) / "image-cache"
    entries = cache_state(cache)
    baseline = ctx.cache_baseline  # type: ignore[attr-defined]
    require(
        entries["files"] == baseline["files"]
        and entries["file_bytes"] == baseline["file_bytes"],
        f"hostile input left a cached entry behind: {entries['files']}",
    )
    url = verify_url(ctx)
    adjacent = http_post(url, ctx.payload("sev-snp-attestation.json"))
    require(
        adjacent["status"] == 200, "the adjacent platform identity stopped verifying"
    )
    adjacent_document = result_json(adjacent)
    require(
        adjacent_document["is_valid"] is True,
        "the adjacent platform identity stopped verifying",
    )
    health = http_get(health_url(ctx))
    require(health["status"] == 200, "the listener did not survive the stress phase")
    log_text = pathlib.Path(str(ctx.verifier["log"])).read_text(errors="replace")
    require(no_secret(log_text), "the verifier log contained private key material")
    evidence = {
        "image_cache_state": entries,
        "cached_entries_unchanged": True,
        "scaffolding_created": sorted(
            set(entries["directories"]) - set(baseline["directories"])
        ),
        "adjacent_identity": {
            "input": "sev-snp-attestation.json",
            "is_valid": adjacent_document["is_valid"],
            "app_id": (adjacent_document["details"]["app_info"] or {}).get("app_id"),
        },
        "health_after": health["status"],
        "log_secret_free": True,
    }
    return (
        "The measurement cache held no cached entry at all after the stress phase -- only the "
        "empty scaffolding a failed download creates -- the adjacent platform identity was "
        "unchanged, the listener survived, and no credential appeared in the log.",
        evidence,
    )


# --------------------------------------------------------------------------
# Scenario: one-shot JSON verification interface (tc-ver-cli-cert-o-001)
# --------------------------------------------------------------------------


def flip_hex(value: str, index: int) -> str:
    """Return the hex string with one nibble changed."""
    replacement = "0" if value[index] != "0" else "1"
    return value[:index] + replacement + value[index + 1 :]


def oneshot_inputs(ctx: Context) -> dict[str, pathlib.Path]:
    """Materialise the one-shot input corpus in the case work area."""
    ctx.load_corpus()
    directory = ctx.workdir / "oneshot"
    directory.mkdir(exist_ok=True)
    paths: dict[str, pathlib.Path] = {}
    for name in ("tdx-lite-attestation.json", "sev-snp-attestation.json"):
        target = directory / name
        shutil.copyfile(ctx.corpus[name], target)
        paths[name] = target
    tampered = directory / "tampered.json"
    tampered.write_text(
        json.dumps(
            {"attestation": flip_hex(ctx.attestation("tdx-lite-attestation.json"), 100)}
        ),
        encoding="utf-8",
    )
    paths["tampered.json"] = tampered
    malformed = directory / "malformed.json"
    malformed.write_text("{ not json", encoding="utf-8")
    paths["malformed.json"] = malformed
    empty = directory / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    paths["empty.json"] = empty
    oversized = directory / "oversized.json"
    oversized.write_text(
        json.dumps({"attestation": "00" * (2 * 1024 * 1024)}), encoding="utf-8"
    )
    paths["oversized.json"] = oversized
    paths["missing.json"] = directory / "missing.json"
    paths["-"] = directory / "-"
    return paths


def cli001_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Confirm the prepared binary and an empty one-shot baseline."""
    require(
        ctx.binary.is_file(), f"the prepared verifier binary is absent: {ctx.binary}"
    )
    recorded = str(ctx.binary_record.get("sha256", ""))
    observed = sha256_file(ctx.binary)
    require(
        not recorded or recorded == observed,
        "the prepared verifier binary does not match the digest the run recorded",
    )
    help_run = subprocess.run(
        [str(ctx.binary), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    require(
        help_run.returncode == 0, "the prepared verifier did not report its interface"
    )
    for flag in ("--verify", "--verify-cert", "--config"):
        require(
            flag in help_run.stdout, f"the one-shot interface does not document {flag}"
        )
    ctx.inputs = oneshot_inputs(ctx)  # type: ignore[attr-defined]
    sidecars = sorted(
        path.name for path in (ctx.workdir / "oneshot").glob("*.verification.json")
    )
    require(not sidecars, "the case work area already held a verification result")
    ctx.config = write_config(  # type: ignore[attr-defined]
        ctx.workdir / "oneshot.toml", ctx.port("aux1"), ctx.workdir / "oneshot-cache"
    )
    evidence = {
        "binary": str(ctx.binary),
        "binary_sha256": observed,
        "binary_matches_run_manifest": (not recorded) or recorded == observed,
        "documented_modes": [
            flag
            for flag in ("--verify", "--verify-cert", "--config")
            if flag in help_run.stdout
        ],
        "workdir": str(ctx.workdir / "oneshot"),
        "preexisting_results": sidecars,
    }
    return (
        "The prepared candidate verifier matched the digest recorded for this run, documented its "
        "one-shot modes, and the case-owned work area held no prior verification result.",
        evidence,
    )


def cli001_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Run the one-shot matrix and separate verified, unverified, and error."""
    config = ctx.config  # type: ignore[attr-defined]
    paths = ctx.inputs  # type: ignore[attr-defined]
    rows: dict[str, dict[str, Any]] = {}
    for name in (
        "tdx-lite-attestation.json",
        "sev-snp-attestation.json",
        "tampered.json",
        "oversized.json",
        "empty.json",
        "malformed.json",
        "missing.json",
        "-",
    ):
        rows[name] = run_oneshot(
            ctx, config, paths[name], argument=name if name == "-" else None
        )
    for name, row in rows.items():
        require(
            row["returncode"] in (0, 1),
            f"{name} exited with an unexpected status {row['returncode']}",
        )
        require(not row["panicked"], f"{name} panicked instead of reporting a result")
        require(row["stdout_is_json"], f"{name} did not emit a structured result")
        require(
            no_secret(row["stderr_tail"]),
            f"{name} disclosed private material in its diagnostics",
        )
    verified = ("tdx-lite-attestation.json", "sev-snp-attestation.json")
    unverified = ("tampered.json",)
    tool_error = (
        "oversized.json",
        "empty.json",
        "malformed.json",
        "missing.json",
        "-",
    )
    for name in verified:
        require(
            rows[name]["returncode"] == 0,
            f"a committed valid fixture exited {rows[name]['returncode']}",
        )
        require(rows[name]["document"]["is_valid"] is True, f"{name} did not verify")
        require(
            rows[name]["document"]["reason"] is None,
            f"{name} reported a diagnostic for a verified result",
        )
        require(
            rows[name]["sidecar_written"],
            f"{name} did not persist its verification result",
        )
    for name in unverified:
        require(
            rows[name]["returncode"] == 1, f"{name} did not report an unverified result"
        )
        require(
            rows[name]["document"]["is_valid"] is False,
            f"{name} reported a valid verdict",
        )
        require(rows[name]["document"]["reason"], f"{name} reported no diagnostic")
    for name in unverified:
        require(
            rows[name]["sidecar_written"],
            f"{name} did not persist the verification it actually performed",
        )
    for name in tool_error:
        require(rows[name]["returncode"] == 1, f"{name} did not report a tool error")
        require(
            rows[name]["document"]["is_valid"] is False,
            f"{name} reported a valid verdict",
        )
        require(
            not rows[name]["sidecar_written"],
            f"{name} persisted a verification result although verification never ran",
        )
        require(
            "Internal error" in str(rows[name]["document"]["reason"]),
            f"{name} was not reported as a tool error: {rows[name]['document']['reason']}",
        )
    require(
        "Quote verification failed" in str(rows["tampered.json"]["document"]["reason"]),
        "a tampered quote was not attributed to quote verification",
    )
    evidence = {
        "classes": {
            "verified": list(verified),
            "unverified": list(unverified),
            "tool_error": list(tool_error),
        },
        "rows": {
            name: {
                "returncode": row["returncode"],
                "elapsed_s": row["elapsed_s"],
                "is_valid": row["document"]["is_valid"],
                "reason": row["document"]["reason"],
                "sidecar_written": row["sidecar_written"],
                "panicked": row["panicked"],
            }
            for name, row in rows.items()
        },
    }
    ctx.rows = rows  # type: ignore[attr-defined]
    return (
        "Valid, tampered, oversized, empty, malformed, missing and stdin-sentinel inputs each "
        "produced a structured result: exit 0 only for a verified fixture, exit 1 with a persisted "
        "result only when verification ran, and exit 1 with no persisted result for a tool error. No run "
        "panicked or partially succeeded.",
        evidence,
    )


def cli001_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Repeat the matrix and confirm isolation from the candidate checkout."""
    config = ctx.config  # type: ignore[attr-defined]
    paths = ctx.inputs  # type: ignore[attr-defined]
    rows = ctx.rows  # type: ignore[attr-defined]
    repeats = {
        name: run_oneshot(ctx, config, paths[name])
        for name in ("tdx-lite-attestation.json", "malformed.json", "tampered.json")
    }
    for name, row in repeats.items():
        require(
            row["returncode"] == rows[name]["returncode"],
            f"{name} changed its exit status on repeat",
        )
        require(
            row["stdout_sha256"] == rows[name]["stdout_sha256"],
            f"{name} changed its structured result on repeat",
        )
    unchanged = {name: sha256_file(ctx.fixtures_src / name) for name in CORPUS}
    require(
        unchanged == ctx.corpus_source_sha,
        "the one-shot run modified the committed fixtures in the candidate checkout",
    )
    stray = sorted(path.name for path in ctx.fixtures_src.glob(f"*{ctx.case_id}*"))
    require(
        not stray,
        f"the case wrote run-scoped files into the candidate checkout: {stray}",
    )
    evidence = {
        "repeat_rows": {
            name: {
                "returncode": row["returncode"],
                "stdout_sha256": row["stdout_sha256"],
            }
            for name, row in repeats.items()
        },
        "committed_fixtures_unchanged": True,
        "results_written_under": str(ctx.workdir / "oneshot"),
    }
    return (
        "Repeating a verified, an unverified, and a tool-error input reproduced the same exit "
        "status and the same structured output, and every result stayed inside the case-owned work "
        "area with the committed fixtures unmodified.",
        evidence,
    )


# --------------------------------------------------------------------------
# Scenario: offline fixtures regression suite (tc-ver-cli-cert-o-006)
# --------------------------------------------------------------------------

# Expected verdict of every committed fixture with no image server reachable.
OFFLINE_VERDICTS = {
    "tdx-lite-attestation.json": {
        "is_valid": True,
        "tee_variant": "dstack-tdx",
        "tcb_status": "UpToDate",
    },
    "tdx-lite-getquote.json": {
        "is_valid": True,
        "tee_variant": "dstack-tdx",
        "tcb_status": "UpToDate",
    },
    "sev-snp-attestation.json": {
        "is_valid": True,
        "tee_variant": "dstack-amd-sev-snp",
        "tcb_status": "OutOfDate",
    },
    # Full TDX: measurement requires the OS image, so an offline run must fail
    # at the image stage rather than skip the check.
    "quote-report.json": {
        "is_valid": False,
        "tee_variant": "dstack-tdx",
        "stage": "os_image_hash_verified",
    },
}


def cli006_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Confirm the committed corpus and an offline, case-owned configuration."""
    require(
        ctx.binary.is_file(), f"the prepared verifier binary is absent: {ctx.binary}"
    )
    ctx.load_corpus()
    ctx.config = write_config(  # type: ignore[attr-defined]
        ctx.workdir / "offline.toml", ctx.port("aux1"), ctx.workdir / "offline-cache"
    )
    require(
        port_is_free("127.0.0.1", 1),
        "the offline image endpoint used by this configuration is unexpectedly reachable",
    )
    sidecars = sorted(
        path.name for path in (ctx.workdir / "fixtures").glob("*.verification.json")
    )
    require(not sidecars, "the case work area already held a verification result")
    evidence = {
        "fixtures_source": str(ctx.fixtures_src),
        "committed_fixtures": sorted(ctx.corpus_source_sha),
        "committed_sha256": ctx.corpus_source_sha,
        "config": str(ctx.config),  # type: ignore[attr-defined]
        "image_download_reachable": False,
        "preexisting_results": sidecars,
    }
    return (
        "Every committed TDX-lite, full-TDX and SEV-SNP fixture was present and copied into the "
        "case-owned work area, the configuration pointed the image download at an unreachable "
        "endpoint, and no prior verification result existed.",
        evidence,
    )


def cli006_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Verify every committed fixture and a staged one-field mutation corpus."""
    config = ctx.config  # type: ignore[attr-defined]
    known: dict[str, dict[str, Any]] = {}
    for name, expected in OFFLINE_VERDICTS.items():
        row = run_oneshot(ctx, config, ctx.corpus[name])
        document = row["document"]
        require(document is not None, f"{name} produced no structured result")
        details = document["details"]
        require(
            document["is_valid"] is expected["is_valid"],
            f"{name} changed verdict: expected is_valid={expected['is_valid']}",
        )
        require(
            details["tee_variant"] == expected["tee_variant"],
            f"{name} was decoded as {details['tee_variant']}, not {expected['tee_variant']}",
        )
        if expected["is_valid"]:
            require(
                details["tcb_status"] == expected["tcb_status"],
                f"{name} changed TCB status",
            )
            require(
                row["returncode"] == 0,
                f"{name} exited {row['returncode']} for a verified fixture",
            )
        else:
            require(
                details[expected["stage"]] is False,
                f"{name} did not fail at {expected['stage']}",
            )
            require(
                details["quote_verified"] is True,
                f"{name} failed before its expected stage",
            )
        known[name] = {
            "returncode": row["returncode"],
            "is_valid": document["is_valid"],
            "tee_variant": details["tee_variant"],
            "tcb_status": details["tcb_status"],
            "quote_verified": details["quote_verified"],
            "event_log_verified": details["event_log_verified"],
            "os_image_hash_verified": details["os_image_hash_verified"],
            "reason_excerpt": str(document["reason"])[:160],
        }

    mutation_dir = ctx.workdir / "mutations"
    mutation_dir.mkdir(exist_ok=True)
    mutations: dict[str, dict[str, Any]] = {}
    for base in ("tdx-lite-attestation.json", "sev-snp-attestation.json"):
        blob = ctx.attestation(base)
        rows = {
            # A nibble inside the signed quote body must fail signature checks.
            "quote_body": (flip_hex(blob, 100), "quote_verified"),
            # A nibble in the trailing material the quote does not sign must
            # fail the stage after the quote itself has verified.
            "post_quote_material": (
                flip_hex(blob, len(blob) - 4),
                "event_log_verified",
            ),
            # A truncated blob cannot even be decoded.
            "truncated": (blob[: (len(blob) // 2) & ~1], "quote_verified"),
        }
        for label, (mutated, stage) in rows.items():
            path = mutation_dir / f"{base[:-5]}-{label}.json"
            path.write_text(json.dumps({"attestation": mutated}), encoding="utf-8")
            row = run_oneshot(ctx, config, path)
            document = row["document"]
            require(
                document["is_valid"] is False,
                f"{base}/{label} still verified after mutation",
            )
            require(row["returncode"] == 1, f"{base}/{label} did not report failure")
            require(
                document["details"][stage] is False,
                f"{base}/{label} did not fail at {stage}",
            )
            if stage == "event_log_verified":
                require(
                    document["details"]["quote_verified"] is True,
                    f"{base}/{label} failed before the post-quote stage it targets",
                )
            require(document["reason"], f"{base}/{label} produced no diagnostic")
            mutations[f"{base}:{label}"] = {
                "failed_stage": stage,
                "quote_verified": document["details"]["quote_verified"],
                "event_log_verified": document["details"]["event_log_verified"],
                "reason_excerpt": str(document["reason"])[:160],
            }
    ctx.known = known  # type: ignore[attr-defined]
    return (
        "Every committed fixture retained its recorded offline verdict -- TDX-lite and SEV-SNP "
        "verified, full TDX failed closed at the image stage -- and each one-field mutation failed "
        "at exactly the verification stage it targets.",
        {"known_fixtures": known, "mutations": mutations},
    )


def cli006_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Repeat the suite, reject invalid input, and prove source isolation."""
    config = ctx.config  # type: ignore[attr-defined]
    repeat: dict[str, dict[str, Any]] = {}
    for name in OFFLINE_VERDICTS:
        row = run_oneshot(ctx, config, ctx.corpus[name])
        document = row["document"]
        recorded = ctx.known[name]  # type: ignore[attr-defined]
        require(
            row["returncode"] == recorded["returncode"],
            f"{name} changed exit status on repeat",
        )
        require(
            document["is_valid"] == recorded["is_valid"],
            f"{name} changed verdict on repeat",
        )
        repeat[name] = {
            "returncode": row["returncode"],
            "is_valid": document["is_valid"],
        }
    invalid = ctx.workdir / "mutations" / "invalid.json"
    invalid.write_text(json.dumps({"attestation": "zz"}), encoding="utf-8")
    invalid_row = run_oneshot(ctx, config, invalid)
    require(invalid_row["returncode"] == 1, "invalid input was accepted")
    require(
        invalid_row["document"]["is_valid"] is False,
        "invalid input produced a valid verdict",
    )
    require(
        no_secret(invalid_row["stderr_tail"]),
        "the invalid-input diagnostic disclosed private material",
    )
    unchanged = {name: sha256_file(ctx.fixtures_src / name) for name in CORPUS}
    require(
        unchanged == ctx.corpus_source_sha,
        "the regression suite modified the committed fixtures in the candidate checkout",
    )
    evidence = {
        "repeat": repeat,
        "invalid_input": {
            "returncode": invalid_row["returncode"],
            "reason": invalid_row["document"]["reason"],
        },
        "committed_fixtures_unchanged": True,
    }
    return (
        "Rerunning the whole suite reproduced every verdict, invalid input was rejected with a "
        "redacted diagnostic, and the committed fixtures in the candidate checkout were unmodified.",
        evidence,
    )


# --------------------------------------------------------------------------
# Scenario: configuration validation and trust roots (tc-ver-cli-cert-o-005)
# --------------------------------------------------------------------------


def cli005_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Record the binary, free listeners, and a non-production trust root."""
    require(
        ctx.binary.is_file(), f"the prepared verifier binary is absent: {ctx.binary}"
    )
    ctx.load_corpus()
    require(
        shutil.which("openssl"),
        "openssl is required to mint a non-production trust root",
    )
    ports = {name: ctx.port(name) for name in ("aux1", "aux2", "aux3")}
    free = {name: port_is_free(ctx.loopback, port) for name, port in ports.items()}
    require(all(free.values()), f"a lease-reserved port was already in use: {free}")
    ca_dir = ctx.workdir / "roots"
    ca_dir.mkdir(exist_ok=True)
    key = ca_dir / "nonprod-ca.key"
    certificate = ca_dir / "nonprod-ca.pem"
    minted = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-nodes",
            "-subj",
            f"/CN=dstack-test-{ctx.case_id}",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    require(minted.returncode == 0, "failed to mint the non-production trust root")
    require(
        certificate.is_file() and key.is_file(),
        "the non-production trust root was not written",
    )
    (ca_dir / "garbage.pem").write_text("not a certificate\n", encoding="utf-8")
    ctx.roots = {  # type: ignore[attr-defined]
        "key": key,
        "certificate": certificate,
        "garbage": ca_dir / "garbage.pem",
        "absent": ca_dir / "absent.pem",
    }
    evidence = {
        "binary": str(ctx.binary),
        "reserved_ports": ports,
        "ports_free_at_baseline": free,
        "trust_root": {
            "certificate": str(certificate),
            "sha256": sha256_file(certificate),
            "private_key_retained": False,
        },
        "default_config_template": str(
            ctx.repository / "dstack/verifier/dstack-verifier.toml"
        ),
    }
    return (
        "The prepared verifier was available, every lease-reserved listener this case uses was free, "
        "and a non-production trust root was minted inside the case work area with its private key "
        "recorded only by presence.",
        evidence,
    )


def cli005_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Start valid configurations and require unsafe ones to fail closed."""
    roots = ctx.roots  # type: ignore[attr-defined]
    key_text = pathlib.Path(roots["key"]).read_text()
    secret_body = key_text.splitlines()[1][:40]

    default_config = write_config(
        ctx.workdir / "valid-default.toml",
        ctx.port("aux1"),
        ctx.workdir / "cache-default",
    )
    custom_config = write_config(
        ctx.workdir / "valid-custom-roots.toml",
        ctx.port("aux2"),
        ctx.workdir / "cache-custom",
        insecure=True,
        root_ca=str(roots["certificate"]),
    )
    starts: dict[str, dict[str, Any]] = {}
    verdicts: dict[str, dict[str, Any]] = {}
    for label, config, port in (
        ("valid-default", default_config, ctx.port("aux1")),
        ("valid-custom-roots", custom_config, ctx.port("aux2")),
    ):
        log = ctx.workdir / f"{label}.log"
        process, observation = start_instance(ctx, config, port, log)
        try:
            require(
                observation["health_status"] == 200, f"{label} did not become healthy"
            )
            url = f"http://127.0.0.1:{port}/verify"
            verdicts[label] = {
                name: projection(result_json(http_post(url, ctx.payload(name))))
                for name in ("tdx-lite-attestation.json", "sev-snp-attestation.json")
            }
        finally:
            observation["exit_after_stop"] = stop_instance(process, ctx)
        observation["log_secret_free"] = no_secret(
            log.read_text(errors="replace"), (secret_body,)
        )
        require(
            observation["log_secret_free"],
            f"{label} disclosed private key material in its log",
        )
        starts[label] = observation

    # The default trust roots verify the committed Intel-signed evidence; a
    # configuration that replaces the TDX root must stop verifying it while
    # leaving the unrelated AMD platform alone. Anything else would mean the
    # setting did not take effect, or took effect too broadly.
    require(
        verdicts["valid-default"]["tdx-lite-attestation.json"]["is_valid"] is True,
        "the default trust roots stopped verifying committed TDX evidence",
    )
    require(
        verdicts["valid-custom-roots"]["tdx-lite-attestation.json"]["is_valid"]
        is False,
        "a replaced TDX trust root did not take effect",
    )
    require(
        verdicts["valid-custom-roots"]["sev-snp-attestation.json"]["is_valid"] is True,
        "replacing the TDX trust root changed an unrelated platform's verdict",
    )

    failures: dict[str, dict[str, Any]] = {}
    expectations = {
        "unsafe-conflict": (
            write_config(
                ctx.workdir / "unsafe-conflict.toml",
                ctx.port("aux3"),
                ctx.workdir / "cache-conflict",
                insecure=False,
                root_ca=str(roots["certificate"]),
            ),
            "insecure_allow_external_trust_anchors",
        ),
        "missing-root": (
            write_config(
                ctx.workdir / "missing-root.toml",
                ctx.port("aux3"),
                ctx.workdir / "cache-missing",
                insecure=True,
                root_ca=str(roots["absent"]),
            ),
            "No such file or directory",
        ),
        "invalid-root": (
            write_config(
                ctx.workdir / "invalid-root.toml",
                ctx.port("aux3"),
                ctx.workdir / "cache-invalid",
                insecure=True,
                root_ca=str(roots["garbage"]),
            ),
            "parse TDX root CA",
        ),
    }
    for label, (config, marker) in expectations.items():
        observation = start_failure(ctx, config)
        require(
            observation["returncode"] != 0, f"{label} started instead of failing closed"
        )
        require(
            marker in observation["stderr_tail"],
            f"{label} did not name its cause: {observation['stderr_tail'][:120]}",
        )
        require(
            no_secret(observation["stderr_tail"], (secret_body,)),
            f"{label} disclosed private key material",
        )
        require(
            port_is_free(ctx.loopback, ctx.port("aux3")),
            f"{label} bound its listener before failing configuration validation",
        )
        failures[label] = observation
    ctx.valid_default = default_config  # type: ignore[attr-defined]
    evidence = {
        "valid_starts": starts,
        "trust_root_effect": verdicts,
        "expected_startup_failures": failures,
    }
    return (
        "Default and custom trust-root configurations both started and served health; the replaced "
        "TDX root changed only the TDX verdict and left SEV-SNP untouched; and the unsafe "
        "anchor conflict, the missing root, and the unparsable root each failed at startup with a "
        "specific redacted diagnostic and no listener bound.",
        evidence,
    )


def cli005_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Recover on the previous valid configuration and clean the work area."""
    config = ctx.valid_default  # type: ignore[attr-defined]
    log = ctx.workdir / "recovery.log"
    process, observation = start_instance(ctx, config, ctx.port("aux1"), log)
    try:
        require(
            observation["health_status"] == 200,
            "the verifier did not recover on a valid configuration",
        )
        url = f"http://127.0.0.1:{ctx.port('aux1')}/verify"
        first = http_post(url, ctx.payload("tdx-lite-attestation.json"))
        second = http_post(url, ctx.payload("tdx-lite-attestation.json"))
        require(
            first["status"] == 200 and first["payload"] == second["payload"],
            "the recovered instance was not deterministic",
        )
        invalid = http_post(url, b'{"attestation": "zzzz"}')
        require(
            invalid["status"] == 422,
            f"the recovered instance accepted invalid input: HTTP {invalid['status']}",
        )
    finally:
        observation["exit_after_stop"] = stop_instance(process, ctx)
    require(
        port_is_free(ctx.loopback, ctx.port("aux1")),
        "the recovered instance left a listener behind",
    )
    key = pathlib.Path(ctx.roots["key"])  # type: ignore[attr-defined]
    key.unlink(missing_ok=True)
    evidence = {
        "recovery": observation,
        "deterministic_repeat": True,
        "invalid_input_status": invalid["status"],
        "listener_released": True,
        "private_key_removed": not key.exists(),
    }
    return (
        "Restoring the previous valid configuration recovered the service, repeated valid requests "
        "were byte-identical, invalid input was still rejected, the listener was released, and the "
        "non-production private key was removed from the work area.",
        evidence,
    )


# --------------------------------------------------------------------------
# Scenario: collateral and trust-root update lifecycle (tc-ver-tools-005)
# --------------------------------------------------------------------------


def lifecycle_verdicts(port: int, ctx: Context) -> dict[str, bool]:
    """Return the verdict each committed platform fixture gets on a port."""
    url = f"http://127.0.0.1:{port}/verify"
    return {
        name: bool(result_json(http_post(url, ctx.payload(name)))["is_valid"])
        for name in ("tdx-lite-attestation.json", "sev-snp-attestation.json")
    }


def replace_under_load(
    ctx: Context, port: int, path: pathlib.Path, text: str, requests: int = 24
) -> dict[str, Any]:
    """Replace the configuration while requests are in flight on the listener.

    The point of the row is that a running process holds one complete
    configuration: every request issued across the replacement must return the
    behaviour the process started with, never a mixture.
    """
    url = f"http://127.0.0.1:{port}/verify"
    body = ctx.payload("tdx-lite-attestation.json")
    replaced: dict[str, Any] = {}

    def swap() -> None:
        time.sleep(0.15)
        replaced["sha256"] = atomic_config(path, text)
        replaced["at"] = round(time.monotonic(), 3)

    with ThreadPoolExecutor(max_workers=requests + 1) as pool:
        swapper = pool.submit(swap)
        responses = list(pool.map(lambda _: http_post(url, body), range(requests)))
        swapper.result()
    statuses = sorted({response["status"] for response in responses})
    digests = sorted({digest(response["payload"]) for response in responses})
    return {
        "requests": requests,
        "statuses": statuses,
        "distinct_bodies": digests,
        "replacement_sha256": replaced.get("sha256", ""),
    }


def tools005_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Record the binary, free listener, and the starting configuration."""
    require(
        ctx.binary.is_file(), f"the prepared verifier binary is absent: {ctx.binary}"
    )
    ctx.load_corpus()
    require(
        shutil.which("openssl"),
        "openssl is required to mint a non-production trust root",
    )
    port = ctx.port("aux1")
    require(
        port_is_free(ctx.loopback, port),
        "the lease-reserved listener was already in use",
    )
    roots = ctx.workdir / "roots"
    roots.mkdir(exist_ok=True)
    key = roots / "nonprod-ca.key"
    certificate = roots / "nonprod-ca.pem"
    minted = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-nodes",
            "-subj",
            f"/CN=dstack-test-{ctx.case_id}",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    require(minted.returncode == 0, "failed to mint the non-production trust root")
    (roots / "garbage.pem").write_text("not a certificate\n", encoding="utf-8")
    ctx.roots = {
        "key": key,
        "certificate": certificate,
        "garbage": roots / "garbage.pem",
    }  # type: ignore[attr-defined]
    cache = ctx.workdir / "lifecycle-cache"
    cache.mkdir(exist_ok=True)
    ctx.config_path = ctx.workdir / "lifecycle.toml"  # type: ignore[attr-defined]
    ctx.config_a = config_text(port, cache)  # type: ignore[attr-defined]
    ctx.config_b = config_text(port, cache, insecure=True, root_ca=str(certificate))  # type: ignore[attr-defined]
    ctx.config_invalid = config_text(
        port, cache, insecure=True, root_ca=str(roots / "garbage.pem")
    )  # type: ignore[attr-defined]
    sha_a = atomic_config(ctx.config_path, ctx.config_a)  # type: ignore[attr-defined]
    ctx.sha_a = sha_a  # type: ignore[attr-defined]
    process, observation = start_instance(
        ctx, ctx.config_path, port, ctx.workdir / "lifecycle-a.log"
    )  # type: ignore[attr-defined]
    require(
        observation["health_status"] == 200,
        "the case-owned verifier did not start on the original configuration",
    )
    baseline = lifecycle_verdicts(port, ctx)
    require(
        baseline["tdx-lite-attestation.json"] is True,
        "committed TDX evidence did not verify at baseline",
    )
    require(
        baseline["sev-snp-attestation.json"] is True,
        "committed SEV-SNP evidence did not verify at baseline",
    )
    ctx.instance = process  # type: ignore[attr-defined]
    ctx.baseline_verdicts = baseline  # type: ignore[attr-defined]
    evidence = {
        "binary": str(ctx.binary),
        "listener": observation,
        "config_path": str(ctx.config_path),  # type: ignore[attr-defined]
        "config_sha256": sha_a,
        "baseline_verdicts": baseline,
        "trust_root": {"certificate": str(certificate), "private_key_retained": False},
    }
    return (
        "The prepared verifier started from a complete original configuration on a free "
        "lease-reserved listener, served health, and both committed platform fixtures verified.",
        evidence,
    )


def tools005_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Replace, restart, verify, restore, and restart the configuration."""
    port = ctx.port("aux1")
    path = ctx.config_path  # type: ignore[attr-defined]
    url = f"http://127.0.0.1:{port}/verify"
    original_body = digest(
        http_post(url, ctx.payload("tdx-lite-attestation.json"))["payload"]
    )

    during_replace = replace_under_load(ctx, port, path, ctx.config_b)  # type: ignore[attr-defined]
    require(
        during_replace["statuses"] == [200],
        "a request failed while the configuration was replaced",
    )
    require(
        during_replace["distinct_bodies"] == [original_body],
        "a running process observed a configuration change it had not restarted for",
    )
    exit_original = stop_instance(ctx.instance, ctx)  # type: ignore[attr-defined]
    require(
        port_is_free(ctx.loopback, port),
        "the original instance kept its listener after stopping",
    )

    updated, updated_observation = start_instance(
        ctx, path, port, ctx.workdir / "lifecycle-b.log"
    )
    ctx.instance = updated  # type: ignore[attr-defined]
    require(
        updated_observation["health_status"] == 200,
        "the replaced configuration did not start",
    )
    updated_verdicts = lifecycle_verdicts(port, ctx)
    require(
        updated_verdicts["tdx-lite-attestation.json"] is False,
        "the replaced TDX trust root did not take effect after restart",
    )
    require(
        updated_verdicts["sev-snp-attestation.json"] is True,
        "replacing the TDX trust root changed an unrelated platform's verdict",
    )
    updated_body = digest(
        http_post(url, ctx.payload("tdx-lite-attestation.json"))["payload"]
    )

    during_restore = replace_under_load(ctx, port, path, ctx.config_a)  # type: ignore[attr-defined]
    require(
        during_restore["statuses"] == [200],
        "a request failed while the configuration was restored",
    )
    require(
        during_restore["distinct_bodies"] == [updated_body],
        "a running process observed the restored configuration without restarting",
    )
    exit_updated = stop_instance(ctx.instance, ctx)  # type: ignore[attr-defined]
    restored, restored_observation = start_instance(
        ctx, path, port, ctx.workdir / "lifecycle-c.log"
    )
    ctx.instance = restored  # type: ignore[attr-defined]
    require(
        restored_observation["health_status"] == 200,
        "the restored configuration did not start",
    )
    restored_verdicts = lifecycle_verdicts(port, ctx)
    require(
        restored_verdicts == ctx.baseline_verdicts,  # type: ignore[attr-defined]
        "restoring the previous complete configuration did not recover the original behaviour",
    )
    evidence = {
        "concurrent_during_replacement": during_replace,
        "concurrent_during_restore": during_restore,
        "original_exit": exit_original,
        "updated_exit": exit_updated,
        "updated_verdicts": updated_verdicts,
        "restored_verdicts": restored_verdicts,
        "config_sha256_after_restore": sha256_file(path),
    }
    return (
        "Requests in flight across an atomic configuration replacement all returned the behaviour "
        "their process started with, the replaced TDX trust root took effect only after a bounded "
        "restart and left SEV-SNP untouched, and restoring the previous complete configuration "
        "recovered the original verdicts.",
        evidence,
    )


def tools005_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Fail closed on an invalid configuration and on an interrupted restart."""
    port = ctx.port("aux1")
    path = ctx.config_path  # type: ignore[attr-defined]
    stop_instance(ctx.instance, ctx)  # type: ignore[attr-defined]
    invalid_sha = atomic_config(path, ctx.config_invalid)  # type: ignore[attr-defined]
    failure = start_failure(ctx, path)
    require(
        failure["returncode"] != 0, "an invalid trust-root configuration started anyway"
    )
    require(
        "parse TDX root CA" in failure["stderr_tail"],
        f"the diagnostic did not name the cause: {failure['stderr_tail'][:120]}",
    )
    require(
        no_secret(failure["stderr_tail"]),
        "the startup diagnostic disclosed private material",
    )
    require(
        port_is_free(ctx.loopback, port), "an invalid configuration bound its listener"
    )
    require(
        sha256_file(path) == invalid_sha,
        "the configuration on disk was not the complete document that was written",
    )
    restored_sha = atomic_config(path, ctx.config_a)  # type: ignore[attr-defined]
    process, observation = start_instance(
        ctx, path, port, ctx.workdir / "lifecycle-recovery.log"
    )
    ctx.instance = process  # type: ignore[attr-defined]
    require(
        observation["health_status"] == 200,
        "the valid configuration did not recover service",
    )
    # An interrupted restart must not leave the listener or a stale decision
    # behind: kill without a graceful shutdown and start again.
    process.kill()
    process.wait(timeout=20)
    ctx.owned.remove(process)
    require(
        port_is_free(ctx.loopback, port), "an interrupted instance kept its listener"
    )
    process, observation = start_instance(
        ctx, path, port, ctx.workdir / "lifecycle-after-kill.log"
    )
    ctx.instance = process  # type: ignore[attr-defined]
    require(
        observation["health_status"] == 200,
        "the verifier did not recover after an interrupted restart",
    )
    verdicts = lifecycle_verdicts(port, ctx)
    require(
        verdicts == ctx.baseline_verdicts,  # type: ignore[attr-defined]
        "recovery after an interrupted restart reused a stale decision",
    )
    evidence = {
        "invalid_configuration": failure,
        "invalid_config_sha256": invalid_sha,
        "restored_config_sha256": restored_sha,
        "recovery": observation,
        "verdicts_after_recovery": verdicts,
    }
    return (
        "An invalid trust root failed closed at startup with a specific redacted diagnostic and no "
        "listener bound, the configuration on disk stayed a complete document, and both the valid "
        "restart and a restart after an abrupt kill recovered the original behaviour.",
        evidence,
    )


def tools005_step04(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Confirm the selected configuration persists and nothing else survives."""
    port = ctx.port("aux1")
    path = ctx.config_path  # type: ignore[attr-defined]
    require(
        sha256_file(path) == ctx.sha_a,  # type: ignore[attr-defined]
        "the selected configuration did not persist across the case-owned restarts",
    )
    stop_instance(ctx.instance, ctx)  # type: ignore[attr-defined]
    final, observation = start_instance(
        ctx, path, port, ctx.workdir / "lifecycle-final.log"
    )
    ctx.instance = final  # type: ignore[attr-defined]
    require(
        observation["health_status"] == 200, "the persisted configuration did not start"
    )
    verdicts = lifecycle_verdicts(port, ctx)
    require(
        verdicts == ctx.baseline_verdicts,  # type: ignore[attr-defined]
        "an adjacent platform identity changed across the configuration lifecycle",
    )
    exit_code = stop_instance(ctx.instance, ctx)  # type: ignore[attr-defined]
    require(
        port_is_free(ctx.loopback, port), "the final instance left a listener behind"
    )
    logs = sorted(ctx.workdir.glob("lifecycle-*.log"))
    for log in logs:
        require(
            no_secret(log.read_text(errors="replace")),
            f"{log.name} disclosed private key material",
        )
    key = pathlib.Path(ctx.roots["key"])  # type: ignore[attr-defined]
    key.unlink(missing_ok=True)
    evidence = {
        "persisted_config_sha256": sha256_file(path),
        "final_start": observation,
        "final_exit": exit_code,
        "verdicts": verdicts,
        "logs_checked": [log.name for log in logs],
        "listener_released": True,
        "private_key_removed": not key.exists(),
    }
    return (
        "The selected complete configuration persisted across every case-owned restart, a final "
        "instance reproduced the baseline verdicts for both platform identities, stopping it "
        "released the listener, and no log carried private key material.",
        evidence,
    )


# --------------------------------------------------------------------------
# Scenario: result schema completeness and diagnostics (tc-ver-cli-cert-o-004)
# --------------------------------------------------------------------------

# Fields every verification result carries, whatever the verdict.
RESULT_TOP_FIELDS = ("is_valid", "details", "reason")
RESULT_DETAIL_FIELDS = (
    "quote_verified",
    "event_log_verified",
    "os_image_hash_verified",
    "acpi_tables_verified",
    "os_image_is_dev",
    "os_image_version",
    "tee_variant",
    "report_data",
    "tcb_status",
    "advisory_ids",
    "key_provider",
    "app_info",
)
# The stages a verification passes through, in the order they are decided, and
# the diagnostic each one produces when it is the stage that failed.
STAGE_ORDER = ("quote_verified", "event_log_verified", "os_image_hash_verified")
STAGE_DIAGNOSTIC = {
    "quote_signature": ("quote_verified", "Quote verification failed"),
    "post_quote_material": ("event_log_verified", "OS image hash verification failed"),
    "image_download": ("event_log_verified", "Failed to download image"),
    "decode": ("quote_verified", "Failed to decode"),
    "missing_quote": ("quote_verified", "Quote is required"),
}


def schema_rows(ctx: Context) -> dict[str, pathlib.Path]:
    """Write one input per verification outcome the result schema must describe."""
    directory = ctx.workdir / "schema"
    directory.mkdir(exist_ok=True)
    blob = ctx.attestation("tdx-lite-attestation.json")
    paths = {"success": directory / "success.json"}
    shutil.copyfile(ctx.corpus["tdx-lite-attestation.json"], paths["success"])
    paths["image_download"] = directory / "image-download.json"
    shutil.copyfile(ctx.corpus["quote-report.json"], paths["image_download"])
    for label, payload in (
        ("quote_signature", {"attestation": flip_hex(blob, 100)}),
        ("post_quote_material", {"attestation": flip_hex(blob, len(blob) - 4)}),
        ("decode", {"attestation": blob[: (len(blob) // 2) & ~1]}),
        ("missing_quote", {}),
    ):
        path = directory / f"{label.replace('_', '-')}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        paths[label] = path
    return paths


def check_schema(label: str, document: dict[str, Any]) -> None:
    """Assert one result document is complete, consistent, and secret-free."""
    require(
        sorted(document) == sorted(RESULT_TOP_FIELDS),
        f"{label} result carried {sorted(document)}, not the documented top-level fields",
    )
    details = document["details"]
    missing = sorted(set(RESULT_DETAIL_FIELDS) - set(details))
    require(not missing, f"{label} result omitted {missing}")
    require(
        isinstance(details["advisory_ids"], list),
        f"{label} advisory_ids was {type(details['advisory_ids']).__name__}, not a list",
    )
    require(
        details["tcb_status"] is None or isinstance(details["tcb_status"], str),
        f"{label} tcb_status was neither a status nor absent",
    )
    require(
        no_secret(json.dumps(document)),
        f"{label} result contained private key material",
    )
    if document["is_valid"]:
        for stage in STAGE_ORDER:
            require(details[stage] is True, f"{label} was valid with {stage} false")
        require(
            document["reason"] is None, f"{label} was valid but carried a diagnostic"
        )
        require(
            isinstance(details.get("boot_info"), dict),
            f"{label} was valid without boot_info",
        )
        app = details["app_info"]
        require(isinstance(app, dict), f"{label} was valid without app_info")
        for field in APP_FIELDS:
            require(app.get(field), f"{label} was valid without {field}")
        require(details["key_provider"], f"{label} was valid without a key provider")
        require(details["report_data"], f"{label} was valid without report data")
    else:
        require(document["reason"], f"{label} failed without a diagnostic")
        require(
            "boot_info" not in details,
            f"{label} failed yet still projected boot_info",
        )
        require(
            details["app_info"] is None,
            f"{label} failed yet still projected an application identity",
        )


def cli004_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Confirm the prepared binary and stage one input per outcome."""
    require(
        ctx.binary.is_file(), f"the prepared verifier binary is absent: {ctx.binary}"
    )
    ctx.load_corpus()
    ctx.config = write_config(  # type: ignore[attr-defined]
        ctx.workdir / "schema.toml", ctx.port("aux1"), ctx.workdir / "schema-cache"
    )
    ctx.rows = schema_rows(ctx)  # type: ignore[attr-defined]
    existing = sorted(
        path.name for path in (ctx.workdir / "schema").glob("*.verification.json")
    )
    require(not existing, "the case work area already held a verification result")
    evidence = {
        "binary": str(ctx.binary),
        "documented_top_fields": list(RESULT_TOP_FIELDS),
        "documented_detail_fields": list(RESULT_DETAIL_FIELDS),
        "outcome_inputs": {label: path.name for label, path in ctx.rows.items()},  # type: ignore[attr-defined]
        "preexisting_results": existing,
    }
    return (
        "The prepared verifier was available and one input was staged for the successful outcome "
        "and for each failure stage the result schema has to describe, with no prior result in the "
        "case-owned work area.",
        evidence,
    )


def cli004_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Inspect every field of the success and per-stage failure results."""
    config = ctx.config  # type: ignore[attr-defined]
    rows: dict[str, dict[str, Any]] = {}
    observations: dict[str, dict[str, Any]] = {}
    for label, path in ctx.rows.items():  # type: ignore[attr-defined]
        row = run_oneshot(ctx, config, path)
        require(
            row["stdout_is_json"], f"{label} did not emit a machine-readable result"
        )
        require(not row["panicked"], f"{label} panicked instead of reporting a result")
        document = row["document"]
        check_schema(label, document)
        rows[label] = row
        details = document["details"]
        observations[label] = {
            "returncode": row["returncode"],
            "is_valid": document["is_valid"],
            "stage_flags": {stage: details[stage] for stage in STAGE_ORDER},
            "reason": document["reason"],
            "projects_boot_info": "boot_info" in details,
        }
    require(
        rows["success"]["returncode"] == 0, "the successful outcome did not exit zero"
    )
    for label, (stage, marker) in STAGE_DIAGNOSTIC.items():
        document = rows[label]["document"]
        details = document["details"]
        require(rows[label]["returncode"] == 1, f"{label} did not report failure")
        failed = [name for name in STAGE_ORDER if details[name] is not True]
        require(
            failed and failed[0] == stage,
            f"{label} reported {failed[:1]} as its first failed stage, not {stage}",
        )
        for name in STAGE_ORDER[: STAGE_ORDER.index(stage)]:
            require(
                details[name] is True,
                f"{label} failed at {name}, before the stage it targets",
            )
        require(
            marker in str(document["reason"]),
            f"{label} did not name its failed trust assertion: {str(document['reason'])[:120]}",
        )
    return (
        "The successful result carried every documented field including the boot-info projection, "
        "each failure carried the same field set with the identity fields absent, and every failure "
        "named the exact trust assertion that failed at the first stage whose flag was not set.",
        {"rows": observations},
    )


def cli004_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Re-run every outcome and confirm the output is stable and isolated."""
    config = ctx.config  # type: ignore[attr-defined]
    first = {
        label: run_oneshot(ctx, config, path)["stdout_sha256"]
        for label, path in ctx.rows.items()  # type: ignore[attr-defined]
    }
    second = {
        label: run_oneshot(ctx, config, path)["stdout_sha256"]
        for label, path in ctx.rows.items()  # type: ignore[attr-defined]
    }
    require(
        first == second, "the machine-readable output changed between identical runs"
    )
    invalid = ctx.workdir / "schema" / "invalid.json"
    invalid.write_text(json.dumps({"attestation": "zz"}), encoding="utf-8")
    row = run_oneshot(ctx, config, invalid)
    require(row["returncode"] == 1, "invalid input was accepted")
    check_schema("invalid", row["document"])
    require(
        no_secret(row["stderr_tail"]),
        "the invalid-input diagnostic disclosed private material",
    )
    unchanged = {name: sha256_file(ctx.fixtures_src / name) for name in CORPUS}
    require(
        unchanged == ctx.corpus_source_sha,
        "the schema inspection modified the committed fixtures in the candidate checkout",
    )
    evidence = {
        "stdout_sha256": first,
        "stable_across_repeats": True,
        "invalid_input": {
            "returncode": row["returncode"],
            "reason": row["document"]["reason"],
        },
        "committed_fixtures_unchanged": True,
    }
    return (
        "Every outcome produced byte-identical machine-readable output on a second run, a further "
        "invalid input produced the same complete schema with a redacted diagnostic, and the "
        "committed fixtures in the candidate checkout were unmodified.",
        evidence,
    )


def input001_step01(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Prepare both documented input encodings and an offline configuration."""
    require(
        ctx.binary.is_file(), f"the prepared verifier binary is absent: {ctx.binary}"
    )
    ctx.load_corpus()
    ctx.config = write_config(  # type: ignore[attr-defined]
        ctx.workdir / "precedence.toml",
        ctx.port("aux1"),
        ctx.workdir / "precedence-cache",
    )
    require(
        not list((ctx.workdir / "fixtures").glob("*.verification.json")),
        "the case work area already held verification output",
    )
    return (
        "The self-contained and raw TDX-lite encodings were copied into a clean case-owned "
        "workspace with an offline configuration and no preexisting result.",
        {
            "inputs": ["tdx-lite-attestation.json", "tdx-lite-getquote.json"],
            "source_sha256": {
                name: ctx.corpus_source_sha[name]
                for name in ("tdx-lite-attestation.json", "tdx-lite-getquote.json")
            },
            "preexisting_results": [],
        },
    )


def input001_step02(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Exercise precedence, canonicalization, and ambiguity rejection."""
    config = ctx.config  # type: ignore[attr-defined]
    base_path = ctx.corpus["tdx-lite-attestation.json"]
    base = run_oneshot(ctx, config, base_path)
    require(base["returncode"] == 0, "the self-contained control did not verify")
    require(
        base["document"]["is_valid"] is True, "the self-contained control was invalid"
    )

    source = json.loads(base_path.read_text())
    conflict = dict(source)
    conflict.update(
        {
            "quote": "00",
            "event_log": "not authenticated",
            "vm_config": "{not valid json",
        }
    )
    conflict_path = ctx.workdir / "precedence-conflict.json"
    conflict_path.write_text(json.dumps(conflict), encoding="utf-8")
    conflict_row = run_oneshot(ctx, config, conflict_path)
    require(
        conflict_row["returncode"] == 0,
        "conflicting top-level fields overrode attestation",
    )
    require(
        conflict_row["document"] == base["document"],
        "conflicting top-level fields changed the authenticated attestation result",
    )

    reordered_path = ctx.workdir / "precedence-reordered.json"
    reordered_path.write_text(
        '{\n  "vm_config": "{not valid json",\n  "attestation": '
        + json.dumps(source["attestation"])
        + ',\n  "event_log": "not authenticated",\n  "quote": "00"\n}\n',
        encoding="utf-8",
    )
    reordered = run_oneshot(ctx, config, reordered_path)
    require(reordered["document"] == base["document"], "JSON order changed the verdict")

    raw = run_oneshot(ctx, config, ctx.corpus["tdx-lite-getquote.json"])
    require(
        raw["returncode"] == 0 and raw["document"]["is_valid"] is True,
        "raw TDX-lite failed",
    )
    for field in ("tee_variant", "app_info", "boot_info", "report_data"):
        require(
            raw["document"]["details"][field] == base["document"]["details"][field],
            f"raw and self-contained encodings disagree on {field}",
        )

    duplicate = ctx.workdir / "duplicate-attestation.json"
    duplicate.write_text(
        '{"attestation":'
        + json.dumps(source["attestation"])
        + ',"attestation":'
        + json.dumps(source["attestation"])
        + "}",
        encoding="utf-8",
    )
    duplicate_row = run_oneshot(ctx, config, duplicate)
    require(
        duplicate_row["returncode"] == 1, "duplicate attestation keys were accepted"
    )
    require(not duplicate_row["panicked"], "duplicate input panicked")
    require(
        no_secret(duplicate_row["stderr_tail"]),
        "duplicate diagnostic disclosed a secret",
    )
    ctx.input001_base_sha = base["stdout_sha256"]  # type: ignore[attr-defined]
    return (
        "Authenticated attestation fields took precedence over conflicting top-level fields, "
        "JSON ordering did not change the result, raw and self-contained encodings projected the "
        "same identity, and duplicate attestation keys were rejected.",
        {
            "base_sha256": base["stdout_sha256"],
            "conflict_same_document": True,
            "reordered_same_document": True,
            "raw_same_identity_fields": True,
            "duplicate": {
                "returncode": duplicate_row["returncode"],
                "stdout_is_json": duplicate_row["stdout_is_json"],
                "stderr_tail": duplicate_row["stderr_tail"],
            },
        },
    )


def input001_step03(ctx: Context) -> tuple[str, dict[str, Any]]:
    """Repeat the control and reject incomplete and malformed input."""
    config = ctx.config  # type: ignore[attr-defined]
    repeat = run_oneshot(ctx, config, ctx.corpus["tdx-lite-attestation.json"])
    require(
        repeat["stdout_sha256"] == ctx.input001_base_sha,  # type: ignore[attr-defined]
        "identical self-contained input changed output",
    )
    rows = {}
    for label, payload in {
        "empty": {},
        "event-without-quote": {"event_log": "[]", "vm_config": "{}"},
        "malformed-attestation": {"attestation": "00"},
    }.items():
        path = ctx.workdir / f"{label}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        row = run_oneshot(ctx, config, path)
        require(row["returncode"] == 1, f"{label} input was accepted")
        require(not row["panicked"], f"{label} input panicked")
        require(no_secret(row["stderr_tail"]), f"{label} diagnostic disclosed a secret")
        rows[label] = {
            "returncode": row["returncode"],
            "stdout_is_json": row["stdout_is_json"],
            "stderr_tail": row["stderr_tail"],
        }
    unchanged = {name: sha256_file(ctx.fixtures_src / name) for name in CORPUS}
    require(
        unchanged == ctx.corpus_source_sha, "the candidate fixture corpus was modified"
    )
    return (
        "The control produced byte-identical output on repeat, incomplete and malformed modes "
        "failed without panic or secret disclosure, and the committed fixture corpus was unchanged.",
        {
            "repeat_stdout_sha256": repeat["stdout_sha256"],
            "invalid_rows": rows,
            "committed_fixtures_unchanged": True,
        },
    )


CASES: dict[str, dict[str, Any]] = {
    "tc-ver-input-plat-001": {
        "steps": [
            ("prereq", input001_step01),
            ("precedence-canonicalization", input001_step02),
            ("recovery-isolation", input001_step03),
        ],
        "summary": (
            "Authenticated self-contained evidence took precedence over conflicting top-level "
            "fields, canonical JSON order was deterministic, raw and self-contained encodings "
            "projected the same identity, ambiguous duplicates and incomplete modes failed closed, "
            "and repeated execution remained byte-stable and isolated."
        ),
        "remarks": (
            "Conflicting unauthenticated fields are intentionally ignored rather than allowed to "
            "influence the authenticated result; duplicate occurrences of the authoritative field "
            "are rejected by deserialization."
        ),
    },
    "tc-ver-input-plat-004": {
        "steps": [
            ("prereq", cli006_step01),
            ("measurement-mutation-matrix", cli006_step02),
            ("state-isolation", cli006_step03),
        ],
        "summary": (
            "TDX-lite measurements retained their recorded verdicts and platform labels, quote-body "
            "and post-quote mutations failed at the exact trust stage they targeted, unsupported "
            "full-TDX image verification failed closed offline, and repeats remained isolated."
        ),
        "remarks": (
            "The shared offline corpus also exercises SEV-SNP as an adjacent-platform identity; "
            "the assertions specific to this case are the two TDX-lite encodings, their mutations, "
            "and full-TDX fail-closed behavior."
        ),
    },
    "tc-ver-image-meas-002": {
        "steps": [
            ("prereq", meas002_step01),
            ("determinism", meas002_step02),
            ("state-diagnostics", meas002_step03),
        ],
        "summary": (
            "Measurement computation was deterministic: identical evidence reproduced every "
            "measured register byte for byte across encodings and repeats, changed evidence "
            "changed every register and reported its platform source, and invalid input was "
            "rejected without losing availability."
        ),
        "remarks": (
            "The measured inputs are the committed attestation fixtures, which carry authenticated "
            "kernel, initrd, cmdline and config material inside the quote; the verifier exposes no "
            "route that takes those artifacts as separate parameters."
        ),
    },
    "tc-ver-tools-004": {
        "steps": [
            ("baseline", tools004_step01),
            ("concurrent-api", tools004_step02),
            ("failure-recovery", tools004_step03),
            ("isolation-persistence", tools004_step04),
        ],
        "summary": (
            "Concurrent verification stayed request-scoped: fifteen interleaved requests over five "
            "distinct inputs each returned exactly the result that input produces alone, the image "
            "dependency failed closed within its bound, and a freshly started case-owned instance "
            "agreed with the long-running one."
        ),
        "remarks": (
            "The API is exercised through the component's HTTP surface rather than as an in-process "
            "library; cancellation is expressed as client disconnect and is not separately asserted."
        ),
    },
    "tc-ver-tools-006": {
        "steps": [
            ("baseline", tools006_step01),
            ("stress", tools006_step02),
            ("failure-recovery", tools006_step03),
            ("isolation-persistence", tools006_step04),
        ],
        "summary": (
            "Hostile input was bounded by configured limits: over-limit bodies were rejected by size "
            "in milliseconds, nested and compressed bodies were rejected before decoding, and "
            "event-heavy, certificate-heavy, near-limit and image-dependent inputs all completed "
            "within bound while health and the valid control stayed available."
        ),
        "remarks": (
            "The baseline names no restorable case-owned dependency to interrupt, so the injected "
            "faults are malformed and oversized input, as the case allows."
        ),
    },
    "tc-ver-cli-cert-o-001": {
        "steps": [
            ("prereq", cli001_step01),
            ("oneshot-matrix", cli001_step02),
            ("state-diagnostics", cli001_step03),
        ],
        "summary": (
            "The one-shot JSON interface separated its three outcomes: exit 0 with a persisted "
            "result for a verified fixture, exit 1 with a persisted result for an unverified one, "
            "and exit 1 with no persisted result for a tool error. No input panicked or partially "
            "succeeded, and repeats were identical."
        ),
        "remarks": (
            "`--verify -` is not a stdin sentinel in this release: the CLI reads it as a file name "
            "and reports a tool error, which is recorded as observed rather than as a defect."
        ),
    },
    "tc-ver-cli-cert-o-006": {
        "steps": [
            ("prereq", cli006_step01),
            ("offline-regression", cli006_step02),
            ("state-isolation", cli006_step03),
        ],
        "summary": (
            "The committed fixture corpus verified offline with its recorded verdicts, full TDX "
            "failed closed at the image stage with no image server reachable, and every one-field "
            "mutation failed at exactly the verification stage it targets."
        ),
        "remarks": (
            "Fixtures are copied into the lease work area first, because one-shot mode writes its "
            "result beside the input file; the committed copies are re-hashed afterwards to prove "
            "the candidate checkout was untouched."
        ),
    },
    "tc-ver-tools-005": {
        "steps": [
            ("baseline", tools005_step01),
            ("lifecycle", tools005_step02),
            ("failure-recovery", tools005_step03),
            ("isolation-persistence", tools005_step04),
        ],
        "summary": (
            "The trust-root update lifecycle held: every request in flight across an atomic "
            "configuration replacement returned the behaviour its process started with, the "
            "replaced TDX root took effect only after a bounded restart and left SEV-SNP "
            "untouched, an invalid root failed closed at startup without binding a listener, and "
            "restoring the previous complete configuration recovered the original verdicts."
        ),
        "remarks": (
            "The lifecycle runs against a verifier this case starts on a lease-reserved port, so "
            "the restarts stay inside the case rather than disturbing the fixture's own listener. "
            "The trust root is a run-scoped non-production CA whose private key is removed in the "
            "postcondition."
        ),
    },
    "tc-ver-cli-cert-o-004": {
        "steps": [
            ("prereq", cli004_step01),
            ("schema-matrix", cli004_step02),
            ("stability-isolation", cli004_step03),
        ],
        "summary": (
            "The verification result schema was complete and internally consistent: the successful "
            "outcome carried every documented field plus the boot-info projection, each failure "
            "carried the same field set with the identity fields absent, every failure named the "
            "exact trust assertion that failed at the first unset stage, and repeated runs were "
            "byte-identical and secret-free."
        ),
        "remarks": (
            "The RA-TLS certificate mode is not part of this case's field matrix and has no "
            "committed fixture; tc-ver-cli-cert-o-002 owns that coverage and remains unscripted."
        ),
    },
    "tc-ver-cli-cert-o-005": {
        "steps": [
            ("prereq", cli005_step01),
            ("config-validation", cli005_step02),
            ("recovery-cleanup", cli005_step03),
        ],
        "summary": (
            "Configuration validation held: valid default and custom trust-root configurations "
            "started and served health, a replaced TDX root changed only the TDX verdict, and the "
            "unsafe anchor conflict, missing root and unparsable root each failed at startup "
            "without binding a listener."
        ),
        "remarks": (
            "The custom trust root is a run-scoped non-production CA minted in the work area; its "
            "private key is recorded only by presence and removed in the postcondition."
        ),
    },
}


def main() -> int:
    """Run the scenario registered for this case and emit its result."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    spec = CASES.get(case_id)
    if spec is None:
        raise SystemExit(f"unsupported promoted verifier case: {case_id}")
    ctx = Context()
    steps: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    status = "PASS"
    failure: str | None = None

    for index, (slug, action) in enumerate(spec["steps"], start=1):
        step_id = f"{case_id}-step-{index:02d}"
        if status != "PASS":
            steps.append(
                {
                    "id": step_id,
                    "status": "NOT_RUN",
                    "observed": "Not run after earlier failure.",
                }
            )
            continue
        print(f"STEP {step_id} START", flush=True)
        try:
            observed, evidence = action(ctx)
        except Exception as error:  # noqa: BLE001 - recorded as the case failure
            status = "FAIL"
            failure = f"{type(error).__name__}: {error}"
            steps.append({"id": step_id, "status": "FAIL", "observed": failure})
            print(
                f"EVIDENCE {step_id} - Records the first failed expectation.",
                flush=True,
            )
            print(failure, flush=True)
            print(f"STEP {step_id} END - FAIL", flush=True)
            continue
        relative = f"artifacts/step{index:02d}-{slug}.json"
        atomic_json(ctx.result_dir / relative, evidence)
        entry = {
            "path": relative,
            "step_id": step_id,
            "name": f"Step {index} {slug.replace('-', ' ')}",
            "description": observed,
        }
        entries.append(entry)
        steps.append({"id": step_id, "status": "PASS", "observed": observed})
        print(f"EVIDENCE {step_id} - {observed}", flush=True)
        print(f"STEP {step_id} END - PASS", flush=True)

    for process in list(ctx.owned):
        stop_instance(process, ctx)
    if status == "PASS":
        shutil.rmtree(ctx.workdir, ignore_errors=True)
    atomic_json(ctx.artifacts / "manifest.json", {"artifacts": entries})
    atomic_json(
        ctx.result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": spec["summary"] if status == "PASS" else str(failure),
            "steps": steps,
            "artifacts": entries,
            "remarks": spec["remarks"],
        },
    )
    print(
        json.dumps(
            {
                "status": status,
                "summary": spec["summary"] if status == "PASS" else failure,
            }
        ),
        flush=True,
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

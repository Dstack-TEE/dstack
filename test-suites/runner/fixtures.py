#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D101, D102, D103, D107
"""Fixture provider registry and lifecycle coordinator."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import signal
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from leases import Lease, LeaseJournal, OwnedResource, process_identity


@dataclass
class CheckResult:
    ok: bool
    expected: dict[str, Any] = field(default_factory=dict)
    observed: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class PreparedFixture:
    provider: str
    profile: str
    values: dict[str, Any] = field(default_factory=dict)
    initial_state: CheckResult | None = None


class FixtureUnavailable(RuntimeError):
    """Raised when the requested lab capability is not configured."""


class FixtureProvider(ABC):
    name: str

    @abstractmethod
    def prepare(
        self, request: dict[str, Any], lease: Lease, journal: LeaseJournal
    ) -> PreparedFixture:
        raise NotImplementedError

    def verify_initial_state(
        self, request: dict[str, Any], lease: Lease, prepared: PreparedFixture
    ) -> CheckResult:
        return CheckResult(
            ok=True, expected=request.get("initial_state", {}), observed={}
        )

    def collect(
        self, request: dict[str, Any], lease: Lease, destination: Path
    ) -> list[dict[str, Any]]:
        return []

    @abstractmethod
    def destroy(self, lease: Lease, journal: LeaseJournal) -> None:
        raise NotImplementedError


class NoopProvider(FixtureProvider):
    name = "noop"

    def prepare(
        self, request: dict[str, Any], lease: Lease, journal: LeaseJournal
    ) -> PreparedFixture:
        return PreparedFixture(provider=self.name, profile=lease.profile)

    def destroy(self, lease: Lease, journal: LeaseJournal) -> None:
        return None


class ProcessProvider(FixtureProvider):
    """Launch a declared local process in an owned process group."""

    name = "process"

    def __init__(self) -> None:
        self.processes: dict[int, subprocess.Popen[bytes]] = {}

    def prepare(
        self, request: dict[str, Any], lease: Lease, journal: LeaseJournal
    ) -> PreparedFixture:
        command = request.get("command")
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(value, str) for value in command)
        ):
            raise ValueError("process fixture command must be a non-empty string array")
        cwd_value = request.get("cwd")
        cwd = Path(cwd_value).resolve() if isinstance(cwd_value, str) else None
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.processes[process.pid] = process
        identity = process_identity(process.pid)
        journal.add_resource(
            lease,
            OwnedResource(
                type="process",
                identity=identity,
                cleanup={"method": "signal-process-group", "signal": "SIGTERM"},
            ),
        )
        return PreparedFixture(
            provider=self.name,
            profile=lease.profile,
            values={"process": identity},
        )

    @staticmethod
    def _owned_process(identity: dict[str, Any]) -> bool:
        try:
            fields = (
                Path(f"/proc/{int(identity['pid'])}/stat")
                .read_text(encoding="utf-8")
                .split()
            )
            if fields[2] == "Z":
                return False
            actual = process_identity(int(identity["pid"]))
        except (OSError, ValueError, KeyError, IndexError):
            return False
        return actual == identity

    def destroy(self, lease: Lease, journal: LeaseJournal) -> None:
        for resource in reversed(lease.resources):
            if resource.type != "process" or resource.state == "RELEASED":
                continue
            if self._owned_process(resource.identity):
                try:
                    os.killpg(int(resource.identity["pgid"]), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 2
                while (
                    self._owned_process(resource.identity)
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                if self._owned_process(resource.identity):
                    try:
                        os.killpg(int(resource.identity["pgid"]), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            process = self.processes.pop(int(resource.identity["pid"]), None)
            if process is not None:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            else:
                try:
                    os.waitpid(int(resource.identity["pid"]), os.WNOHANG)
                except ChildProcessError:
                    pass
            resource.state = "RELEASED"
            journal.save(lease)


class LocalSimulatorProvider(FixtureProvider):
    name = "local-simulator"

    def prepare(
        self, request: dict[str, Any], lease: Lease, journal: LeaseJournal
    ) -> PreparedFixture:
        plan_root = Path(str(request.get("_plan_root", ""))).resolve()
        runtime_manifest = Path(str(request.get("_runtime_manifest", ""))).resolve()
        start_helper = plan_root / "shared" / "automation" / "start-simulator.sh"
        stop_helper = plan_root / "shared" / "automation" / "stop-simulator.sh"
        if (
            not runtime_manifest.is_file()
            or not start_helper.is_file()
            or not stop_helper.is_file()
        ):
            raise FixtureUnavailable(
                "local simulator requires a prepared runtime manifest and simulator helpers"
            )
        try:
            runtime_config = json.loads(runtime_manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError("runtime manifest is not valid JSON") from error
        state_root = Path(
            str(runtime_config.get("environment", {}).get("DSTACK_TEST_STATE_ROOT", ""))
            or os.environ.get("DSTACK_TEST_STATE_ROOT", "")
            or tempfile.gettempdir()
        )
        runtime = state_root / "s" / f"{lease.case_id}-{lease.lease_id[-12:]}"
        fixture_path = runtime / "simulator-fixture.json"
        runtime.mkdir(parents=True, exist_ok=False)
        process = subprocess.run(
            [str(start_helper), str(runtime_manifest), str(runtime), str(fixture_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(
                f"simulator fixture failed to start: {process.stderr[-2000:]}"
            )
        try:
            values = json.loads(fixture_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                "simulator helper produced no valid fixture JSON"
            ) from error
        journal.add_resource(
            lease,
            OwnedResource(
                type="local-simulator",
                identity={"fixture_path": str(fixture_path)},
                cleanup={"method": "simulator-stop-helper", "path": str(stop_helper)},
            ),
        )
        return PreparedFixture(provider=self.name, profile=lease.profile, values=values)

    def destroy(self, lease: Lease, journal: LeaseJournal) -> None:
        for resource in reversed(lease.resources):
            if resource.type != "local-simulator" or resource.state == "RELEASED":
                continue
            helper = Path(str(resource.cleanup["path"])).resolve()
            fixture_path = Path(str(resource.identity["fixture_path"])).resolve()
            if not fixture_path.exists():
                resource.state = "RELEASED"
                journal.save(lease)
                continue
            process = subprocess.run(
                [str(helper), str(fixture_path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
            if process.returncode != 0:
                raise RuntimeError(
                    f"simulator fixture cleanup failed: {process.stderr[-2000:]}"
                )
            resource.state = "RELEASED"
            journal.save(lease)


class ExternalCommandProvider(FixtureProvider):
    """Bridge a lab-specific provider through a checked command protocol."""

    def __init__(self, name: str, plan_root: Path | None = None):
        self.name = name
        self.plan_root = plan_root

    @property
    def environment_name(self) -> str:
        return "DSTACK_TEST_PROVIDER_" + self.name.upper().replace("-", "_")

    def _default_path(self) -> Path | None:
        """Return the provider checked in under shared/fixtures/providers/<name>.py."""
        if self.plan_root is None:
            return None
        candidate = (
            self.plan_root / "shared" / "fixtures" / "providers" / f"{self.name}.py"
        )
        return candidate if candidate.is_file() else None

    def _command(self) -> list[str]:
        value = os.environ.get(self.environment_name)
        if not value:
            # A provider checked in beside the plan is the configuration; the
            # environment variable only overrides it for a different lab.
            # Requiring the variable turned every such case into a spurious
            # BLOCKED result whenever a run was launched without it.
            default = self._default_path()
            if default is None:
                raise FixtureUnavailable(
                    f"fixture provider {self.name!r} is not configured; set "
                    f"{self.environment_name}"
                )
            value = str(default)
        # Provider configuration is an executable path, never a shell fragment.
        path = Path(value).resolve()
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
            raise FixtureUnavailable(f"invalid provider executable: {path}")
        return [str(path)]

    def _invoke(self, action: str, value: dict[str, Any]) -> dict[str, Any]:
        process = subprocess.run(
            [*self._command(), action],
            input=json.dumps(value),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # Multi-guest hardware providers provision sequentially and each guest
            # has its own bounded readiness window.  The action timeout must cover
            # the whole lease rather than expire during a valid second guest boot.
            timeout=1800,
            check=False,
        )
        if process.returncode != 0:
            stderr = process.stderr
            if len(stderr) > 4000:
                stderr = (
                    stderr[:2000] + "\n... stderr middle omitted ...\n" + stderr[-2000:]
                )
            raise RuntimeError(
                f"{self.name} provider {action} failed with {process.returncode}: "
                + stderr
            )
        try:
            result = json.loads(process.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"{self.name} provider returned invalid JSON") from error
        if not isinstance(result, dict):
            raise RuntimeError(f"{self.name} provider returned a non-object")
        return result

    def prepare(
        self, request: dict[str, Any], lease: Lease, journal: LeaseJournal
    ) -> PreparedFixture:
        result = self._invoke("prepare", {"request": request, "lease": asdict(lease)})
        cleanup_handle = result.get("cleanup_handle")
        if cleanup_handle is not None:
            journal.add_resource(
                lease,
                OwnedResource(
                    type="external-fixture",
                    identity={"provider": self.name, "lease_id": lease.lease_id},
                    cleanup={"method": "provider-command", "handle": cleanup_handle},
                ),
            )
        return PreparedFixture(
            provider=self.name,
            profile=lease.profile,
            values=result.get("values", {}),
        )

    def verify_initial_state(
        self, request: dict[str, Any], lease: Lease, prepared: PreparedFixture
    ) -> CheckResult:
        result = self._invoke(
            "verify",
            {
                "request": request,
                "lease": asdict(lease),
                "prepared": asdict(prepared),
            },
        )
        return CheckResult(
            ok=bool(result.get("ok")),
            expected=result.get("expected", request.get("initial_state", {})),
            observed=result.get("observed", {}),
            error=result.get("error"),
        )

    def destroy(self, lease: Lease, journal: LeaseJournal) -> None:
        resources = [
            resource
            for resource in lease.resources
            if resource.type == "external-fixture" and resource.state != "RELEASED"
        ]
        self._invoke(
            "destroy",
            {"lease": asdict(lease), "resources": [asdict(item) for item in resources]},
        )
        for resource in resources:
            resource.state = "RELEASED"
            journal.save(lease)


class FixtureManager:
    def __init__(
        self,
        run_root: Path,
        profiles: dict[str, dict[str, Any]] | None = None,
        plan_root: Path | None = None,
    ):
        self.run_root = run_root.resolve()
        self.plan_root = plan_root.resolve() if plan_root is not None else None
        self.journal = LeaseJournal(self.run_root / "leases")
        self.profiles = profiles or {}
        self.providers: dict[str, FixtureProvider] = {}
        for provider in (NoopProvider(), ProcessProvider(), LocalSimulatorProvider()):
            self.providers[provider.name] = provider
        for name in (
            "tdxlab-isolated",
            "isolated-component",
            "hardware-pool",
            "version-matrix",
        ):
            self.providers[name] = ExternalCommandProvider(name, self.plan_root)

    def provider(self, name: str) -> FixtureProvider:
        try:
            return self.providers[name]
        except KeyError as error:
            raise ValueError(f"unknown fixture provider: {name}") from error

    def provision(
        self, run_id: str, case_id: str, request: dict[str, Any]
    ) -> tuple[Lease, dict[str, Any]]:
        profile = str(request.get("profile", "noop"))
        profile_defaults = self.profiles.get(profile, {})
        resolved_request = {**profile_defaults, **request}
        provider_name = str(resolved_request.get("provider", "noop"))
        ttl = resolved_request.get("ttl_seconds", 3600)
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 86400:
            raise ValueError("fixture ttl_seconds must be 1..86400")
        lease_id = f"lease-{case_id}-{secrets.token_hex(6)}"
        lease = self.journal.create(
            lease_id, run_id, case_id, provider_name, profile, ttl
        )
        provider = self.provider(provider_name)
        try:
            self.journal.set_state(lease, "PROVISIONING")
            prepared = provider.prepare(resolved_request, lease, self.journal)
            self.journal.set_state(lease, "VERIFYING_FIXTURE")
            checked = provider.verify_initial_state(resolved_request, lease, prepared)
            prepared.initial_state = checked
            if not checked.ok:
                raise RuntimeError(
                    checked.error or "fixture initial state did not match"
                )
            self.journal.set_state(lease, "READY")
            manifest = {
                "schema_version": "1.0",
                "lease_id": lease.lease_id,
                "run_id": run_id,
                "case_id": case_id,
                "provider": provider_name,
                "profile": profile,
                "contract": {
                    key: value
                    for key, value in resolved_request.items()
                    if not key.startswith("_")
                },
                "expires_at": lease.expires_at,
                "initial_state": asdict(checked),
                "values": prepared.values,
                "resources": [asdict(resource) for resource in lease.resources],
            }
            manifest["sha256"] = hashlib.sha256(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return lease, manifest
        except Exception as error:
            self.journal.set_state(lease, "PROVISION_ERROR", str(error))
            if not lease.resources:
                self.journal.set_state(lease, "RELEASED", str(error))
            else:
                try:
                    self.cleanup(lease)
                except Exception:
                    pass
            raise

    def cleanup(self, lease: Lease) -> None:
        provider = self.provider(lease.provider)
        self.journal.set_state(lease, "CLEANING")
        try:
            provider.destroy(lease, self.journal)
        except Exception as error:
            self.journal.set_state(lease, "CLEANUP_ERROR", str(error))
            raise
        self.journal.set_state(lease, "RELEASED")

    def reconcile(self) -> list[str]:
        released = []
        for lease in self.journal.unfinished():
            self.cleanup(lease)
            released.append(lease.lease_id)
        return released

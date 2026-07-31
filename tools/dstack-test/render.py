#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D101, D102, D103
"""Validate and render a dstack test-plan run as one self-contained HTML file."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import mimetypes
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STATUS = ("PASS", "FAIL", "BLOCKED", "NOT_RUN", "SKIPPED")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
ANCHOR_LINE_RE = re.compile(r'^\s*<a\s+id="([a-z0-9][a-z0-9-]*)"></a>\s*$')
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
CODE_RE = re.compile(r"`([^`]+)`")
BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")


class ReportError(Exception):
    """Raised when a plan or result violates the report contract."""


@dataclass
class CaseEntry:
    chapter_id: str
    chapter_title: str
    section_id: str
    section_title: str
    id: str
    title: str
    path: Path
    spec_path: Path
    spec_anchor: str
    priority: str = ""
    requirements: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    execution: dict[str, Any] | None = None
    fixture: dict[str, Any] | None = None
    actions_under_test: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)


@dataclass
class Plan:
    root: Path
    index: dict[str, Any]
    guide_path: Path
    cases: list[CaseEntry]
    chapter_docs: dict[str, Path]
    section_docs: dict[str, Path]
    anchors: set[str]
    fixture_profiles: dict[str, dict[str, Any]] = field(default_factory=dict)


def case_result_dir(plan: Plan, run_id: str, case: CaseEntry) -> Path:
    """Return the canonical run-scoped result directory for one case."""
    relative = case.path.relative_to(plan.root)
    return plan.root / "results" / run_id / "cases" / relative


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ReportError(f"missing JSON file: {path}") from error
    except json.JSONDecodeError as error:
        raise ReportError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReportError(f"expected JSON object in {path}")
    return value


def require(obj: dict[str, Any], key: str, context: str) -> Any:
    if key not in obj:
        raise ReportError(f"missing {key!r} in {context}")
    return obj[key]


def check_id(value: Any, context: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ReportError(f"invalid ID {value!r} in {context}")
    return value


def safe_path(root: Path, relative: str, context: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ReportError(f"invalid relative path {relative!r} in {context}")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ReportError(f"path escapes plan root in {context}: {relative}") from error
    return candidate


def markdown_anchors(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ReportError(f"missing Markdown document: {path}") from error
    return {
        match.group(1)
        for line in text.splitlines()
        if (match := ANCHOR_LINE_RE.match(line))
    }


def sorted_by_order(items: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        raise ReportError(f"expected array in {context}")
    result: list[dict[str, Any]] = []
    orders: list[int] = []
    for item in items:
        if not isinstance(item, dict):
            raise ReportError(f"expected object in {context}")
        order = require(item, "order", context)
        if not isinstance(order, int) or order < 1:
            raise ReportError(f"invalid order in {context}: {order!r}")
        result.append(item)
        orders.append(order)
    if orders != sorted(orders) or len(orders) != len(set(orders)):
        raise ReportError(f"items in {context} must have unique ascending order")
    return result


def validate_execution(root: Path, value: Any, context: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ReportError(f"execution must be an object in {context}")
    entrypoint_value = require(value, "entrypoint", f"{context}.execution")
    entrypoint = safe_path(root, entrypoint_value, f"{context}.execution.entrypoint")
    if entrypoint.is_symlink() or not entrypoint.is_file():
        raise ReportError(f"execution entrypoint must be a regular file: {entrypoint}")
    if not os.access(entrypoint, os.X_OK):
        raise ReportError(f"execution entrypoint is not executable: {entrypoint}")
    try:
        with entrypoint.open(encoding="utf-8") as source:
            first_line = source.readline()
    except (OSError, UnicodeError) as error:
        raise ReportError(f"cannot read execution entrypoint: {entrypoint}") from error
    if not first_line.startswith("#!"):
        raise ReportError(f"execution entrypoint has no shebang: {entrypoint}")
    args = value.get("args", [])
    if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
        raise ReportError(f"execution args must be an array of strings in {context}")
    timeout = value.get("timeout_seconds", 600)
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 86400
    ):
        raise ReportError(f"execution timeout_seconds must be 1..86400 in {context}")
    return {
        "entrypoint": str(entrypoint.relative_to(root)),
        "args": list(args),
        "timeout_seconds": timeout,
    }


def load_plan(root: Path) -> Plan:
    root = root.resolve()
    index = load_json(root / "index.json")
    plan_id = check_id(require(index, "id", "index.json"), "index.json")
    guide = require(index, "guide", "index.json")
    if not isinstance(guide, dict):
        raise ReportError("guide must be an object")
    guide_path = safe_path(root, require(guide, "path", "guide"), "guide")
    guide_anchor = check_id(require(guide, "anchor", "guide"), "guide")
    anchors: set[str] = {plan_id}
    fixture_profiles: dict[str, dict[str, Any]] = {}
    profiles_path = root / "fixtures" / "profiles.json"
    if profiles_path.is_file():
        profile_document = load_json(profiles_path)
        profile_values = require(profile_document, "profiles", str(profiles_path))
        if not isinstance(profile_values, dict):
            raise ReportError(f"profiles must be an object in {profiles_path}")
        for profile_name, profile in profile_values.items():
            check_id(profile_name, str(profiles_path))
            if not isinstance(profile, dict) or not isinstance(
                profile.get("provider"), str
            ):
                raise ReportError(f"invalid fixture profile {profile_name!r}")
            fixture_profiles[profile_name] = dict(profile)
    guide_anchors = markdown_anchors(guide_path)
    if guide_anchor not in guide_anchors:
        raise ReportError(f"guide anchor #{guide_anchor} not found in {guide_path}")
    anchors.update(guide_anchors)

    cases: list[CaseEntry] = []
    chapter_docs: dict[str, Path] = {}
    section_docs: dict[str, Path] = {}
    ids = {plan_id}
    for chapter in sorted_by_order(
        require(index, "chapters", "index.json"), "chapters"
    ):
        chapter_id = check_id(require(chapter, "id", "chapter"), "chapter")
        if chapter_id in ids:
            raise ReportError(f"duplicate ID: {chapter_id}")
        ids.add(chapter_id)
        chapter_title = str(require(chapter, "title", chapter_id))
        chapter_root = safe_path(root, require(chapter, "path", chapter_id), chapter_id)
        document = chapter.get("document")
        if isinstance(document, dict):
            doc = safe_path(root, require(document, "path", chapter_id), chapter_id)
            anchor = check_id(require(document, "anchor", chapter_id), chapter_id)
            doc_anchors = markdown_anchors(doc)
            if anchor not in doc_anchors:
                raise ReportError(f"chapter anchor #{anchor} not found in {doc}")
            anchors.update(doc_anchors)
            chapter_docs[chapter_id] = doc
        elif (chapter_root / "README.md").is_file():
            chapter_docs[chapter_id] = chapter_root / "README.md"
            anchors.update(markdown_anchors(chapter_root / "README.md"))

        for section in sorted_by_order(
            require(chapter, "sections", chapter_id), f"{chapter_id}.sections"
        ):
            section_id = check_id(require(section, "id", "section"), "section")
            if section_id in ids:
                raise ReportError(f"duplicate ID: {section_id}")
            ids.add(section_id)
            section_title = str(require(section, "title", section_id))
            section_root = safe_path(
                root, require(section, "path", section_id), section_id
            )
            document = section.get("document")
            if isinstance(document, dict):
                doc = safe_path(root, require(document, "path", section_id), section_id)
                anchor = check_id(require(document, "anchor", section_id), section_id)
                doc_anchors = markdown_anchors(doc)
                if anchor not in doc_anchors:
                    raise ReportError(f"section anchor #{anchor} not found in {doc}")
                anchors.update(doc_anchors)
                section_docs[section_id] = doc
            elif (section_root / "README.md").is_file():
                section_docs[section_id] = section_root / "README.md"
                anchors.update(markdown_anchors(section_root / "README.md"))

            for case in sorted_by_order(
                require(section, "cases", section_id), f"{section_id}.cases"
            ):
                case_id = check_id(require(case, "id", "case"), "case")
                if case_id in ids:
                    raise ReportError(f"duplicate ID: {case_id}")
                ids.add(case_id)
                case_path = safe_path(root, require(case, "path", case_id), case_id)
                spec = require(case, "spec", case_id)
                if not isinstance(spec, dict):
                    raise ReportError(f"spec must be object in {case_id}")
                spec_path = safe_path(root, require(spec, "path", case_id), case_id)
                spec_anchor = check_id(require(spec, "anchor", case_id), case_id)
                case_anchors = markdown_anchors(spec_path)
                if spec_anchor not in case_anchors:
                    raise ReportError(
                        f"spec anchor #{spec_anchor} not found in {spec_path}"
                    )
                duplicate_anchors = anchors.intersection(case_anchors)
                if duplicate_anchors:
                    raise ReportError(
                        f"duplicate Markdown anchor(s): {sorted(duplicate_anchors)}"
                    )
                anchors.update(case_anchors)
                execution = validate_execution(root, case.get("execution"), case_id)
                fixture = case.get("fixture")
                if fixture is not None and not isinstance(fixture, dict):
                    raise ReportError(f"fixture must be an object in {case_id}")
                if fixture is not None:
                    profile_name = fixture.get("profile")
                    if not isinstance(profile_name, str) or not profile_name:
                        raise ReportError(
                            f"fixture profile must be a string in {case_id}"
                        )
                    if fixture_profiles and profile_name not in fixture_profiles:
                        raise ReportError(
                            f"unknown fixture profile {profile_name!r} in {case_id}"
                        )
                actions = case.get("actions_under_test", [])
                if not isinstance(actions, list) or any(
                    not isinstance(action, str) or not action.strip()
                    for action in actions
                ):
                    raise ReportError(
                        f"actions_under_test must be an array of strings in {case_id}"
                    )
                depends_on = case.get("depends_on", [])
                if not isinstance(depends_on, list) or any(
                    not isinstance(ref, str) or not ref.strip() for ref in depends_on
                ):
                    raise ReportError(
                        f"depends_on must be an array of case IDs in {case_id}"
                    )
                cases.append(
                    CaseEntry(
                        chapter_id=chapter_id,
                        chapter_title=chapter_title,
                        section_id=section_id,
                        section_title=section_title,
                        id=case_id,
                        title=str(require(case, "title", case_id)),
                        path=case_path,
                        spec_path=spec_path,
                        spec_anchor=spec_anchor,
                        priority=str(case.get("priority", "")),
                        requirements=list(case.get("requirements", [])),
                        risks=list(case.get("risks", [])),
                        tags=list(case.get("tags", [])),
                        execution=execution,
                        fixture=dict(fixture) if fixture is not None else None,
                        actions_under_test=list(actions),
                        depends_on=list(depends_on),
                    )
                )
    # depends_on must reference known cases that are ordered earlier, so a
    # deterministic driver can resolve every dependency from prior results.
    positions = {case.id: order for order, case in enumerate(cases)}
    for order, case in enumerate(cases):
        for ref in case.depends_on:
            if ref not in positions:
                raise ReportError(f"unknown depends_on case {ref!r} in {case.id}")
            if positions[ref] >= order:
                raise ReportError(
                    f"depends_on {ref!r} must be ordered before {case.id}"
                )
    return Plan(
        root,
        index,
        guide_path,
        cases,
        chapter_docs,
        section_docs,
        anchors,
        fixture_profiles,
    )


def inline_markup(text: str) -> str:
    escaped = html.escape(text, quote=False)
    escaped = CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
    escaped = BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)

    def link(match: re.Match[str]) -> str:
        label, target = match.group(1), html.unescape(match.group(2))
        if "#" in target:
            target = "#" + target.rsplit("#", 1)[1]
        return f'<a href="{html.escape(target, quote=True)}">{label}</a>'

    return LINK_RE.sub(link, escaped)


def markdown_to_html(text: str) -> str:
    """Render the deliberately small Markdown subset used by test plans."""
    lines = text.splitlines()
    out: list[str] = []
    paragraph: list[str] = []
    list_type: str | None = None
    in_code = False
    code_lang = ""
    code_lines: list[str] = []
    table_lines: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            out.append(
                f"<p>{inline_markup(' '.join(x.strip() for x in paragraph))}</p>"
            )
            paragraph = []

    def close_list() -> None:
        nonlocal list_type
        if list_type:
            out.append(f"</{list_type}>")
            list_type = None

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        rows = [
            [cell.strip() for cell in line.strip().strip("|").split("|")]
            for line in table_lines
        ]
        if len(rows) >= 2 and all(
            re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in rows[1]
        ):
            out.append(
                '<div class="table-wrap"><table><thead><tr>'
                + "".join(f"<th>{inline_markup(c)}</th>" for c in rows[0])
                + "</tr></thead><tbody>"
            )
            for row in rows[2:]:
                out.append(
                    "<tr>"
                    + "".join(f"<td>{inline_markup(c)}</td>" for c in row)
                    + "</tr>"
                )
            out.append("</tbody></table></div>")
        else:
            out.extend(f"<p>{inline_markup(line)}</p>" for line in table_lines)
        table_lines = []

    for line in lines + [""]:
        if in_code:
            if line.startswith("```"):
                out.append(
                    f'<pre class="code" data-language="{html.escape(code_lang)}"><code>{html.escape(chr(10).join(code_lines))}</code></pre>'
                )
                in_code = False
                code_lines = []
            else:
                code_lines.append(line)
            continue
        if line.startswith("```"):
            flush_paragraph()
            close_list()
            flush_table()
            in_code = True
            code_lang = line[3:].strip()
            continue
        if match := ANCHOR_LINE_RE.match(line):
            flush_paragraph()
            close_list()
            flush_table()
            out.append(f'<a id="{match.group(1)}" class="anchor"></a>')
            continue
        if match := HEADING_RE.match(line):
            flush_paragraph()
            close_list()
            flush_table()
            level = len(match.group(1))
            out.append(f"<h{level}>{inline_markup(match.group(2))}</h{level}>")
            continue
        if line.startswith("|") and line.rstrip().endswith("|"):
            flush_paragraph()
            close_list()
            table_lines.append(line)
            continue
        flush_table()
        if match := re.match(r"^\s*[-*]\s+(.+)$", line):
            flush_paragraph()
            if list_type != "ul":
                close_list()
                out.append("<ul>")
                list_type = "ul"
            out.append(f"<li>{inline_markup(match.group(1))}</li>")
            continue
        if match := re.match(r"^\s*\d+[.)]\s+(.+)$", line):
            flush_paragraph()
            if list_type != "ol":
                close_list()
                out.append("<ol>")
                list_type = "ol"
            out.append(f"<li>{inline_markup(match.group(1))}</li>")
            continue
        if not line.strip():
            flush_paragraph()
            close_list()
        else:
            close_list()
            paragraph.append(line)
    return "\n".join(out)


def status_badge(status: str) -> str:
    cls = status.lower().replace("_", "-")
    return f'<span class="status {cls}">{html.escape(status)}</span>'


def json_block(value: Any) -> str:
    return f'<pre class="json"><code>{html.escape(json.dumps(value, ensure_ascii=False, indent=2))}</code></pre>'


def ref_link(ref: str, label: str | None = None) -> str:
    fragment = ref.rsplit("#", 1)[-1] if "#" in ref else ""
    href = f"#{html.escape(fragment, quote=True)}" if fragment else "#"
    return f'<a href="{href}">{html.escape(label or ref)}</a>'


def resolve_ref_file(base: Path, ref: str, plan_root: Path) -> tuple[Path, str]:
    path_part, _, anchor = ref.partition("#")
    path = base if not path_part else (base.parent / path_part).resolve()
    try:
        path.relative_to(plan_root)
    except ValueError as error:
        raise ReportError(f"reference escapes plan root: {ref}") from error
    if not path.is_file():
        raise ReportError(f"referenced file does not exist: {ref} from {base}")
    return path, anchor


def load_evidence(
    result_path: Path, ref: str, plan_root: Path
) -> tuple[dict[str, Any], Path]:
    path, anchor = resolve_ref_file(result_path, ref, plan_root)
    value = load_json(path)
    if anchor and anchor not in (value.get("anchor"), value.get("id")):
        raise ReportError(f"evidence anchor #{anchor} not found in {path}")
    return value, path


def verify_attachment(result_path: Path, item: dict[str, Any], plan_root: Path) -> Path:
    path = safe_path(
        result_path.parent, require(item, "path", "attachment"), "attachment"
    )
    try:
        path.relative_to(plan_root)
    except ValueError as error:
        raise ReportError(f"attachment escapes plan root: {path}") from error
    if not path.is_file():
        raise ReportError(f"missing attachment: {path}")
    data = path.read_bytes()
    expected_size = item.get("size_bytes")
    if expected_size is not None and expected_size != len(data):
        raise ReportError(f"attachment size mismatch: {path}")
    expected_hash = item.get("sha256")
    if expected_hash and hashlib.sha256(data).hexdigest() != expected_hash:
        raise ReportError(f"attachment SHA-256 mismatch: {path}")
    return path


def render_command(command: dict[str, Any], anchor_override: str | None = None) -> str:
    anchor = anchor_override or str(
        command.get("anchor") or command.get("id") or "command"
    )
    title = str(command.get("command", "command"))
    env = command.get("environment", {})
    meta = {
        "cwd": command.get("cwd"),
        "environment": env,
        "started_at": command.get("started_at"),
        "finished_at": command.get("finished_at"),
        "duration_ms": command.get("duration_ms"),
        "exit_code": command.get("exit_code"),
    }
    parts = [
        f'<a id="{html.escape(anchor)}" class="anchor"></a>',
        '<details class="command"><summary><span class="chevron">›</span> ',
        f"<code>{html.escape(title)}</code>",
        f' <span class="exit-code">exit {html.escape(str(command.get("exit_code", "?")))}</span></summary>',
    ]
    parts.append('<div class="command-body"><h5>Execution metadata</h5>')
    parts.append(json_block(meta))
    for stream in ("stdout", "stderr"):
        value = command.get(stream)
        if value is not None:
            parts.append(
                f'<h5>{stream}</h5><pre class="stream {stream}"><code>{html.escape(str(value))}</code></pre>'
            )
        attachment = command.get(f"{stream}_attachment")
        if attachment:
            parts.append(
                f"<p>{stream} attachment: {ref_link(str(attachment.get('ref', '')))}</p>"
            )
    parts.append("</div></details>")
    return "".join(parts)


def render_attachment(item: dict[str, Any], path: Path) -> str:
    data = path.read_bytes()
    media = str(
        item.get("media_type")
        or mimetypes.guess_type(path.name)[0]
        or "application/octet-stream"
    )
    anchor = str(item.get("anchor") or item.get("id") or f"attachment-{path.name}")
    title = str(item.get("title") or path.name)
    digest = hashlib.sha256(data).hexdigest()
    header = f'<a id="{html.escape(anchor)}" class="anchor"></a><h5>{html.escape(title)}</h5><p class="attachment-meta">{html.escape(media)} · {len(data)} bytes · SHA-256 <code>{digest}</code></p>'
    if media.startswith("image/"):
        uri = f"data:{media};base64,{base64.b64encode(data).decode()}"
        return (
            header
            + f'<a href="{uri}" download="{html.escape(path.name)}"><img class="attachment-image" src="{uri}" alt="{html.escape(title)}"></a>'
        )
    if media.startswith("text/") or media in ("application/json", "application/xml"):
        text = data.decode("utf-8", errors="replace")
        lang = "json" if media == "application/json" else "text"
        return (
            header
            + f'<details class="attachment"><summary><span class="chevron">›</span> View {html.escape(path.name)}</summary><pre class="{lang}"><code>{html.escape(text)}</code></pre></details>'
        )
    uri = f"data:{media};base64,{base64.b64encode(data).decode()}"
    return (
        header
        + f'<a class="download" download="{html.escape(path.name)}" href="{uri}">Download inline attachment</a>'
    )


def validate_case_result(case: CaseEntry, result: dict[str, Any], path: Path) -> None:
    if result.get("id") != case.id:
        raise ReportError(f"case ID mismatch in {path}: expected {case.id}")
    status = result.get("status")
    if status not in STATUS:
        raise ReportError(f"invalid case status {status!r} in {path}")
    steps = result.get("steps", [])
    if not isinstance(steps, list):
        raise ReportError(f"steps must be array in {path}")
    for step in steps:
        if not isinstance(step, dict) or step.get("status") not in STATUS:
            raise ReportError(f"invalid step in {path}")
        refs = step.get("evidence_refs", [])
        commands = step.get("commands", [])
        if status not in ("NOT_RUN", "SKIPPED") and not refs and not commands:
            raise ReportError(
                f"step {step.get('id')} has no command evidence in {path}"
            )
    if status == "PASS" and any(step.get("status") != "PASS" for step in steps):
        raise ReportError(f"PASS case contains non-PASS step in {path}")
    if status == "PASS" and not steps:
        raise ReportError(f"PASS case has no steps in {path}")


def session_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as source:
        for line_no, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ReportError(
                    f"invalid session JSONL at {path}:{line_no}: {error}"
                ) from error
            if not isinstance(value, dict):
                raise ReportError(f"session event is not an object at {path}:{line_no}")
            events.append(value)
    if not events:
        raise ReportError(f"empty session JSONL: {path}")
    return events


def event_title(event: dict[str, Any], number: int) -> str:
    kind = str(
        event.get("type") or event.get("event") or event.get("subtype") or "event"
    )
    item = event.get("item")
    if isinstance(item, dict) and item.get("type"):
        kind += f" · {item['type']}"
    message = event.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            kind += f" · {content.strip()[:80]}"
    return f"{number:04d} · {kind}"


def render_session(
    case_id: str,
    events: list[dict[str, Any]],
    label: str = "Complete execution session",
) -> str:
    parts = [
        '<details class="session"><summary><span class="chevron">›</span> '
        + html.escape(label)
        + " ("
        + str(len(events))
        + ' events)</summary><div class="session-events">'
    ]
    for number, event in enumerate(events, 1):
        anchor = f"session-{case_id}-event-{number}"
        parts.append(
            f'<a id="{anchor}" class="anchor"></a><details class="session-event"><summary><span class="chevron">›</span> {html.escape(event_title(event, number))}</summary>{json_block(event)}</details>'
        )
    parts.append("</div></details>")
    return "".join(parts)


def step_session_ref(step_id: str, events: list[dict[str, Any]], case_id: str) -> str:
    for number, event in enumerate(events, 1):
        if step_id in json.dumps(event, ensure_ascii=False):
            return f'<a class="session-ref" href="#session-{case_id}-event-{number}">Jump to session evidence · event {number}</a>'
    return '<span class="session-ref fallback">Evidence mapping: whole session fallback</span>'


def render_case_result(
    case: CaseEntry, result: dict[str, Any], result_path: Path, plan: Plan
) -> str:
    status = str(result["status"])
    result_dir = result_path.parent
    runner_path = result_dir / "runner.json"
    session_path = result_dir / "session.jsonl"
    if not runner_path.is_file():
        raise ReportError(f"missing runner.json for {case.id}")
    runner = load_json(runner_path)
    events = session_events(session_path)
    parts = [
        f'<section class="case-result status-border-{status.lower().replace("_", "-")}" id="result-{case.id}" data-status="{status}">'
    ]
    parts.append(
        f'<div class="case-result-head"><h3>Execution result</h3>{status_badge(status)}</div>'
    )
    parts.append(
        f'<div class="result-summary">{html.escape(str(result.get("summary", "")))}</div>'
    )
    parts.append(
        '<details class="meta"><summary><span class="chevron">›</span> Runner metadata</summary>'
        + json_block(runner)
        + "</details>"
    )
    fixture_dir = result_dir / "fixture"
    fixture_values = {}
    for name in ("runtime-manifest", "lease", "cleanup"):
        path = fixture_dir / f"{name}.json"
        if path.is_file():
            fixture_values[name] = load_json(path)
    if fixture_values:
        parts.append(
            '<details class="meta"><summary><span class="chevron">›</span> Fixture, lease, and cleanup</summary>'
            + json_block(fixture_values)
            + "</details>"
        )
    if result.get("version_overrides"):
        parts.append(
            '<details><summary><span class="chevron">›</span> Version overrides</summary>'
            + json_block(result["version_overrides"])
            + "</details>"
        )
    for step in result.get("steps", []):
        step_id = str(step.get("id", "step"))
        step_status = str(step.get("status", ""))
        parts.append(
            f'<article class="step" id="result-{html.escape(step_id)}"><div class="step-head"><h4>{html.escape(step_id)}</h4>{status_badge(step_status)}</div>'
        )
        parts.append(
            f'<div class="observed"><h5>Observed</h5><p>{html.escape(str(step.get("observed", "")))}</p></div>'
        )
        parts.append(step_session_ref(step_id, events, case.id))
        parts.append("</article>")
    artifacts = result.get("artifacts", [])
    if artifacts:
        parts.append(
            '<details class="attachments"><summary><span class="chevron">›</span> Artifacts</summary>'
        )
        for number, artifact in enumerate(artifacts, 1):
            if not isinstance(artifact, dict) or not artifact.get("path"):
                raise ReportError(f"invalid artifact in {result_path}")
            path = safe_path(result_dir, str(artifact["path"]), "result artifact")
            try:
                path.relative_to(result_dir.resolve())
            except ValueError as error:
                raise ReportError(
                    f"artifact escapes result directory: {path}"
                ) from error
            if not path.is_file():
                raise ReportError(f"missing artifact: {path}")
            item = {
                "id": f"attachment-{case.id}-{number}",
                "anchor": f"attachment-{case.id}-{number}",
                "title": artifact.get("name") or path.name,
                "media_type": artifact.get("media_type")
                or mimetypes.guess_type(path.name)[0],
            }
            parts.append(render_attachment(item, path))
        parts.append("</details>")
    session_format = str(runner.get("session", {}).get("format", ""))
    session_label = (
        "Complete script process session"
        if session_format == "process-jsonl"
        else "Complete agent session"
    )
    parts.append(render_session(case.id, events, session_label))
    if result.get("remarks"):
        parts.append(
            f'<div class="remarks"><strong>Remarks:</strong> {html.escape(str(result["remarks"]))}</div>'
        )
    parts.append("</section>")
    return "".join(parts)


def load_session_results(
    plan: Plan, run_id: str
) -> tuple[dict[str, Any], dict[str, tuple[dict[str, Any], Path]]]:
    run_path = plan.root / "results" / run_id / "run.json"
    run = load_json(run_path)
    if run.get("id") != run_id or run.get("plan_id") != plan.index.get("id"):
        raise ReportError(f"run/plan ID mismatch in {run_path}")
    listed = run.get("case_results", [])
    if not isinstance(listed, list):
        raise ReportError("case_results must be an array")
    path_by_id: dict[str, Path] = {}
    for item in listed:
        if not isinstance(item, dict):
            raise ReportError("case_results entries must be objects")
        case_id = check_id(require(item, "id", "case_results"), "case_results")
        candidate = (
            run_path.parent / str(require(item, "result_path", case_id))
        ).resolve()
        try:
            candidate.relative_to(plan.root)
        except ValueError as error:
            raise ReportError(f"case result escapes plan root: {candidate}") from error
        path_by_id[case_id] = candidate
    results: dict[str, tuple[dict[str, Any], Path]] = {}
    for case in plan.cases:
        path = path_by_id.get(case.id)
        if path is None or not path.is_file():
            raise ReportError(f"missing finalized result for {case.id}")
        result = load_json(path)
        if result.get("case_id") != case.id or result.get("status") not in STATUS:
            raise ReportError(f"invalid shallow result for {case.id}: {path}")
        session_events(path.parent / "session.jsonl")
        if not (path.parent / "runner.json").is_file():
            raise ReportError(f"missing runner.json for {case.id}")
        results[case.id] = (result, path)
    return run, results


def load_results(
    plan: Plan, run_id: str
) -> tuple[dict[str, Any], dict[str, tuple[dict[str, Any], Path]]]:
    run_path = plan.root / "results" / run_id / "run.json"
    run = load_json(run_path)
    if run.get("id") != run_id:
        raise ReportError(f"run ID mismatch in {run_path}")
    if run.get("plan_id") != plan.index.get("id"):
        raise ReportError(f"plan ID mismatch in {run_path}")
    listed = run.get("case_results", [])
    path_by_id: dict[str, Path] = {}
    if not isinstance(listed, list):
        raise ReportError("case_results must be an array")
    for item in listed:
        if not isinstance(item, dict):
            raise ReportError("case_results entries must be objects")
        case_id = check_id(require(item, "id", "case_results"), "case_results")
        candidate = (
            run_path.parent / str(require(item, "result_path", case_id))
        ).resolve()
        try:
            candidate.relative_to(plan.root)
        except ValueError as error:
            raise ReportError(f"case result escapes plan root: {candidate}") from error
        path_by_id[case_id] = candidate
    results: dict[str, tuple[dict[str, Any], Path]] = {}
    for case in plan.cases:
        path = path_by_id.get(
            case.id, case_result_dir(plan, run_id, case) / "result.json"
        )
        if not path.is_file():
            raise ReportError(f"missing result for {case.id}: {path}")
        result = load_json(path)
        validate_case_result(case, result, path)
        results[case.id] = (result, path)
    actual: dict[str, list[str]] = {status: [] for status in STATUS}
    for case in plan.cases:
        actual[str(results[case.id][0]["status"])].append(f"#result-{case.id}")
    summary = require(run, "summary", str(run_path))
    if not isinstance(summary, dict) or summary.get("total") != len(plan.cases):
        raise ReportError("run summary total does not match plan")
    by_status = require(summary, "by_status", "summary")
    for status in STATUS:
        item = by_status.get(status, {})
        if (
            item.get("count") != len(actual[status])
            or item.get("case_refs") != actual[status]
        ):
            raise ReportError(f"summary mismatch for {status}")
    return run, results


def nav_html(plan: Plan, results: dict[str, tuple[dict[str, Any], Path]]) -> str:
    guide_anchor = html.escape(str(plan.index["guide"]["anchor"]), quote=True)
    parts = [
        f'<nav class="toc"><div class="toc-title">Contents</div><a href="#report-overview">Overview</a><a href="#{guide_anchor}">Test guide</a>'
    ]
    current_chapter = current_section = None
    for case in plan.cases:
        if case.chapter_id != current_chapter:
            if current_section is not None:
                parts.append("</div>")
            if current_chapter is not None:
                parts.append("</div>")
            parts.append(
                f'<div class="toc-chapter"><a href="#view-{case.chapter_id}">{html.escape(case.chapter_title)}</a>'
            )
            current_chapter = case.chapter_id
            current_section = None
        if case.section_id != current_section:
            if current_section is not None:
                parts.append("</div>")
            parts.append(
                f'<div class="toc-section"><a href="#view-{case.section_id}">{html.escape(case.section_title)}</a>'
            )
            current_section = case.section_id
        status = str(results[case.id][0]["status"])
        parts.append(
            f'<a class="toc-case" data-status="{status}" href="#case-card-{case.id}"><span>{html.escape(case.id)}</span>{status_badge(status)}</a>'
        )
    if current_section is not None:
        parts.append("</div>")
    if current_chapter is not None:
        parts.append("</div>")
    parts.append("</nav>")
    return "".join(parts)


CSS = r"""
:root{--bg:#f5f7fb;--panel:#fff;--ink:#172033;--muted:#667085;--line:#e3e8ef;--brand:#5b5bd6;--brand2:#7c3aed;--pass:#067647;--pass-bg:#ecfdf3;--fail:#b42318;--fail-bg:#fef3f2;--blocked:#b54708;--blocked-bg:#fffaeb;--not:#475467;--not-bg:#f2f4f7;--shadow:0 10px 30px rgba(16,24,40,.08)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}.layout{display:grid;grid-template-columns:300px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;overflow:auto;background:#111827;color:#e5e7eb;padding:22px 16px}.brand{font-size:19px;font-weight:750;margin-bottom:4px}.run-label{font-size:12px;color:#9ca3af;margin-bottom:18px}.search{width:100%;border:1px solid #374151;background:#1f2937;color:#fff;border-radius:9px;padding:9px 11px;margin-bottom:12px}.filter-row{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:14px}.filter{border:1px solid #374151;background:#1f2937;color:#d1d5db;border-radius:999px;padding:4px 8px;font-size:11px;cursor:pointer}.filter.active{background:var(--brand);border-color:var(--brand);color:#fff}.toc a{color:#d1d5db;text-decoration:none;display:flex;align-items:center;justify-content:space-between;padding:5px 7px;border-radius:6px}.toc a:hover{background:#1f2937;color:#fff}.toc-title{text-transform:uppercase;color:#9ca3af;font-size:11px;letter-spacing:.1em;margin:10px 7px}.toc-chapter{margin-top:8px}.toc-chapter>a{font-weight:700}.toc-section{margin-left:9px}.toc-section>a{font-size:13px;font-weight:600}.toc-case{margin-left:12px;font-size:12px;gap:6px}.toc .status{font-size:9px;padding:1px 5px}.main{min-width:0;padding:36px 46px 80px;max-width:1440px;width:100%;margin:auto}.hero{background:linear-gradient(125deg,#312e81,#6d28d9 60%,#2563eb);color:#fff;padding:35px;border-radius:18px;box-shadow:var(--shadow);margin-bottom:24px}.hero h1{margin:0 0 6px;font-size:30px}.hero p{color:#ddd6fe;margin:0}.panel,.chapter,.section,.case-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:0 3px 14px rgba(16,24,40,.04);padding:24px;margin:18px 0}.chapter{border-left:5px solid var(--brand)}.section{margin-left:12px;border-left:4px solid #a78bfa}.case-card{margin-left:24px;padding:0;overflow:hidden}.case-spec{padding:26px}.case-titlebar{display:flex;gap:12px;align-items:center;justify-content:space-between}.case-result{padding:24px;border-top:1px solid var(--line);background:#fcfcfd}.status-border-pass{border-left:5px solid var(--pass)}.status-border-fail{border-left:5px solid var(--fail)}.status-border-blocked{border-left:5px solid var(--blocked)}.status-border-not-run,.status-border-skipped{border-left:5px solid var(--not)}h1,h2,h3,h4,h5{line-height:1.25;scroll-margin-top:20px}h2{margin-top:30px}h3{margin-top:24px}a{color:#4f46e5}.anchor{scroll-margin-top:18px}.status{display:inline-flex;align-items:center;border-radius:999px;padding:3px 9px;font-size:11px;font-weight:750;letter-spacing:.03em}.pass{color:var(--pass);background:var(--pass-bg)}.fail{color:var(--fail);background:var(--fail-bg)}.blocked{color:var(--blocked);background:var(--blocked-bg)}.not-run,.skipped{color:var(--not);background:var(--not-bg)}.summary-grid{display:grid;grid-template-columns:repeat(5,minmax(90px,1fr));gap:12px;margin:18px 0}.summary-card{padding:15px;border:1px solid var(--line);border-radius:11px;background:#fff}.summary-card strong{display:block;font-size:25px}.summary-card span{color:var(--muted);font-size:12px}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid var(--line);padding:9px 11px;text-align:left;vertical-align:top}th{background:#f8fafc}code{font-family:"SFMono-Regular",Consolas,monospace;font-size:.9em;background:#f2f4f7;border-radius:5px;padding:1px 4px}pre{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:#101828;color:#e5e7eb;border-radius:10px;padding:14px;font:12px/1.55 "SFMono-Regular",Consolas,monospace}pre code{background:none;padding:0}.json{background:#172033}.stderr{border-left:4px solid #f04438}.stdout{border-left:4px solid #12b76a}details{border:1px solid var(--line);border-radius:10px;margin:10px 0;background:#fff}summary{cursor:pointer;padding:10px 13px;font-weight:650;list-style:none}summary::-webkit-details-marker{display:none}.chevron{display:inline-block;margin-right:7px;transition:transform .18s}details[open]>summary .chevron{transform:rotate(90deg)}details>pre,details>.json,details>.command-body,details>.assertion-grid,details>.attachment-meta{margin:0 12px 12px}.case-result-head,.step-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.case-result-head h3,.step-head h4{margin:0}.step{border-top:1px solid var(--line);padding:18px 0}.expected-observed{display:grid;grid-template-columns:1fr 1fr;gap:14px}.expected-observed h5{margin:8px 0}.command summary code{color:#344054}.exit-code{float:right;color:var(--muted);font-size:11px}.assertion-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px}.assertion{border:1px solid var(--line);border-radius:8px;padding:10px}.attachment-image{display:block;max-width:100%;max-height:700px;border:1px solid var(--line);border-radius:8px}.attachment-meta{font-size:12px;color:var(--muted)}.download{display:inline-block;padding:8px 12px;background:var(--brand);color:white;border-radius:7px;text-decoration:none}.reason{background:var(--fail-bg);border:1px solid #fecdca;padding:12px;border-radius:9px}.remarks{background:#f9fafb;padding:12px;border-radius:8px}.hidden{display:none!important}.toolbar{display:flex;gap:8px;justify-content:flex-end;margin:12px 0}.button{border:1px solid var(--line);background:#fff;border-radius:8px;padding:7px 10px;cursor:pointer}.button:hover{background:#f8fafc}.source-json{max-height:500px}@media(max-width:900px){.layout{display:block}.sidebar{position:relative;height:auto}.main{padding:20px}.summary-grid{grid-template-columns:repeat(2,1fr)}.expected-observed{grid-template-columns:1fr}.case-card,.section{margin-left:0}}@media print{.sidebar,.toolbar{display:none}.layout{display:block}.main{max-width:none;padding:0}.case-card{break-inside:avoid}details>*{display:block!important}}
"""

JS = r"""
(()=>{const q=s=>document.querySelector(s),qa=s=>[...document.querySelectorAll(s)];let filter='ALL';function apply(){const term=(q('#search').value||'').toLowerCase();qa('.case-card').forEach(c=>{const okStatus=filter==='ALL'||c.dataset.status===filter;const okText=!term||c.textContent.toLowerCase().includes(term);c.classList.toggle('hidden',!(okStatus&&okText));});qa('.toc-case').forEach(a=>{const target=q(a.getAttribute('href'));a.classList.toggle('hidden',!target||target.classList.contains('hidden'));});}q('#search').addEventListener('input',apply);qa('.filter').forEach(b=>b.addEventListener('click',()=>{qa('.filter').forEach(x=>x.classList.remove('active'));b.classList.add('active');filter=b.dataset.status;apply();}));q('#expand-all').addEventListener('click',()=>qa('details').forEach(d=>d.open=true));q('#collapse-all').addEventListener('click',()=>qa('details').forEach(d=>d.open=false));})();
"""


def render_report(
    plan: Plan, run: dict[str, Any], results: dict[str, tuple[dict[str, Any], Path]]
) -> str:
    title = str(plan.index.get("title", plan.index["id"]))
    run_id = str(run["id"])
    summary = run["summary"]["by_status"]
    body: list[str] = [
        f'<section class="hero" id="report-overview"><h1>{html.escape(title)}</h1><p>Run {html.escape(run_id)} · {html.escape(str(run.get("started_at", "")))} → {html.escape(str(run.get("finished_at", "")))}</p></section>'
    ]
    body.append('<section class="panel"><h2>Run summary</h2><div class="summary-grid">')
    for status in STATUS:
        body.append(
            f'<div class="summary-card">{status_badge(status)}<strong>{summary[status]["count"]}</strong><span>test cases</span></div>'
        )
    body.append(
        '</div><details><summary><span class="chevron">›</span> Software under test</summary>'
        + json_block(run.get("software_under_test", {}))
        + '</details><details><summary><span class="chevron">›</span> Environment and executor</summary>'
        + json_block(
            {
                "environment": run.get("environment", {}),
                "executor": run.get("executor", {}),
            }
        )
        + "</details></section>"
    )
    body.append(
        '<section class="panel"><h2>Test guide</h2>'
        + markdown_to_html(plan.guide_path.read_text(encoding="utf-8"))
        + "</section>"
    )
    current_chapter = current_section = None
    for case in plan.cases:
        if case.chapter_id != current_chapter:
            if current_section is not None:
                body.append("</section>")
            if current_chapter is not None:
                body.append("</section>")
            body.append(
                f'<section class="chapter" id="view-{case.chapter_id}"><h2>{html.escape(case.chapter_title)}</h2>'
            )
            if doc := plan.chapter_docs.get(case.chapter_id):
                body.append(markdown_to_html(doc.read_text(encoding="utf-8")))
            current_chapter = case.chapter_id
            current_section = None
        if case.section_id != current_section:
            if current_section is not None:
                body.append("</section>")
            body.append(
                f'<section class="section" id="view-{case.section_id}"><h3>{html.escape(case.section_title)}</h3>'
            )
            if doc := plan.section_docs.get(case.section_id):
                body.append(markdown_to_html(doc.read_text(encoding="utf-8")))
            current_section = case.section_id
        result, result_path = results[case.id]
        status = str(result["status"])
        body.append(
            f'<article class="case-card" id="case-card-{case.id}" data-status="{status}"><div class="case-spec"><div class="case-titlebar"><div><span class="priority">{html.escape(case.priority)}</span><h3>{html.escape(case.id)} · {html.escape(case.title)}</h3></div>{status_badge(status)}</div>'
        )
        chips = case.requirements + case.risks + case.tags
        if chips:
            body.append(
                '<p class="chips">'
                + " ".join(f"<code>{html.escape(x)}</code>" for x in chips)
                + "</p>"
            )
        body.append(
            markdown_to_html(case.spec_path.read_text(encoding="utf-8")) + "</div>"
        )
        body.append(render_case_result(case, result, result_path, plan) + "</article>")
    if current_section is not None:
        body.append("</section>")
    if current_chapter is not None:
        body.append("</section>")
    body.append(
        '<section class="panel"><h2>Raw run JSON</h2><details><summary><span class="chevron">›</span> Show source</summary><pre class="json source-json"><code>'
        + html.escape(json.dumps(run, ensure_ascii=False, indent=2))
        + "</code></pre></details></section>"
    )
    nav = nav_html(plan, results)
    filters = (
        '<div class="filter-row">'
        + "".join(
            f'<button class="filter{" active" if s == "ALL" else ""}" data-status="{s}">{s}</button>'
            for s in ("ALL",) + STATUS
        )
        + "</div>"
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)} · {html.escape(run_id)}</title><style>{CSS}</style></head><body><div class="layout"><aside class="sidebar"><div class="brand">dstack Test Report</div><div class="run-label">{html.escape(run_id)}</div><input id="search" class="search" type="search" placeholder="Search cases, commands, output…">{filters}{nav}</aside><main class="main"><div class="toolbar"><button class="button" id="expand-all">Expand all</button><button class="button" id="collapse-all">Collapse all</button></div>{"".join(body)}</main></div><script>{JS}</script></body></html>"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        type=Path,
        required=True,
        help="test-plan directory containing index.json",
    )
    parser.add_argument("--run-id", required=True, help="run ID under plan/results")
    parser.add_argument("--output", type=Path, help="self-contained HTML output path")
    parser.add_argument(
        "--validate-only", action="store_true", help="validate without rendering"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.validate_only and args.output is None:
        raise ReportError("--output is required unless --validate-only is used")
    plan = load_plan(args.plan)
    run, results = load_session_results(plan, args.run_id)
    if args.validate_only:
        print(
            json.dumps(
                {
                    "status": "valid",
                    "plan_id": plan.index["id"],
                    "run_id": args.run_id,
                    "cases": len(plan.cases),
                },
                ensure_ascii=False,
            )
        )
        return 0
    rendered = render_report(plan, run, results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "rendered",
                "output": str(args.output),
                "bytes": len(rendered.encode()),
                "cases": len(plan.cases),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReportError as error:
        print(
            json.dumps({"status": "error", "message": str(error)}, ensure_ascii=False),
            file=sys.stderr,
        )
        raise SystemExit(2)

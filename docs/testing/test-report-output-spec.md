<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="dstack-test-report-output-spec"></a>
# dstack Test Report Output Specification

This document defines the normative format for AI sessions, case summaries, run summaries, attachments, cross-references, packages, and self-contained HTML reports. See the [test methodology](dstack-test-methodology.md#dstack-test-methodology) and [case authoring specification](test-case-authoring-spec.md#dstack-test-case-authoring-spec).

<a id="report-principles"></a>
## 1. Principles

1. `run-plan` uses one AI orchestration session to drive the `next-case` loop,
   and each case it executes runs in an independent Codex or Claude session.
2. The agent's native JSONL is the primary source for commands, tool calls, and raw output.
3. The agent writes one shallow `result.json`; it does not copy command output into that file.
4. The runner generates `runner.json`, timestamps, exit code, checksums, and run aggregates.
5. Common versions and environment information appear once at run level.
6. Screenshots, long logs, and binary captures are separate attachments.
7. Stable anchors make every object linkable in one offline HTML report.

<a id="report-commands"></a>
## 2. Command interface

The single public command is `dstack-test`, with consistently named subcommands:

```text
dstack-test run-case
dstack-test run-plan
dstack-test finalize
dstack-test validate
dstack-test package
dstack-test render
```

Options use kebab-case. Execution defaults to Codex; select Claude with
`--agent claude`. Do not introduce separate `--codex` or `--claude` switches.
`run-case` and `run-plan` generate a unique run ID when `--run-id` is omitted.
Commands that operate on an existing run still require its ID.

<a id="report-run-case"></a>
## 3. Case execution

```bash
dstack-test run-case \
  --plan <plan> \
  --case <case-id-or-directory> \
  --workdir <repository> \
  -- "Additional execution constraints"
```

The runner supplies the plan guide, `case.md`, output location, status rules, and result schema in the prompt. The agent must read the guide before the case and must not modify plan specifications.

For a dependency-driven skip, the orchestrator creates a synthetic one-event
case session containing the reason and causal earlier case IDs. It does not
pretend that the skipped case was executed. The full decision process remains
available in the run-level `orchestrator.jsonl`.

<a id="report-layout"></a>
## 4. Result layout

```text
<plan>/results/<run-id>/
├── run.json
├── context.json          # optional
├── case-manifests/
├── case-lifecycle/
├── leases/
├── attempts/
├── cases/
    └── <chapter>/<section>/<case-id>/
        ├── prompt.md
        ├── session.jsonl
        ├── agent-stderr.log
        ├── runner.json
        ├── result.json
        ├── artifacts/
        ├── fixture/
        │   ├── runtime-manifest.json
        │   ├── lease.json
        │   └── cleanup.json
        └── SHA256SUMS
└── SHA256SUMS
```

One run is one self-contained directory. Its `cases/` tree mirrors the indexed
chapter, section, and case specification paths. A non-empty case result must
not be overwritten unless the caller explicitly supplies `--overwrite`.

<a id="report-session"></a>
## 5. `session.jsonl`

For Agent execution, the runner stores the native Agent CLI event stream
without rewriting it. For script execution it stores `process.started`,
`stdout`, `stderr`, and `process.exited` JSON objects. Every non-empty line is
one complete JSON object. Renderer adapters normalize these formats only for
display; the stored file remains unchanged.

The agent should include the complete step ID when beginning and completing a step:

```text
tc-gw-pp-001-step-01
```

The renderer links matching session events to the step. If no marker is found, it exposes the complete session as fallback evidence rather than inventing a narrower association.

<a id="report-runner-json"></a>
## 6. `runner.json`

Only `dstack-test` writes this file:

```json
{
  "schema_version": "1.0",
  "run_id": "run-20260723-001",
  "case_id": "tc-gw-pp-001",
  "executor": {"type": "agent", "agent": "codex", "model": "gpt-5-codex"},
  "session": {
    "format": "codex-jsonl",
    "path": "session.jsonl",
    "events": 42
  },
  "prompt_path": "prompt.md",
  "result_path": "result.json",
  "started_at": "2026-07-23T18:00:00.000Z",
  "finished_at": "2026-07-23T18:04:32.000Z",
  "duration_ms": 272000,
  "exit_code": 0,
  "result_valid": true,
  "result_error": null
}
```

Historical files may retain the legacy top-level `agent` field. New files use
`executor`. A script executor additionally records its entrypoint, argv, and
entrypoint SHA-256. Extract an Agent model name from the session when possible,
otherwise use explicit `--model`, then `unknown`; never guess. The exit code
describes executor infrastructure, not product status. A valid product `FAIL`
may accompany any executor exit code.

Fixture success is separate from product success. `lease.json` records exact
resource ownership, while `cleanup.json` records forced teardown. A product
`PASS` with failed fixture cleanup retains the product observation but makes
the overall execution `INFRA_ERROR`; validation and packaging must reject the
run until the leak is reconciled.

<a id="report-result-json"></a>
## 7. Shallow `result.json`

Before exiting, the agent atomically writes:

```json
{
  "schema_version": "1.0",
  "case_id": "tc-gw-pp-001",
  "status": "PASS",
  "summary": "Gateway forwarded the Proxy v1 address to the PP-enabled application port.",
  "steps": [
    {
      "id": "tc-gw-pp-001-step-01",
      "status": "PASS",
      "observed": "Gateway's cached port 8443 policy had pp=true."
    },
    {
      "id": "tc-gw-pp-001-step-02",
      "status": "PASS",
      "observed": "The capture backend was ready and initially contained zero records."
    }
  ],
  "artifacts": [
    {
      "name": "Backend capture",
      "path": "artifacts/backend-capture.json"
    }
  ],
  "remarks": ""
}
```

Constraints:

- status is `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN`, or `SKIPPED`;
- `PARTIAL` is forbidden;
- `PASS` requires at least one step and all steps must be `PASS`;
- step IDs must come from `case.md`;
- `observed` is a concise observation, not copied raw command output;
- artifact paths must remain inside the result directory; and
- results must not contain tokens, private keys, or other secrets.

<a id="report-artifacts"></a>
## 8. Attachments

Put screenshots, long logs, JSON responses, and binary captures under `artifacts/`; reference them by name and relative path in `result.json`. Generate `SHA256SUMS` during finalization. The renderer displays images inline, shows text and JSON in collapsible blocks, and provides embedded download links for other files. Absolute paths and `..` traversal are forbidden.

<a id="report-run-json"></a>
## 9. Run summary

After all cases, `dstack-test finalize` scans case outputs and generates `run.json`:

```json
{
  "schema_version": "1.0",
  "id": "run-20260723-001",
  "anchor": "run-20260723-001",
  "plan_id": "dstack-v0-6-0-release",
  "status": "COMPLETED",
  "started_at": "2026-07-23T18:00:00.000Z",
  "finished_at": "2026-07-23T20:00:00.000Z",
  "executors": [{"type": "codex", "model": "gpt-5-codex"}],
  "software_under_test": {
    "repository": "Dstack-TEE/dstack",
    "candidate": "0123456789abcdef",
    "previous_release": "v0.5.11"
  },
  "environment": {"level": "INTEGRATION", "simulated": true},
  "summary": {
    "total": 1,
    "completed": 1,
    "by_status": {
      "PASS": {"count": 1, "case_refs": ["#result-tc-gw-pp-001"]},
      "FAIL": {"count": 0, "case_refs": []},
      "BLOCKED": {"count": 0, "case_refs": []},
      "NOT_RUN": {"count": 0, "case_refs": []},
      "SKIPPED": {"count": 0, "case_refs": []}
    }
  },
  "case_results": [
    {
      "id": "tc-gw-pp-001",
      "anchor": "result-tc-gw-pp-001",
      "status": "PASS",
      "result_path": "../../01-gateway/01-proxy-protocol/tc-gw-pp-001/results/run-20260723-001/result.json"
    }
  ]
}
```

Supply common versions and environment data through `--context <json>`. Put exceptional component versions in the relevant case result only.

<a id="report-validation"></a>
## 10. Validation

```bash
dstack-test validate --plan <plan> --run-id <run-id>
```

Validation must cover at least:

1. plan paths, IDs, anchors, and index order;
2. one JSON object per non-empty session line;
3. required runner/result files and matching case/run IDs;
4. consistent case and step statuses;
5. safe, existing artifact paths;
6. recomputable run statistics;
7. no missing case in a completed run; and
8. complete and correct `SHA256SUMS` files.
9. released fixture leases and successful cleanup for every fixture-backed case.

<a id="report-package"></a>
## 11. Packaging

```bash
dstack-test package \
  --plan <plan> \
  --run-id <run-id> \
  --output <plan-id>-<run-id>.tar.gz
```

Supported formats are `.tar.gz`, `.tgz`, `.tar`, and `.zip`. Validate before packaging. Include the complete plan and selected run, but exclude every other historical run stored beside it.

<a id="report-html"></a>
## 12. Self-contained HTML

```bash
dstack-test render \
  --plan <plan> \
  --run-id <run-id> \
  --output report.html
```

The output must work offline and inline all CSS, JavaScript, session events, text, JSON, images, and downloadable attachments. It must provide:

- chapter/section/case navigation;
- the original guide and `case.md` requirements;
- common versions, environment, and executor model;
- status summaries, search, and status filters;
- each case summary and step observation;
- step-to-session-event links;
- collapsible original agent messages, tool calls, command output, and errors;
- every attachment and the complete raw session; and
- stable cross-reference anchors.

<a id="report-live-dashboard"></a>
## 13. Live and historical dashboard

`run-plan --web` starts a read-only HTTP dashboard for case status and the
native JSONL output of the orchestrator and every case agent. The browser polls
incremental byte ranges so active output appears without rewriting session
files. `dstack-test serve --plan <plan> --run-id <run-id>` exposes the same view
for a completed or interrupted run. The server has no built-in authentication;
non-loopback binding is permitted only on a trusted network or behind an
authenticated tunnel.

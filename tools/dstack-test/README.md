<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# dstack-test

`dstack-test` runs each indexed test case in a fresh Codex or Claude session,
preserves the agent's native JSONL event stream, validates shallow case
summaries, materializes run-level statistics, packages results, and renders one
self-contained interactive HTML report.

## Run one case

```bash
tools/dstack-test/dstack-test run-case \
  --plan path/to/plan \
  --case tc-gw-pp-001 \
  --workdir "$PWD" \
  -- "Do not restart the physical host"
```

The executor defaults to Codex; use `--agent claude` for Claude Code. The run ID
is generated when `--run-id` is omitted. Additional CLI options may be passed
with repeatable `--agent-arg`. The runner writes only below:

```text
<case>/results/<run-id>/
├── prompt.md
├── session.jsonl
├── agent-stderr.log
├── runner.json
├── result.json            # written by the agent
├── artifacts/
└── SHA256SUMS
```

## Run the indexed plan

```bash
tools/dstack-test/dstack-test run-plan \
  --plan path/to/plan \
  --context run-context.json \
  --web \
  -- "Follow the environment restrictions in README.md"
```

`run-plan` starts one orchestration-agent session. The agent drives the loop by
calling `next-case`, followed by either `run-case` or `complete-case`, until the
server reports `COMPLETE`. A file-based control channel lets the outer runner
launch each case agent outside the orchestrator sandbox. When a prior non-PASS
result demonstrably invalidates a later prerequisite, the orchestrator records
that case as `SKIPPED`; it must not skip independent or merely expensive cases.
The complete control conversation is stored in `orchestrator.jsonl`.

An interrupted run can be continued with the same run ID and `--resume`.

`--web` starts a read-only live dashboard on `127.0.0.1` and an automatically
selected port. Use `--web-host 0.0.0.0 --web-port 8000` for remote access;
there is no built-in authentication, so expose it only on a trusted network or
through an authenticated tunnel. The dashboard shows case status and polls the
native orchestrator/case JSONL files for near-real-time output.

After a run has finished, serve the same historical sessions with:

```bash
tools/dstack-test/dstack-test serve \
  --plan path/to/plan --run-id run-20260723-001 \
  --host 127.0.0.1 --port 8000
```

## Finalize and validate

```bash
tools/dstack-test/dstack-test finalize \
  --plan path/to/plan --run-id run-20260723-001 \
  --context run-context.json

tools/dstack-test/dstack-test validate \
  --plan path/to/plan --run-id run-20260723-001
```

## Package and render

```bash
tools/dstack-test/dstack-test package \
  --plan path/to/plan --run-id run-20260723-001 \
  --output report.tar.gz

tools/dstack-test/dstack-test render \
  --plan path/to/plan --run-id run-20260723-001 \
  --output report.html
```

The renderer uses only the Python standard library. The generated HTML embeds
all CSS, JavaScript, raw session events, text, JSON, images, and downloadable
binary artifacts. It has a chapter/section/case table of contents, status
filters, search, cross-reference anchors, and interactive expansion of raw
session evidence.

`package` includes the plan and the selected run only; results from other run
IDs are deliberately excluded.

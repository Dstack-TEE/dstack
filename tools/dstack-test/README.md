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
  --agent codex \
  --plan path/to/plan \
  --case tc-gw-pp-001 \
  --run-id run-20260723-001 \
  --workdir "$PWD" \
  -- "Do not restart the physical host"
```

Use `--agent claude` for Claude Code. Additional CLI options may be passed with
repeatable `--agent-arg`. The runner writes only below:

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
  --agent codex \
  --plan path/to/plan \
  --run-id run-20260723-001 \
  --context run-context.json \
  -- "Follow the environment restrictions in README.md"
```

Every case receives an independent agent session. `run-plan` continues after an
agent/runner failure and finalizes an `INCOMPLETE` run when necessary.

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

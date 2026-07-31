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
<plan>/results/<run-id>/cases/<chapter>/<section>/<case-id>/
├── prompt.md
├── session.jsonl
├── agent-stderr.log
├── runner.json
├── execution.json         # RUNNING/COMPLETED/INCOMPLETE/TERMINATED lifecycle
├── result.json            # written by the agent
├── evidence.jsonl         # generated PASS evidence and attachment index
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
By default, every existing terminal or incomplete case remains part of the prior
results and only unresolved cases run. For a repair round, repeat `--skip
STATUS` to retain only selected statuses and archive/rerun every other existing
case. For example, `--resume --skip PASS --skip SKIPPED` preserves successful
and intentionally skipped cases while rerunning `FAIL`, `BLOCKED`,
`INCOMPLETE`, and infrastructure-error cases. `--skip` requires `--resume` and
cannot be combined with `--overwrite`.

`--web` starts the same controllable dashboard as `serve` on `127.0.0.1` and an
automatically selected port, then starts the plan automatically. The printed
URL contains a generated control token; use `--control-token` to supply a
stable token. The dashboard can stop the automatic round and start a selected
repair queue. It remains available after automatic execution ends until the
process is interrupted. Use `--web-host 0.0.0.0 --web-port 8000` for remote
access, and expose the token-bearing URL only on a trusted network or through
an authenticated tunnel. The dashboard polls native orchestrator/case JSONL
files for near-real-time output.

After a run has finished, serve the same historical sessions with:

```bash
tools/dstack-test/dstack-test serve \
  --plan path/to/plan --run-id run-20260723-001 \
  --host 127.0.0.1 --port 8000
```

Unlike `run-plan --web`, `serve` is an interactive control server. The printed
URL contains a random control token in its URL fragment. The browser sends that
token only on start/stop requests. From the dashboard, select one or more cases,
optionally add a prompt, enable root-cause investigation, and start a sequential
queue. The current case process group can be terminated without stopping the
server. Rerunning an existing case requires an explicit checkbox; the old result
directory is atomically archived below
`<plan>/results/<run-id>/attempts/<chapter>/<section>/<case-id>/` before execution.

For a stable token or a remote controller, pass `--control-token`. Keep the
fragment-bearing URL private even when the read-only dashboard is exposed by a
tunnel.

For each valid case result, the runner derives `evidence.jsonl` from successful
step summaries, successful native command events, and the files explicitly
referenced by `result.json`. Command records contain an output excerpt plus the
full-output SHA-256 and native session line reference. Attachment records point
to files under `artifacts/`; the live UI renders their metadata, downloads, and
inline image previews.

Agents identify the purpose of proof-producing commands with
`EVIDENCE <step-id> - <what this command/output proves>`. The runner associates
that note and subsequent command events with the owning step. Attachments use
the same `step_id` plus a required descriptive annotation in
`artifacts/manifest.json`. The dashboard displays every annotation as
**Proves:** metadata and links it back to the corresponding step result.

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

<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<a id="dstack-test-report-output-spec"></a>
# dstack 测试报告输出规范

本文规定 AI执行会话、用例总结、run汇总、附件、引用、打包和单文件HTML的格式。测试方法见[dstack 测试方法](dstack-test-methodology.md#dstack-test-methodology)，用例格式见[测试用例编写规范](test-case-authoring-spec.md#dstack-test-case-authoring-spec)。

<a id="report-principles"></a>
## 1. 输出原则

1. 每条用例由一个独立Codex或Claude会话执行；
2. Agent原生JSONL会话是命令、tool call和原始输出的主要证据；
3. Agent只写一个浅层`result.json`，不在其中复制命令输出；
4. `runner.json`、run汇总、时间、退出码和摘要由工具生成；
5. 公共版本与环境只在run顶层记录；
6. 截图、日志和二进制文件作为独立附件；
7. 所有产物保留稳定锚点并可内联为单个HTML文件。

<a id="report-command-style"></a>
## 2. 统一命令

工具对外统一命名为`dstack-test`：

```bash
dstack-test run-case
dstack-test run-plan
dstack-test finalize
dstack-test validate
dstack-test package
dstack-test render
```

参数统一使用kebab-case。Agent通过`--agent codex`或`--agent claude`选择，不使用独立的`--codex`、`--claude`开关。

<a id="report-run-case"></a>
## 3. 单用例执行

```bash
dstack-test run-case \
  --agent codex \
  --plan path/to/plan \
  --case tc-gw-pp-001 \
  --run-id run-20260723-001 \
  --workdir path/to/repository \
  -- "附加执行要求"
```

runner自动把顶层说明书、`case.md`、结果目录、统一状态规则和总结schema加入Agent prompt。Agent必须先读说明书，再按用例执行；不得修改Plan规格。

<a id="report-layout"></a>
## 4. 结果目录

```text
<case>/results/<run-id>/
├── prompt.md
├── session.jsonl
├── agent-stderr.log
├── runner.json
├── result.json
├── artifacts/
└── SHA256SUMS

<plan>/results/<run-id>/
├── context.json          # 可选
├── run.json
└── SHA256SUMS
```

不同用例写不同目录，因此可以并行执行。已存在的非空run目录默认不得覆盖；显式重跑需使用`--overwrite`。

<a id="report-session-jsonl"></a>
## 5. `session.jsonl`

runner直接保存Agent CLI的原生事件流：

- Codex：`codex exec --json`；
- Claude：`claude --print --verbose --output-format stream-json`。

每行必须是一个完整JSON对象。runner不改写或摘要stdout中的事件。命令、tool call、tool result、Agent消息和错误均保留在会话中。Claude和Codex格式不同，由HTML渲染器的adapter在读取时统一展示，原文件保持不变。

Agent应在步骤开始和结束的消息中包含完整step ID，例如：

```text
[DSTACK-TEST-STEP-START tc-gw-pp-001-step-01]
[DSTACK-TEST-STEP-END tc-gw-pp-001-step-01 PASS]
```

渲染器据此链接步骤与会话事件。没有标记时，可搜索step ID；仍找不到时显示`WHOLE_SESSION_FALLBACK`，并保留整个会话作为证据。

<a id="report-runner-json"></a>
## 6. `runner.json`

`runner.json`只能由`dstack-test`生成：

```json
{
  "schema_version": "1.0",
  "run_id": "run-20260723-001",
  "case_id": "tc-gw-pp-001",
  "agent": {
    "type": "codex",
    "model": "gpt-5.4"
  },
  "session": {
    "format": "codex-jsonl",
    "path": "session.jsonl",
    "events": 137
  },
  "prompt_path": "prompt.md",
  "result_path": "result.json",
  "started_at": "2026-07-23T08:10:00.000Z",
  "finished_at": "2026-07-23T08:17:15.000Z",
  "duration_ms": 435000,
  "exit_code": 0,
  "result_valid": true,
  "result_error": null
}
```

模型名优先从会话事件提取，其次使用显式`--model`，否则填写`unknown`，不得猜测。

runner退出码描述Agent执行基础设施，不等于测试状态。Agent正常完成且写出合法`FAIL`结果时，runner仍可成功退出。

<a id="report-case-json"></a>
## 7. 浅层 `result.json`

Agent在结束前原子写入：

```json
{
  "schema_version": "1.0",
  "case_id": "tc-gw-pp-001",
  "status": "PASS",
  "summary": "Gateway解析入站Proxy v1地址并向启用PP的应用端口正确转发。",
  "steps": [
    {
      "id": "tc-gw-pp-001-step-01",
      "status": "PASS",
      "observed": "Gateway缓存中的端口8443配置为pp=true。"
    },
    {
      "id": "tc-gw-pp-001-step-02",
      "status": "PASS",
      "observed": "后端记录已清空，初始记录数为0。"
    }
  ],
  "artifacts": [
    {
      "name": "backend-capture",
      "path": "artifacts/backend-capture.json"
    }
  ],
  "remarks": ""
}
```

约束：

- 状态只能是`PASS`、`FAIL`、`BLOCKED`、`NOT_RUN`或`SKIPPED`；
- 不得使用`PARTIAL`；
- `PASS`要求至少一个步骤，且所有步骤均为`PASS`；
- step ID必须来自`case.md`；
- `observed`只写简短观察总结，不复制命令原文；
- artifact路径必须位于本次结果目录内；
- 不能嵌入token、私钥或密钥材料。

<a id="report-artifacts"></a>
## 8. 附件

截图、长日志、JSON响应和二进制捕获写入`artifacts/`。`result.json`只保存名称和相对路径。finalize阶段生成`SHA256SUMS`；HTML根据MIME类型：

- 图片：内联展示并提供下载；
- 文本和JSON：默认折叠展示原文；
- 其他二进制：内联为data URI下载链接。

附件不能使用绝对路径或`..`逃逸结果目录。

<a id="report-run-json"></a>
## 9. `run.json`

全部用例结束后，`dstack-test finalize`扫描各用例结果并生成：

```json
{
  "schema_version": "1.0",
  "id": "run-20260723-001",
  "anchor": "run-20260723-001",
  "plan_id": "plan-gateway-proxy-protocol",
  "status": "COMPLETED",
  "started_at": "2026-07-23T08:10:00.000Z",
  "finished_at": "2026-07-23T09:12:00.000Z",
  "executors": [
    {"type": "codex", "model": "gpt-5.4"}
  ],
  "software_under_test": {},
  "environment": {},
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

公共软件版本和环境由`--context <json>`提供。只有特殊旧版组件写入单用例`version_overrides`。

<a id="report-validation"></a>
## 10. 校验

```bash
dstack-test validate --plan <plan> --run-id <run-id>
```

至少校验：

1. Plan目录、ID、锚点和索引顺序；
2. `session.jsonl`每个非空行均为JSON对象；
3. `runner.json`和`result.json`存在且case/run ID一致；
4. 用例和步骤状态一致；
5. artifact路径合法且文件存在；
6. 顶层统计可由用例结果重新计算；
7. 完成run不存在缺失用例；
8. `SHA256SUMS`与文件内容一致。

<a id="report-package"></a>
## 11. 打包

```bash
dstack-test package \
  --plan <plan> \
  --run-id <run-id> \
  --output <plan-id>-<run-id>.tar.gz
```

支持`.tar.gz`、`.tgz`、`.tar`和`.zip`。工具必须先校验，再打包完整Plan及指定run结果；
不得夹带同一Plan下其他历史run的结果。

<a id="report-html"></a>
## 12. 单文件HTML

```bash
dstack-test render \
  --plan <plan> \
  --run-id <run-id> \
  --output report.html
```

HTML必须离线可用并内联全部CSS、JavaScript、会话事件、文本、JSON、图片和可下载附件。展示内容包括：

- 章／节／用例三级目录；
- 测试说明书和`case.md`原始要求；
- 公共版本、环境和Agent模型；
- 状态统计、搜索和状态过滤；
- 每条用例总结及逐步observed结果；
- step到对应会话事件的跳转；
- 原始Agent消息、tool call、命令输出和错误的交互式折叠；
- 所有附件；
- 完整原始会话折叠区；
- 稳定交叉引用锚点。

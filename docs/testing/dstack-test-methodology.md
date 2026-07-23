<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<a id="dstack-test-methodology"></a>
# dstack 测试方法

本文规定 dstack 版本测试从需求分析、风险建模、用例设计、环境执行、证据采集到发布判定的统一方法。具体用例格式见[测试用例编写规范](test-case-authoring-spec.md#dstack-test-case-authoring-spec)，执行产物格式见[测试报告输出规范](test-report-output-spec.md#dstack-test-report-output-spec)。

<a id="methodology-goals"></a>
## 1. 目标

测试应当提供可重复、可审计且可追踪的发布证据，而不只是证明某个脚本曾经退出为零。任一结论都应能从需求或风险追踪到用例、步骤、命令原文、观察结果和附件。

测试工作的完成条件是：

1. 版本变化、产品需求和主要风险均有明确测试覆盖；
2. 测试规格可由不了解实现细节的执行者独立复现；
3. 每一步实际执行的命令、退出码、标准输出和标准错误均保存；
4. 模拟测试和真实硬件测试分别报告，不能互相替代；
5. 汇总状态可由工具从原子结果重新计算；
6. 报告中的引用、附件摘要和统计均可机器校验。

<a id="methodology-artifacts"></a>
## 2. 测试资料分层

测试资料分为四类，禁止混写：

| 资料 | 作用 | 是否随执行变化 |
|---|---|---|
| 测试说明 `README.md` | 范围、环境配置、公共前置条件、执行与清理方法 | 否 |
| 测试索引 `index.json` | 章、节、用例顺序及机器可读引用 | 否 |
| 用例规格 `case.md` | 单条用例的目标、前置条件、数据、步骤和预期结果 | 否 |
| 执行结果 `results/<run-id>/` | 实际版本、命令证据、观察结果、附件和状态 | 是 |

测试规格是只读输入。执行器只能在 `results/` 下创建当前 run 的产物，不得根据执行结果反向修改预期结果。

<a id="methodology-organization"></a>
## 3. 组织结构

测试计划固定使用“章／节／用例”三个层级。每条用例必须拥有独立目录，便于附带 fixture、脚本和多次执行结果。

```text
<plan>/
├── index.json
├── README.md
├── schemas/
├── results/<run-id>/run.json
└── <chapter>/
    └── <section>/
        └── <case-id>/
            ├── case.md
            ├── fixtures/       # 可选
            ├── scripts/        # 可选
            └── results/<run-id>/
```

目录名建议使用两位数字前缀维持人工浏览顺序；权威执行顺序仍来自 `index.json`，执行器不得通过文件名猜测顺序。

<a id="methodology-input-analysis"></a>
## 4. 测试输入分析

在编写用例前，测试负责人应收集并冻结：

- 上一个发布版本及本次候选 revision；
- change log、PR、schema、RPC 和配置变化；
- 产品需求及用户场景；
- 安全不变量和信任边界；
- 已知缺陷、迁移约束和运维方式；
- 可用的真实硬件、模拟器与外部服务。

每项变化至少回答：谁使用它、正常行为是什么、错误输入如何处理、升级时如何兼容、失败后如何恢复、会影响哪些旧功能。

<a id="methodology-traceability"></a>
## 5. 追踪与覆盖

每条用例应引用至少一个需求或风险。推荐维护以下关系：

```text
Change / Requirement / Risk
             ↓
          Test case
             ↓
            Step
             ↓
      Command and output
             ↓
         Assertion/result
```

覆盖审计至少包含：

1. 新增和改变的功能；
2. 受影响功能的回归；
3. 新旧组件组合兼容；
4. 配置和 API 的合法、边界及错误输入；
5. 有状态组件的创建、运行、停止、重启、升级、回滚和恢复；
6. 安全策略的允许、拒绝及恢复；
7. 并发、隔离、幂等和重试；
8. 资源耗尽、依赖不可用和网络故障；
9. 可观测性、错误信息及审计记录。

覆盖数量不是质量指标。一个包含多个独立断言的大用例应拆为若干原子用例，否则失败无法定位，结果也无法准确统计。

<a id="methodology-environments"></a>
## 6. 环境等级

执行报告必须标记环境等级：

| 等级 | 说明 |
|---|---|
| `UNIT` | 单进程或模块测试 |
| `INTEGRATION` | 多组件集成，但不使用模拟硬件证据代替真实平台 |
| `SIMULATED` | mock attestation、no-TEE、swtpm 等模拟环境 |
| `REAL_SGX` | 真实 SGX enclave |
| `REAL_TDX` | 真实 TDX CVM |
| `REAL_PLATFORM` | 指定 NVIDIA、GCP、AWS、SEV-SNP 等真实平台 |

用例规格必须声明最低环境。若只在较低等级执行，原用例保持 `NOT_RUN` 或 `BLOCKED`，模拟结果应记录在单独用例中。

<a id="methodology-status"></a>
## 7. 状态与判定

状态枚举固定为：

- `PASS`：所有步骤的实际结果完全满足预期；
- `FAIL`：至少一步实际结果不完全满足预期；
- `BLOCKED`：外部环境或前置条件阻止被测行为开始；
- `NOT_RUN`：尚未执行；
- `SKIPPED`：预先定义的适用条件不成立。

单个用例不使用 `PARTIAL`。若一部分断言通过、一部分未执行，应拆分用例或将该用例判为非 `PASS`。顶层汇总必须由用例结果计算，不能手工覆盖。

<a id="methodology-execution"></a>
## 8. 标准执行流程

AI或人工执行器应按以下顺序工作：

1. 阅读顶层 `README.md`；
2. 读取并校验 `index.json`、schema、路径、锚点和引用；
3. 创建唯一 `run_id`，记录执行器、公共版本和环境；
4. 按索引顺序逐章、逐节、逐用例读取 `case.md`；
5. 为每条用例启动独立AI会话，验证前置条件并执行各步骤；
6. runner将Agent原生JSONL事件流直接保存为`session.jsonl`，其中包含实际tool call、命令和原始输出；
7. 将观察结果与预期逐项比较，结束前原子写入浅层`result.json`；
8. 执行用例后置条件，记录未能清理的资源；
9. 全部完成后重新校验会话、结果、附件摘要、引用和统计；
10. 生成顶层`run.json`、`SHA256SUMS`，再打包上传或渲染HTML。

AI执行器必须记录实际提供方、产品和模型名称；无法从运行环境确认模型时填写 `unknown`，不得猜测。

<a id="methodology-evidence"></a>
## 9. 证据原则

每一步至少包含一条实际执行的命令证据。命令和输出由Agent原生
`session.jsonl`保存，不要求AI再次复制或转义。会话应包含：

- 未经改写的命令字符串和工作目录；
- 已脱敏的环境变量；
- UTC开始、结束时间和退出码；
- stdout、stderr原文；
- 从原文提取的结构化 observed 值；
- 截图、日志或二进制捕获附件及 SHA-256。

额外的截图、长日志或二进制捕获写入`artifacts/`并由`result.json`引用；
`result.json`只保存逐步观察总结，不嵌入大段输出。密钥、token、私钥和用户数据
不得进入会话或附件；脱敏必须保留字段存在性和数据形状，且在报告中声明。

<a id="methodology-versioning"></a>
## 10. 版本与环境记录

公共被测版本只在 run 顶层记录一次，包括 Git revision、binary SHA-256、container digest 和 guest image digest。单个用例只在使用旧版或特殊构件时设置 `version_overrides`。

环境记录至少包括：主机标识、内核、CPU架构、TEE能力、模拟标志、关键外部服务及配置摘要。路径和主机名如涉及隐私，可使用稳定别名，但必须足以复现拓扑。

<a id="methodology-release-decision"></a>
## 11. 发布判定

发布结论应直接引用未通过的 P0/P1 用例及未覆盖需求。以下情况不得表述为“全量通过”：

- P0 用例为 `FAIL`、`BLOCKED` 或 `NOT_RUN`；
- 真实硬件要求仅由模拟测试覆盖；
- 关键附件缺失或摘要不匹配；
- 结果引用失效；
- 执行偏离规格且未记录 deviation；
- 公共版本未固定到可追溯 digest。

<a id="methodology-rendering"></a>
## 12. 打包和展示

规范 Plan目录是平台和本地渲染器的唯一输入。推荐命令：

```bash
dstack-test render \
  --plan path/to/plan \
  --run-id run-20260723-001 \
  --output report.html
```

渲染前必须完成结构、引用、状态、统计和附件摘要校验。生成的 HTML应内联样式、脚本、JSON、文本、图片和可下载附件，不依赖网络资源。

<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<a id="dstack-test-case-authoring-spec"></a>
# dstack 测试用例编写规范

本文规定测试 Plan、索引和 `case.md` 的写法。总体方法见[dstack 测试方法](dstack-test-methodology.md#dstack-test-methodology)，结果格式见[测试报告输出规范](test-report-output-spec.md#dstack-test-report-output-spec)。

<a id="authoring-plan-layout"></a>
## 1. Plan目录

```text
<plan>/
├── index.json
├── README.md
├── schemas/
├── results/
└── <chapter>/
    ├── README.md             # 可选
    └── <section>/
        ├── README.md         # 可选
        └── <case-id>/
            ├── case.md
            ├── fixtures/     # 可选
            ├── scripts/      # 可选
            └── results/
```

测试组织只允许章、节、用例三个语义层级。用例必须放在独立目录中，规格文件固定命名为 `case.md`。

<a id="authoring-identifiers"></a>
## 2. ID和锚点

所有可引用对象必须使用显式、稳定、全局唯一的 ASCII ID：

```text
chapter-gateway
section-gateway-proxy-protocol
tc-gw-pp-001
tc-gw-pp-001-step-01
req-gw-pp-inbound-v1
risk-gw-pp-client-address
```

规则：

- 仅使用小写字母、数字和连字符；
- ID发布后不得因标题变化而改变；
- Markdown不得依赖标题自动生成的 slug；
- 每个可引用标题前必须写 `<a id="..."></a>`；
- 跨文件引用使用相对路径和 fragment，例如 `case.md#tc-gw-pp-001-step-01`。

<a id="authoring-readme"></a>
## 3. 顶层说明书

顶层 `README.md`是执行器必须首先阅读的文件，至少包含：

1. 测试目标和范围；
2. 被测系统和测试拓扑；
3. 硬件、软件、账号及外部服务要求；
4. 公共环境配置命令；
5. 公共前置条件和健康检查；
6. 状态判定规则；
7. 证据、脱敏和附件规则；
8. 执行顺序、并发限制和停止条件；
9. 清理与环境恢复方法；
10. 打包、上传和本地渲染方法。

环境配置命令应可直接执行；不得使用“配置好KMS”“准备可用证书”等无法复现的描述。

<a id="authoring-index"></a>
## 4. `index.json`

索引是用例发现和顺序的权威来源。最低结构如下：

```json
{
  "schema_version": "1.0",
  "id": "plan-gateway-proxy-protocol",
  "title": "Gateway Proxy Protocol Test Plan",
  "guide": {
    "path": "README.md",
    "anchor": "test-plan-guide"
  },
  "chapters": [
    {
      "id": "chapter-gateway",
      "order": 1,
      "title": "Gateway",
      "path": "01-gateway",
      "sections": [
        {
          "id": "section-gateway-proxy-protocol",
          "order": 1,
          "title": "Proxy Protocol",
          "path": "01-gateway/01-proxy-protocol",
          "cases": [
            {
              "id": "tc-gw-pp-001",
              "order": 1,
              "title": "TLS终止路径转发Proxy v1地址",
              "priority": "P0",
              "path": "01-gateway/01-proxy-protocol/tc-gw-pp-001",
              "spec": {
                "path": "01-gateway/01-proxy-protocol/tc-gw-pp-001/case.md",
                "anchor": "tc-gw-pp-001"
              },
              "requirements": ["req-gw-pp-inbound-v1"],
              "risks": ["risk-gw-pp-client-address"],
              "tags": ["gateway", "proxy-protocol", "e2e"]
            }
          ]
        }
      ]
    }
  ]
}
```

章、节和用例数组顺序必须与 `order`一致。路径必须留在 Plan根目录内，不得包含绝对路径或 `..`逃逸。

<a id="authoring-case-sections"></a>
## 5. `case.md`固定结构

每条用例按以下顺序编写：

```markdown
<a id="tc-example-001"></a>
# TC-EXAMPLE-001：标题

<a id="tc-example-001-metadata"></a>
## 元数据

<a id="tc-example-001-objective"></a>
## 测试目标

<a id="tc-example-001-preconditions"></a>
## 前置条件

<a id="tc-example-001-data"></a>
## 测试数据

<a id="tc-example-001-steps"></a>
## 测试步骤

<a id="tc-example-001-step-01"></a>
### Step 1：步骤标题

操作说明。

**预期结果：**

- 可观察结果一；
- 可观察结果二。

<a id="tc-example-001-cleanup"></a>
## 后置条件
```

<a id="authoring-metadata"></a>
## 6. 元数据

元数据至少包含：

- ID；
- 优先级 `P0`、`P1`或`P2`；
- 类型，例如 Functional、Security、Compatibility、Regression、Performance；
- 最低环境等级；
- 是否适合自动化；
- Requirement和Risk引用；
- Tags。

公共版本不在每条用例重复。需要旧版或特殊组件时，在用例中增加“特殊版本要求”，执行结果写入 `version_overrides`。

<a id="authoring-objective"></a>
## 7. 测试目标

目标只描述一个可独立判定的行为。若标题中出现多个互不依赖的“并且”，通常应拆分用例。目标需要说明：

- 什么配置或状态；
- 执行什么行为；
- 对外可观察的核心结果。

不得把实现函数名或已有测试脚本退出零当作产品目标。

<a id="authoring-preconditions"></a>
## 8. 前置条件

前置条件必须可验证并区分于测试步骤。每项应说明所需状态，而不是隐含测试结果。公共环境条件写在顶层说明书，用例只写本用例特有条件。

若前置条件失败，执行器记录命令证据并把用例标为 `BLOCKED`；不能把 setup错误记为产品 `FAIL`。

<a id="authoring-test-data"></a>
## 9. 测试数据

测试数据优先使用 JSON代码块，固定协议字段、边界值和预期值。随机数据必须说明生成方式并在结果中保存实际值。安全测试地址应使用 RFC文档网段，避免依赖执行主机随机地址。

<a id="authoring-steps"></a>
## 10. 步骤和预期结果

每条用例推荐 3至8个逻辑步骤。一个步骤可以执行多条机械命令，但只验证一个阶段性结果。每一步必须：

1. 有显式锚点；
2. 描述执行动作；
3. 描述可观察、可比较的预期结果；
4. 能产生至少一条命令证据。

不单独编写失败判据：只要实际结果没有完全满足预期，该步骤即为 `FAIL`，用例即为 `FAIL`。

避免使用“正常”“正确”“无异常”等模糊结果，应写为具体状态、字段、地址、摘要、计数或响应码。

<a id="authoring-cleanup"></a>
## 11. 后置条件

后置条件描述：

- 清除哪些测试数据；
- 停止或保留哪些服务；
- 如何恢复修改的 policy和配置；
- 哪些状态供后续用例复用；
- 清理失败时如何记录。

<a id="authoring-proxy-example"></a>
## 12. Proxy Protocol样例

````markdown
<a id="tc-gw-pp-001"></a>
# TC-GW-PP-001：启用PP的应用端口接收正确客户端地址

<a id="tc-gw-pp-001-objective"></a>
## 测试目标

验证Gateway启用Inbound Proxy Protocol且应用端口声明`pp=true`时，
上游Proxy v1客户端地址被转发给应用，后续HTTP请求正常完成。

<a id="tc-gw-pp-001-preconditions"></a>
## 前置条件

1. Gateway配置`inbound_pp_enabled=true`。
2. guest已注册，端口8443配置`pp=true`。
3. capture backend ready，Gateway已加载该instance的port policy。

<a id="tc-gw-pp-001-data"></a>
## 测试数据

```json
{
  "source": "198.51.100.27:45678",
  "destination": "203.0.113.10:443",
  "app_port": 8443
}
```

<a id="tc-gw-pp-001-steps"></a>
## 测试步骤

<a id="tc-gw-pp-001-step-01"></a>
### Step 1：检查生效策略

查询guest和Gateway中的端口策略。

**预期结果：** Instance ID正确，端口8443存在且`pp=true`。

<a id="tc-gw-pp-001-step-02"></a>
### Step 2：清理后端记录

清除capture backend历史记录。

**预期结果：** backend ready且记录数为0。

<a id="tc-gw-pp-001-step-03"></a>
### Step 3：发送请求

发送Proxy v1 header，在同一连接完成TLS和HTTP请求。

**预期结果：** TLS成功，HTTP返回200，request ID匹配。

<a id="tc-gw-pp-001-step-04"></a>
### Step 4：检查捕获结果

查询capture backend记录。

**预期结果：** 恰好一条新记录，source和destination与测试数据一致，HTTP请求完整。
````

<a id="authoring-review-checklist"></a>
## 13. 评审清单

提交前确认：

- 用例目录、ID和索引一致；
- 显式锚点存在且唯一；
- 每条用例引用需求或风险；
- 目标只有一个核心行为；
- 前置条件可验证；
- 每一步有精确预期；
- 步骤数量合理且能产生原始证据；
- 模拟和真实硬件要求明确；
- 后置条件可恢复环境；
- 不包含密钥、token和环境私密值。

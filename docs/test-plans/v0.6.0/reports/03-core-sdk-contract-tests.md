# Core、SDK 与合约测试报告

## Rust core

命令：`make core-test`  
结果：**PASS**（约 2m06s）

Workspace 与 doc tests 全部通过。与本版本高风险变化直接相关的覆盖包括 Event Log v1/v2、canonical JSON、混合格式 replay、API auth，以及 KMS/Gateway/VMM/attestation/key-provider 单元和集成测试。

## SDK

命令：`make sdk-test`  
结果：**PASS**

| SDK | 结果 |
|---|---|
| Rust | 13 + 1 + 9 tests 通过，并完成 `no_std` 检查 |
| Go | `dstack` 与 `tappd` package 全部通过 |
| Python | 119 passed；1 个 deprecation warning |
| JavaScript | 99 passed |
| Simulator API | Rust/JS/Python/Go 均成功交互 |

注意：这是 SDK 自身和 simulator API 覆盖，不等同于“旧 SDK × 新真实 guest/control plane”兼容性测试。JS 依赖审计报告 1 low、3 moderate。

## KMS auth JavaScript

| 项目 | 结果 |
|---|---|
| `auth-mock` | 12 PASS |
| `auth-simple` | 16 PASS |
| `auth-eth-bun` | 14 PASS |
| `auth-eth` | 4 PASS |

三个 Bun 项目的 `bun install --frozen-lockfile` 在 Bun 1.2.18/1.3.14 下失败，改用非 frozen install 后测试通过。因此功能断言通过，但可重复安装门禁失败。`auth-eth` 的 npm audit 为 2 low、1 moderate、3 high。

## Solidity / Foundry

命令：`forge test --ffi`  
结果：**PASS**，3 suites、54 tests、0 failures。

覆盖 two-step ownership transfer、proxy upgrade、storage/initialization compatibility、TCB policy 与 owner authorization。该结果完整支持 GKW-06 的合约层 rehearsal，但不代表所有部署链已执行链上升级。

# dstack v0.6.0 preview 测试执行摘要

> 冻结版本：`dc3b95117f518a752c0726ecd44ba7888a25cc49`（2026-07-22）  
> 对比基线：meta-dstack `v0.5.11`  
> 状态：**测试已执行；发布门禁尚未通过**

## 结论

当前自动化、模拟集成与合约测试未发现确定的产品功能失败。此前阻塞真实硬件测试的 Local-Key-Provider error 44 已定位为公共 PCCS 缺少本机 PCK certificate；使用已 provision 本机的 PCCS 后，production SGX Local-Key-Provider、真实 TDX KMS onboarding、v0.5.11/current 混合 guest 及双 Gateway rolling upgrade 均已走通。

发布预览版前仍必须关闭以下 P0 门禁：

1. 完成 COMP-01 的全 old service baseline 和 COMP-10 的物理 host reboot；COMP-02 的 v0.5.11→current VMM process 原地切换、COMP-07 的同 app 双版本并行隔离及 COMP-08/09 的 guest image upgrade/rollback 与 policy deny/recovery已补测通过；
2. 若发布门禁坚持要求 v0.5.11 KMS/Gateway/VMM，需先提供 release 未包含的可追溯 service artifacts；当前已完成的是确切 v0.5.11 guest 与 0.5.8→current service rolling upgrade；
3. 对真实 NVIDIA、GCP TDX、AWS NitroTPM、AMD SEV-SNP 环境完成硬件证明负向测试；
4. 处理或接受构建与依赖风险清单中的发布风险。

## 已执行套件

| 范围 | 结果 | 关键数字/说明 |
|---|---|---|
| Release Rust binaries | PASS | 11 个目标成功构建 |
| `make core-test` | PASS | workspace tests 与 doc tests 全部通过 |
| `make sdk-test` | PASS | Rust/Go/Python/JS；Python 119、JS 99 个测试通过 |
| Attestation Docker E2E | PASS (SIMULATED) | 6/6 平台，四个 verifier 判据均为 true |
| Gateway 三节点 E2E | PASS (SIMULATED) | 27 PASS / 0 FAIL；debug attestation |
| KMS JS auth | PASS | 12 + 16 + 14 + 4 个测试通过 |
| Foundry | PASS | 3 suites，54 PASS / 0 FAIL |
| VMM UI build | PASS | 构建成功，但有依赖与 CDN fallback 风险 |
| `prek run --all-files` | PASS | 所有 hook 通过 |
| REUSE | TEST-HARNESS ISSUE | 仅本地生成的 9 个短期证书缺少 SPDX 信息 |
| Yocto production image | FAIL / patched artifact built | 原样因 kernel-module-fuse packaging 失败；最小测试补丁后产物校验通过 |
| TDX mixed guest / rolling upgrade | PASS（限定范围） | production SGX Local-Key-Provider 重启持久性；v0.5.11/current guest；image upgrade/rollback；0.5.8→current KMS/Gateway；VMM service 故障恢复；key/SPKI/state/HA 连续性通过；完整 COMP-01..10 尚未全覆盖 |
| no-TEE + swtpm | FAIL (SIMULATED) | TPM/swtpm host 装配成功；dev guest 在进入 `/init` 前停止推进 |

## 结果解释

- **PASS**：执行步骤和断言完整满足用例。
- **PASS (SIMULATED)**：模拟证据通过，不代表真实平台通过。
- **PARTIAL**：只覆盖了用例的一部分断言。
- **FAIL**：已执行且产品断言失败。
- **BLOCKED**：当前本机缺少对应外部平台、硬件或确切旧版资料。
- **NOT RUN**：尚未执行，不能由相邻套件结果推断。

逐用例状态见 `07-test-case-matrix.md`；问题与发布建议见 `08-findings-and-risks.md`；模拟替代的完整边界见 `09-no-tee-swtpm-simulation-report.md`。

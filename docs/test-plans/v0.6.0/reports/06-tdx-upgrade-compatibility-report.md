# TDX rolling-upgrade 与旧版兼容性报告

## 执行入口与环境

```bash
DSTACK_E2E_QCNL_CONF=/etc/sgx_default_qcnl.conf \
DSTACK_E2E_SKIP_CURRENT_BUILD=true \
./test-suites/full-stack-compose/run-upgrade-e2e.sh
```

测试运行在具备真实 SGX 与 TDX 的主机上。AESMD 使用已为本机完成
provisioning 的本地 PCCS；Local-Key-Provider 运行 production SGX enclave，未使用
mock、debug enclave 或 `insecure_skip_attestation`。公共 PCCS 未包含本机 PCK
certificate，原 error 44 是 PCCS provisioning 问题，修复见 PR #819。

## 参与版本

- VMM、第二阶段 KMS/Gateway：冻结提交
  `dc3b95117f518a752c0726ecd44ba7888a25cc49`；
- 初始 KMS：digest-pinned `dstack-kms 0.5.8`；
- 初始 Gateway：digest-pinned `dstack-gateway 0.5.8`；
- 旧 guest：meta-dstack v0.5.11 release artifact，image digest
  `c2aa0186182fe8a404f16d5f3facb334d89be32703b3571c401b114a8b6e700d`；
- 新 guest：本次 v0.6.0 candidate，image digest
  `91bc72e3ca6f283cc0549d761ee436d381d1e8c4ddc4c23354e05c9bbccfdec1`。

meta-dstack v0.5.11 release 只提供 guest artifact，并不提供标记为 v0.5.11 的
KMS/Gateway release containers。因此本报告把 **guest image compatibility** 与
**0.5.8→current service rolling upgrade** 分开表述，不将后者伪称为 v0.5.11
KMS/Gateway 兼容测试。

## 已验证的真实硬件路径

第一次完整执行已到达最终 audit，并证明全部 runtime 阶段成功；其唯一失败是 harness
错误地假设 onboarding 后的两个 KMS 必须各自产生一次 archive HTTP GET。保存状态的
复核结果为 current GET=1、v0.5.11 GET=2；onboarding 会复制 durable state/cache，
所以“每 KMS 一次 GET”不是产品不变量。PR #820 修正该审计；随后从 clean state
完整复跑并明确输出 `production-compatible ... success` 与 `upgrade E2E success`。

已取得的运行态证据如下：

1. production SGX Local-Key-Provider enclave healthy；真实 TDX KMS CVM 报告
   `KeyProviderInfo { name: "local-sgx", id: "<SGX MRENCLAVE>" }`；
2. old KMS quote-enabled bootstrap，按真实 quote 的 `mrAggregated` 与物理 TDX
   device ID 精确授权；latest KMS 以 mutual RA-TLS onboarding；
3. onboarding 前后 KMS CA SPKI、root k256 public key、per-app environment public
   key逐字节一致；
4. v0.5.11 guest 使用 legacy manifest 启动、取得 key，并在切换 latest KMS 后重启；
   加密数据盘重新挂载；
5. current guest 以 TDX lite policy 启动并取得 key；allowlist 精确包含 old/current
   两个 OS hash，不存在关闭 image verification/self-authorization 的日志；
6. old/current guest 同时通过两个 Gateway 可达；两个 Gateway 逐节点从 0.5.8
   升到 current；
7. Gateway certificate、DNS credential 与 durable state 保持；升级后的两个节点均
   能用原 credential 强制重新签发证书；
8. clean rerun 的 rolling upgrade HA probe：4350 次请求、0 failures、1921 次成功
   failover，持续 253195 ms。
9. production SGX Local-Key-Provider 容器重启后，latest KMS CVM 被强制 stop/start；
   它重新取得 `local-sgx` key、挂载原加密数据盘，重启前后 KMS identity JSON
   SHA-256 均为 `09d697...a9056`，app-key JSON SHA-256 均为
   `56ff10...7c05e`；
10. 同一 legacy VM、app ID 与数据盘完成 v0.5.11→current→v0.5.11 image
    transition；两个方向均挂载相同 ext4 UUID
    `8ef37605-73d4-4790-a31a-6ff0dad2cd33`，并通过两个 Gateway；
11. 从 exact allowlist 临时删除 v0.5.11 OS hash 后，回滚 guest 在
    `requesting app keys` 阶段被明确拒绝：`Boot denied: os image not allowed`；恢复
    hash 后同一 VM、数据盘和两条 Gateway 路由恢复。

原始日志：

```text
/home/kvin/src/dstack-v060-artifacts/logs/full-stack-tdx-upgrade-e2e-v0511-mixed-final.log
/home/kvin/src/dstack-v060-artifacts/logs/full-stack-tdx-upgrade-e2e-v0511-mixed-exit0.log
/home/kvin/src/dstack-v060-artifacts/logs/full-stack-tdx-upgrade-e2e-lkp-persistence-base.log
/home/kvin/src/dstack-v060-artifacts/logs/lkp-persistence-image-upgrade-rollback-evidence.txt
```

## COMP 用例审计

| 用例 | 结论 | 本次覆盖与缺口 |
|---|---|---|
| COMP-01 | PARTIAL | 建立了 old service + v0.5.11 guest 的真实 key/TLS/storage 基线，但 VMM 不是 old，且 KMS/Gateway 基线是 0.5.8 |
| COMP-02 | NOT RUN | 未执行 old→new VMM 原地升级 |
| COMP-03 | PASS | v0.5.11 guest 切换 latest KMS 后重新启动、取 key；KMS identity 与 app key 保持 |
| COMP-04 | PASS | v0.5.11 guest 在两个 Gateway 完成 rolling upgrade 后仍可达，DNS/TLS/WireGuard 路径恢复 |
| COMP-05 | PASS | latest VMM 创建全新 v0.5.11 image CVM，legacy numeric manifest 被接受，之后可由 latest service 继续服务 |
| COMP-06 | PASS | latest VMM 创建 current image，TDX lite policy、exact image allowlist、key 与 Gateway 路径通过 |
| COMP-07 | PARTIAL | old/current guest 并行可达且使用独立 app ID；未执行计划要求的同 app image 双版本 identity crossover 专项断言 |
| COMP-08 | PASS | 同一 legacy VM/app ID/data disk 从 v0.5.11 更新为 current；原 ext4 UUID 挂载且双 Gateway 可达 |
| COMP-09 | PASS | 同一 VM 回滚 v0.5.11、原盘与路由恢复；删除 old hash 时明确 deny，恢复 policy 后恢复 |
| COMP-10 | PARTIAL | guest/KMS/Gateway 级 stop/start 与服务恢复有覆盖；未重启物理 host |

## 结论与边界

Local-Key-Provider 阻塞已经解除；真实 TDX 证据支持 v0.5.11/current 混合 guest、
Local-Key-Provider KMS onboarding、Gateway rolling upgrade 及密钥/状态连续性。它不支持
把 COMP-01..10 全部写成 PASS：old→latest VMM 原地升级、同 app 双 VM 并行交叉身份
和物理 host reboot 仍缺专项执行。模拟报告不能替代这些项目。

# Gateway 本地三节点集成报告

## 最终结果

结果：**PASS (SIMULATED)**，27 PASS / 0 FAIL。

覆盖：三节点 health、管理 token（missing 401、wrong 401、correct 200）、DNS credential、ZT domains、Pebble ACME 签发、WaveKV 证书同步、节点间证书一致性、SNI 证书选择和 TLS proxy health。

## 测试环境适配

仓库原始入口直接执行时暴露四个 harness 问题：

1. 固定默认端口已被占用；
2. 配置依赖不可达的远程 TDX guest-agent；
3. `kvin/mock-cf-dns-api:latest` 不支持代码所需 `/client/v4/zones` API；
4. `test_admin_auth()` 将 `log_info` stdout 混入 command substitution，导致真实 HTTP 状态为 401/401/200 时仍误判。

在隔离 worktree 中采用高位端口、本地短期 CA/RPC 证书、仓库内 `test-suites/full-stack-compose/mock-cf-dns`，并设置 `rpc_domain=""`、`insecure_skip_attestation=true`；同时仅将 auth 测试诊断输出重定向至 stderr。修正后的最终日志为 `gateway-e2e-simulated-fixed-harness.log`。

## 结论边界

最终 PASS 证明 Gateway 数据面、证书与集群同步逻辑在本地 debug attestation 下可工作。它不证明生产 TDX quote、真实 guest-agent 或 O/N 滚动升级兼容性。原始失败日志均保留，以便修复正式测试入口。

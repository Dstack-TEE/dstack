# 环境与测试资料

## 版本冻结

| 项目 | 值 |
|---|---|
| 测试提交 | `dc3b95117f518a752c0726ecd44ba7888a25cc49` |
| 版本 | `0.6.0` |
| 基线 release | `https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.11` |
| 隔离 worktree | `/home/kvin/src/dstack-v060-test` |
| 外部原始日志 | `/home/kvin/src/dstack-v060-artifacts/logs/` |

测试在 detached worktree 中执行，避免覆盖原分支的 `docs/security/advisories/` 和 `docs/test-plans/`。Gateway 的本地证书、端口和 debug-attestation 修改仅为 test-harness 适配，未作为产品修改提交。

## 主机能力

- 64 logical CPU、约 125 GiB RAM；
- Docker 29.5.3、Docker Compose 5.1.4；
- `/dev/kvm`、`/dev/vhost-vsock` 可用；
- CPU/内核报告 TDX host 与 SGX 可用，`kvm_intel.tdx=Y`；
- `/dev/sgx_enclave`、`/dev/sgx_provision` 可用；
- 宿主机 PCCS 运行于 `https://localhost:8081/sgx/certification/v4/`，
  `/etc/sgx_default_qcnl.conf` 指向该服务；测试通过
  `DSTACK_E2E_QCNL_CONF=/etc/sgx_default_qcnl.conf` 只读挂载给 AESMD；
- 模拟所需 `tpm_vtpm_proxy`、`cuse`、`wireguard`、`kvm_intel` 可用。

这只能证明主机具备运行条件；只有 CVM 实际启动、quote 验证和升级断言通过后，才记为真实 TDX PASS。

## 已构建二进制

release 构建成功的目标：

`dstack-cli`、`dstack-auth`、`dstack-vmm`、`supervisor`、`dstack-kms`、`dstack-gateway`、`dstack-verifier`、`local-key-provider`、`dstack-guest-agent`、`dstack-guest-agent-simulator`、`dstack-tee-simulator`。

## 证据位置

原始日志保存在 worktree 外，避免清理测试状态时丢失。报告中的统计均应能追溯到：

```text
/home/kvin/src/dstack-v060-artifacts/logs/
```

日志清单包括 `release-materials-build.log`、`core-test.log`、`sdk-test.log`、`attestation-e2e.log`、`gateway-e2e-simulated-fixed-harness.log`、`kms-auth-js-tests.log`、`foundry-tests.log`、`vmm-ui-build.log`、`prek-all-files.log`、`reuse-lint.log` 和 `yocto-os-image-build.log`。

## 真实硬件兼容测试资料

| 资料 | 标识 |
|---|---|
| meta-dstack v0.5.11 archive | `dstack-0.5.11.tar.gz`; SHA-256 `6f95a2a0b59975780e6f5d8bfbf016d50148092889554e4f8272c401ee549e42` |
| v0.5.11 guest image | `dstack-0.5.11`; measurement/digest `c2aa0186182fe8a404f16d5f3facb334d89be32703b3571c401b114a8b6e700d` |
| v0.5.11 source revision | `ce04e924e17e3cb9d38d258338cbe71e8c08d575` |
| dstack VMM v0.5.11 | tag commit `40eaf35e6b3f112998d01569f2a26110baab123b`; locally built binary SHA-256 `513ccf2f6d2860df985b8cc3e6cf471e144f5c79c468a0abc17b3004f357c9ab` |
| current guest image | `dstack-0.6.0`; measurement/digest `91bc72e3ca6f283cc0549d761ee436d381d1e8c4ddc4c23354e05c9bbccfdec1` |
| old KMS container | `dstacktee/dstack-kms:0.5.8@sha256:9650dcb47dad0065470f432f00e78e012912214ef1a5b1d7272918817e61a26d` |
| old Gateway container | `dstacktee/dstack-gateway:0.5.8@sha256:6eb1dc1a5000f37cc5b0322d3fdb71e7f2e31859b5e3a611634919278cee2411` |
| harness fixes | PR #819（PCCS mount，已合并）与 PR #820（混合镜像/升级审计） |

公共 `pccs.phala.network` 未缓存本物理平台的 PCK certificate，AESMD 因而返回
`AESM_NO_PLATFORM_CERT_DATA`（error 44）。改用已为本机完成 provisioning 的本地
PCCS 后，同一 production SGX enclave 稳定健康。该变化是测试基础设施修复，不是
关闭证明校验或使用 mock Local-Key-Provider。

可复核的 quote、quote-derived measurement/device ID、KMS identity/app key、exact
allowlist 与 HA summary 被选择性保存到：

```text
/home/kvin/src/dstack-v060-artifacts/evidence/real-tdx-lkp/
```

目录内 `SHA256SUMS` 固化各证据文件；未把测试 token、environment secret 或私钥纳入
证据包。

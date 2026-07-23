# 发现、风险与发布建议

| ID | 严重度 | 发现 | 建议 |
|---|---|---|---|
| F-01 | High | 三个 Bun 项目执行 `bun install --frozen-lockfile` 均报告 lockfile would change | 在发布 CI 指定 Bun 版本并重新生成/验证 lockfile；恢复 frozen gate |
| F-02 | High | `auth-eth` npm audit：3 high、1 moderate、2 low | 审核可利用路径，升级或记录有期限的风险接受 |
| F-03 | High | VMM UI npm audit：2 high | 发布前完成依赖处置或风险接受 |
| F-04 | Medium | SDK JS npm audit：1 low、3 moderate | 升级依赖并在 CI 固化 audit policy |
| F-05 | Medium | VMM UI 构建找不到 `vendor/vue.global.prod.js`，退回 CDN | release 包中内置并校验 vendor 文件，避免离线/供应链退化 |
| F-06 | High | Gateway 原始 E2E 有固定端口、失效远程 agent、陈旧 mock image 和 auth 判定问题 | 将本地适配整理为可配置、仓库自包含的正式 harness |
| F-07 | High | Gateway 最终 E2E 使用 `insecure_skip_attestation=true` | 不得据此放行生产 Gateway；必须执行真实 TDX suite |
| F-08 | High / scope | meta-dstack v0.5.11 release 可追溯 guest 已参与真实混合测试，但 release 不提供 v0.5.11 KMS/Gateway containers；service rolling baseline 仍为 0.5.8 | 报告中严格区分 v0.5.11 guest compatibility 与 0.5.8→current service upgrade；如必须验证 v0.5.11 service，需另行指定其可追溯 artifact |
| F-09 | Review | Yocto kernel configcheck 报告多项 requested/not-found symbol | 对最终 `.config` 逐项确认安全缓解、AMD/TDX、crypto 与设备支持是否由新版符号替代 |
| F-10 | Test-only | REUSE 仅因本地生成 9 个短期证书无 SPDX 而失败 | 不提交这些证书；清理 harness 后在干净冻结点重跑 REUSE |
| F-11 | Critical | 原样 Yocto build 因 `CONFIG_FUSE_FS=y` 却安装不存在的 `kernel-module-fuse` RPM 而失败 | 删除该 package dependency 或改为模块配置；在干净冻结点重建 |
| F-12 | Resolved infrastructure | 公共 PCCS 无本机 PCK certificate 导致 AESM error 44；挂载指向已 provision 本机的 QCNL 配置后 production SGX Local-Key-Provider healthy | PR #819 已合并；保留本地 PCCS 运维/provisioning，并在 harness 明确传 `DSTACK_E2E_QCNL_CONF` |
| F-13 | High | dev image 中 aws-lc CC builder 尝试运行 Yocto target binary并误报 GCC memcmp bug | 为 cross build 正式采用受支持的 CMake builder 或提供 upstream cross-check 修复 |
| F-14 | High | no-TEE simulator 在 prepare 前读取尚不存在的 `/dstack/.host-shared/.sys-config.json`，缺 seed 后触发 guest reboot loop | 增加 simulator 前置 host-share config mount/copy，修正文档并添加 VMM-to-boot E2E |
| F-15 | Medium | VMM 的 swtpm Unix socket 继承完整 VM 路径，较长 HOME 直接超过 AF_UNIX 限制 | 创建短 runtime socket 或部署前校验并给出可操作错误 |
| F-16 | Test-harness | KMS onboarding 会复制 durable verified-image cache，因此“每个 KMS 必须重新 HTTP GET OS archive”会产生假失败 | PR #820 改为要求每个精确 archive 至少有一次成功 fetch，并结合 exact allowlist、禁止 disabled-verification 路径及 old/current guest 成功取钥判断 |
| F-17 | Low / observability | v0.5.11→current VMM process 切换保持 QEMU/identity/routes，但 current VMM 重载 old state 后 event history 为空、`boot_progress` 显示 `running` 而非切换前的 `done` | 明确 event buffer 是否设计为仅内存态；若 UI/API 要求重启连续性，则持久化或从 supervisor/guest 重建最终 progress |

## Yocto configcheck 特别审计项

构建日志包含 OVMF assignment whitespace、malformed config fragment，以及多项未进入/未出现在 active configuration 的内核符号。安全相关项目包括 `CONFIG_SPECULATION_MITIGATIONS`、`CONFIG_PAGE_TABLE_ISOLATION`、`CONFIG_RETPOLINE`、`CONFIG_RETHUNK`、IBPB/IBRS、SRSO、SLS、GDS mitigation；功能相关项目包括 AMD memory encryption、crypto SIMD/SHA、Atheros WLAN、Bluetooth 和 MD bitmap。

这些当前是 warning，不应直接写成漏洞；但必须用最终内核 `.config` 和运行时探针确认其等价替代项及实际状态后才能关闭。

## 发布建议

当前建议：**NO-GO（仅针对宣称完成 v0.6.0 preview 全量门禁）**。Local-Key-Provider 重启持久性、v0.5.11→current VMM 原地切换、同/不同 app 的混合 guest、guest image upgrade/rollback 与真实 TDX service rolling upgrade 已有正向证据，但全 old service baseline、物理 host reboot、真实 GPU/云平台和最终镜像审计仍未完成，不应将报告表述为全量通过。

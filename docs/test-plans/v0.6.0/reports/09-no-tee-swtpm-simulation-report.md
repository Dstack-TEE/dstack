# no-TEE + swtpm 模拟执行报告

## 范围与结论边界

本次按 `docs/development-without-tee.md` 实际执行 development guest、VMM `--no-tee` 和 TPM key-provider 流程。执行当时它用于临时替代尚未修复的 SGX Local-Key-Provider，并覆盖缺少其他平台硬件的部分集成路径；后续真实 SGX/TDX 结果单独报告。

该模式只验证 QEMU/VMM/guest setup、TEE ABI simulator、swtpm、TPM 密钥和存储路径。Host 完全控制模拟证据，**不能证明硬件隔离、真实 quote、DCAP/KDS/OCSP freshness，也不能替代生产 KMS/Gateway 兼容门禁**。

## Development image build

冻结点原样 dev build：**FAIL**。

`dstack-tee-simulator` 构建 `aws-lc-sys 0.41.0` 时，CC builder 编译后尝试直接执行 Yocto target binary。Cross-compiler wrapper 生成的程序无法在 build host 上直接运行，被错误报告为 GCC PR95189 memcmp compiler bug。

为继续模拟，仅在隔离 worktree 做两个 test-only workaround：

1. `AWS_LC_SYS_CMAKE_BUILDER=1`，绕过错误的 target execution check；
2. 从 simulator RDEPENDS 删除不存在的 `kernel-module-fuse`，因为最终 kernel 是 `CONFIG_FUSE_FS=y`。

补丁后 `dstack-dev-0.6.0.tar.gz` 构建成功，metadata 确认为 `is_dev=true`、version `0.6.0`、revision `dc3b951...`，tar 内全部 checksum 通过。

## VMM 与 TPM 模式

已执行：

- VMM 启动并发现 `dstack-dev-0.6.0`；
- app-compose 使用 `key_provider=tpm`、`kms_enabled=false`、`local_key_provider_enabled=false`、Event Log v2；
- `deploy --no-tee --vcpu 2 --memory 3G --disk 10G` 成功创建 VM；
- QEMU command line 确认包含 `-tpmdev emulator`、`tpm-tis`，且不含 TDX guest object；
- `swtpm` 正常运行并生成 `tpm2-00.permall`。

首次使用长 artifact path 时 swtpm 明确失败：`Path for UnixIO socket is too long`。改用短 HOME `/tmp/dv6` 后 swtpm 成功启动。这是 VMM 对 Unix socket path 长度缺少预检/短路径处理的 harness/product usability 问题。

## 最终模拟结果

结果：**FAIL (SIMULATED)**。

短路径重跑后 VMM 观察到 VM 保持 running，但超过 5 分钟始终为 `Boot Progress: booting`，无 instance ID。初次查看 serial 尾部停在：

```text
Freeing initrd memory: 10844K
```

进一步审计完整 serial 后确认这不是 kernel hang：guest 多次进入 systemd，随后因 simulator 读不到 `mock_attestation_seed` 导致 prepare dependency failure 和自动重启。QEMU 持续占用约一个 CPU来自 reboot loop。根因分析见 `10-no-tee-early-boot-investigation.md`。

TPM 2.0、FUSE built-in、rootfs 和 10 GiB data disk 均已识别，但 guest preparation/agent 未完成，因此无法验证：

- `Generating app keys from TPM`；
- LUKS/ZFS 初始化；
- workload/volume marker；
- stop/start 后 instance ID、TPM key 和加密存储持久性。

Graceful stop 因 guest-agent 不可达失败，force stop 成功。完整 launch spec、serial、VMM、deploy 和 info 日志均保存在 `/home/kvin/src/dstack-v060-artifacts/logs/`。

## 判定

TPM replacement 的 host 侧装配已得到证据，但 guest 启动失败，所以不得据此把 STO-06、PLAT-07、REG-01 或持久存储用例升级为 PASS。Local-Key-Provider 后续已在独立的真实 SGX/TDX full-stack 测试中解除阻塞；该真实硬件结论来自 `06-tdx-upgrade-compatibility-report.md`，不是由本模拟结果推断。模拟失败仍作为独立缺陷记录。

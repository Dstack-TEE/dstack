# no-TEE guest “早期启动卡死”调查

## 结论

这不是 Linux kernel 在 `Freeing initrd memory` 卡死。真实根因是：

1. `dstack-tee-simulator.service` 在 `dstack-prepare.service` **之前**启动；
2. simulator 默认读取 `/dstack/.host-shared/.sys-config.json`；
3. 该路径此时尚未建立，`load_config()` 对不存在的文件静默使用默认值；
4. 默认配置没有必需的 `tee_simulator.mock_attestation_seed`；
5. simulator 失败，使 `dstack-prepare.service` 的 dependency 失败；
6. `dstack-prepare.service` 配置了 `OnFailure=reboot.target` 和 `FailureAction=reboot`，VM 因而不断重启。

早先看到的 serial 尾部刚好位于某次重启的 kernel 阶段；完整 serial 实际包含多次完整 kernel/systemd boot，所以“kernel early boot hang”的初始判断已撤回。

## 直接证据

每轮约在启动后 4 秒出现：

```text
dstack-tee-simulator: Error: tee_simulator.mock_attestation_seed is required
FAILED Failed to start dstack development TEE ABI simulator
DEPEND Dependency failed for dstack Guest Preparation Service
```

Serial 中同一错误重复出现多次。QEMU 持续约 100% 单核并非停在同一指令，而是 guest 的快速 reboot loop。

Host 侧 `.sys-config.json` 经确认确实包含合法 64 hex seed：

```json
{
  "tee_simulator": {
    "platform": "dstack-tdx",
    "mock_attestation_seed": "0123...cdef",
    "collateral_base_url": "http://10.0.2.2:18088"
  }
}
```

因此不是 VMM 没有序列化配置，而是 guest service 启动顺序与配置可见路径不一致。

## 代码路径核查

- VMM 正确从 `[cvm.tee_simulator]` 生成 host shared `.sys-config.json`；
- init/setup 路径将 host-shared 临时挂载并复制到工作目录；
- simulator unit 声明 `Before=dstack-prepare.service`；
- simulator 默认 path 是 `/dstack/.host-shared/.sys-config.json`；
- `/dstack/.host-shared` 的稳定副本/绑定关系要到 guest preparation 路径才可用。

这形成启动依赖环：prepare 需要 simulator 提供 TEE ABI，但 simulator 读取的配置又要等 prepare 建立。

## 文档问题

`docs/development-without-tee.md` 没有要求配置 `[cvm.tee_simulator]` seed。即使按照代码补上 seed，当前 service/path ordering 仍会读不到它。文档缺项和实现时序问题必须分别修复。

## 建议修复

推荐让 simulator 在 prepare 之前独立取得 host-shared config：

1. 增加专用 early host-share mount/copy unit，位于 simulator 之前；或
2. 在 simulator unit 中将 9p/shared-disk 只读挂载到 `/run/dstack/tee-simulator-host-shared`，通过 `--sys-config` 指向该文件，ready 后卸载；或
3. 将 initramfs 阶段复制的 sys-config 放到 switch-root 后仍存在且权限受控的固定路径，再让 simulator读取该路径。

不建议把 simulator 简单移动到 prepare 之后，因为 prepare 的 attestation、measurement 和 TPM key setup 正需要 simulator 先就绪。

同时应：

- 在 dev/no-TEE deploy 时，如果缺 seed，让 VMM 自动生成开发 seed或在创建 VM 前明确拒绝；
- 将 `load_config()` 对默认生产路径不存在的行为改为清晰错误，输出实际读取路径；
- 修订 `development-without-tee.md`，包含 simulator seed/collateral 配置；
- 添加真正从 VMM 创建 dev VM 到 `Boot Progress: done` 的 E2E，防止 Docker 内直接挂载 sys-config 的 simulator tests 掩盖该时序问题。

## 影响范围

该缺陷直接阻断文档描述的 no-TEE + swtpm 开发流程，因此 PLAT-07 保持 `FAIL (SIMULATED)`。它不证明真实 TDX/SEV guest 会失败，因为真实硬件环境不会启动 development simulator service；但它使当前建议的硬件替代测试路径不可用。

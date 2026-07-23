# v0.6.0 测试用例执行矩阵

> 本矩阵逐项列出原计划全部 95 个用例。`PARTIAL` 不计为通过；相邻 suite 通过不自动提升为用例 PASS。

| 用例 | 优先级 | 状态 | 本次证据/缺口 |
|---|---:|---|---|
| COMP-01 | P0 | PARTIAL | 真实 TDX 上建立 old service + v0.5.11 guest 的 key/TLS/storage 基线；VMM 非 old，service baseline 为 0.5.8 |
| COMP-02 | P0 | PASS | v0.5.11→current VMM process 切换复用 detached supervisor；QEMU PID、uptime、identity 和双路由连续 |
| COMP-03 | P0 | PASS | v0.5.11 guest 切换 latest KMS 并重启；CA SPKI、root k256 key 与 per-app key 保持 |
| COMP-04 | P0 | PASS | v0.5.11 guest 在两个 Gateway rolling upgrade 后仍可达，DNS/TLS/WireGuard 恢复 |
| COMP-05 | P0 | PASS | latest VMM 创建全新 v0.5.11 guest；legacy manifest、取钥、存储与 latest service 路径通过 |
| COMP-06 | P0 | PASS | latest guest 真实 TDX lite 启动，exact image policy、取钥及 Gateway 路径通过 |
| COMP-07 | P0 | PASS | 同 app v0.5.11/current VM 并行且四条路由通过；instance/data UUID 隔离；同 app key 稳定、不同 app key 不同 |
| COMP-08 | P0 | PASS | 同一 VM/app ID/data disk 完成 v0.5.11→current；原 ext4 UUID 挂载且双 Gateway 可达 |
| COMP-09 | P0 | PASS | current→v0.5.11 回滚、原盘和路由恢复；old hash 移除时明确 deny，恢复 policy 后恢复 |
| COMP-10 | P0 | PARTIAL | VMM service restart 后 KMS、双 Gateway、old/current guest、identity 与四条路由恢复；未重启物理 host |
| ATT-01 | P0 | PARTIAL | 四种新 SDK 与 simulator 已通过；未在新真实镜像取证 |
| ATT-02 | P0 | PARTIAL | Rust core replay/canonicalization 通过；缺独立真实 quote replay 证据 |
| ATT-03 | P0 | PARTIAL | core 与多 SDK 测试通过；未完成四语言统一 mutation corpus |
| ATT-04 | P0 | PARTIAL | core verifier 负向测试通过；未证明每种 mutation 均阻止真实 KMS 发钥 |
| ATT-05 | P0 | PARTIAL | v1/v2 compatibility 单测通过；未使用真实 v0.5.11 event log |
| ATT-06 | P0 | PARTIAL | 相关 core 测试通过；未在新 guest 对最新 KMS 做并发重启 |
| ATT-07 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| ATT-08 | P1 | PARTIAL | TDX full/lite 模拟验证通过；真实镜像及完整 wrong-digest 矩阵未跑 |
| ATT-09 | P1 | PARTIAL | mock/test trust 路径有覆盖；生产 trust-root 组合未跑 |
| ATT-10 | P1 | PARTIAL | TSM 代码测试有覆盖；真实 provider/override 系统测试未跑 |
| ATT-11 | P1 | PARTIAL | verifier 测试有覆盖；实际 dev/prod release 镜像未对照 |
| ATT-12 | P1 | PARTIAL | event-log 单元测试通过；真实 guest 并发 writer 未跑 |
| GST-01 | P0 | PARTIAL | manifest/version 单元覆盖；实际 boot 矩阵未跑 |
| GST-02 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| GST-03 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| GST-04 | P1 | PARTIAL | RPC/core 兼容测试覆盖；旧 client + 新 guest 未跑 |
| GST-05 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| GST-06 | P1 | PARTIAL | 相关 guest/core tests 通过；实际 boot 组合未跑 |
| VMM-01 | P0 | PARTIAL | VMM core tests 与 UI build 通过；真实 CRUD/API/CLI/UI 全链路未跑 |
| VMM-02 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| VMM-03 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| VMM-04 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| VMM-05 | P1 | PARTIAL | 版本逻辑单测和 UI build 通过；运行态元数据未核对 |
| VMM-06 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| VMM-07 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| AUTH-01 | P0 | PARTIAL | auth core tests 通过；未覆盖真实 VMM 的所有协议/方法 |
| AUTH-02 | P0 | PARTIAL | auth 单元及 Gateway 401/401/200 通过；未完整做冲突凭证/时序采样 |
| AUTH-03 | P0 | PARTIAL | Gateway 新 token 本地 E2E 通过；legacy alias/precedence 未完整跑 |
| AUTH-04 | P0 | PARTIAL | Gateway health/admin token 本地 E2E 通过；所有 method/bypass 矩阵未跑 |
| AUTH-05 | P0 | PARTIAL | KMS core tests 通过；dedicated listener 运行态隔离未跑 |
| AUTH-06 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| AUTH-07 | P1 | PARTIAL | 相关配置测试有覆盖；运行态 warning/兼容组合未跑 |
| STO-01 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| STO-02 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| STO-03 | P0 | PARTIAL | LUKS2 parser/core tests 通过；未执行完整边界设备 I/O 矩阵 |
| STO-04 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| STO-05 | P0 | PARTIAL | production SGX provider 重启后 KMS 重新取钥、原加密盘及 identity/app key 保持；exact OS measurement deny/recovery 通过；rotate/backup 未执行 |
| STO-06 | P0 | PARTIAL | 单 VM swtpm socket/permall 创建成功；guest early boot 卡住，隔离、重启和删除断言未执行 |
| STO-07 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| GKW-01 | P0 | PARTIAL | 三节点 DNS/ACME/TLS 本地 E2E 通过；缺旧/新真实 guest app path |
| GKW-02 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| GKW-03 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| GKW-04 | P1 | PASS | VMM service restart 使 KMS 与双 Gateway 联合重启；old/current guest 自动恢复，KMS identity 不变且四条路由通过 |
| GKW-05 | P1 | PARTIAL | KMS cache 单测覆盖；并发真实 verification 未跑 |
| GKW-06 | P1 | PARTIAL | Foundry 54 tests 通过；未在每条部署链做 rehearsal |
| PLAT-01 | P0 | BLOCKED | 无 NVIDIA GPU/生产 OCSP 在线环境 |
| PLAT-02 | P1 | BLOCKED | 未执行两次 NVIDIA production build |
| PLAT-03 | P0 | PARTIAL | GCP TDX 格式模拟通过；无真实 GCP instance binding |
| PLAT-04 | P1 | BLOCKED | 需要真实 GCP 网络资源 |
| PLAT-05 | P0 | PARTIAL | NitroTPM 格式模拟通过；无真实实例 freshness/replay |
| PLAT-06 | P1 | PARTIAL | SNP 格式模拟与 verifier tests 通过；无真实 KDS 故障恢复 |
| PLAT-07 | P1 | FAIL (SIMULATED) | SDK simulator API 通过；实际 dev image + --no-tee + swtpm 启动停在进入 /init 前 |
| API-01 | P0 | PARTIAL | 四种新 SDK 与 simulator 通过；旧/新真实镜像未跑 |
| API-02 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| API-03 | P1 | PARTIAL | verifier core tests 通过；未记录完整 request matrix |
| API-04 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| API-05 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| API-06 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| API-07 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| OS-01 | P0 | FAIL | 冻结点原样 build 因不存在的 kernel-module-fuse RPM 失败；最小测试补丁后仅 production container 路径成功 |
| OS-02 | P0 | BLOCKED | 本机无 SEV-SNP host，且 TDX 等待镜像 |
| OS-03 | P0 | PARTIAL | 测试补丁产物的 bare/UKI/rootfs/verity/metadata/checksum 已校验；原样 release artifact 未生成 |
| OS-04 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| OS-05 | P1 | BLOCKED | 需要 GCP C3 |
| OS-06 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| OS-07 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| OS-08 | P0 | BLOCKED | 需要 NVIDIA GPU |
| OS-09 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| OS-10 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| OS-11 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| OS-12 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| REG-01 | P0 | PARTIAL | no-TEE VM 创建、kernel、TPM 与磁盘枚举成功；未进入 guest setup，无法完成 launch-through-delete |
| REG-02 | P0 | PARTIAL | core event log/measurement/KMS policy 测试通过；真实启动未跑 |
| REG-03 | P0 | PARTIAL | KMS/Gateway/core tests 通过；真实 key/cert 生命周期未跑 |
| REG-04 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| REG-05 | P0 | NOT RUN | 未执行该用例的完整步骤与断言 |
| REG-06 | P0 | PARTIAL | Gateway 三节点模拟 DNS/HTTPS/TLS/WG 部分通过；真实 guest 未跑 |
| REG-07 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| REG-08 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| REG-09 | P1 | BLOCKED | 需要 GPU 资源 |
| REG-10 | P1 | PARTIAL | UI build 与 VMM tests 通过；真实 UI CRUD/console 未跑 |
| REG-11 | P1 | PARTIAL | 四套 auth tests 与 KMS core tests 通过；运行态 onboarding/cache 未完整跑 |
| REG-12 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| REG-13 | P1 | NOT RUN | 未执行该用例的完整步骤与断言 |
| REG-14 | P2 | NOT RUN | 未执行该用例的完整步骤与断言 |

## 统计

- 总数：95
- PASS: 9
- BLOCKED: 7
- FAIL: 1
- FAIL (SIMULATED): 1
- NOT RUN: 35
- PARTIAL: 42

真实 TDX rolling-upgrade 的逐项边界见 `06-tdx-upgrade-compatibility-report.md`。确切 v0.5.11 guest 已参与；release 未提供 v0.5.11 service artifacts，且未执行的升级/回滚/host reboot 项不得由相邻 PASS 推断。

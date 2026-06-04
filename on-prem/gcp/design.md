# GCP 私有化部署设计文档（air-gapped KMS + Launcher 加密镜像）

> **实现已演进（2026-06-03，以代码为准）**：镜像加密从本文的"对称 CEK、per-digest
> `allowed_images[].cek`、自定义 keyprovider"改成了 **ocicrypt 原生 JWE（非对称 EC P-256）+
> 全局密钥环**。即:① 加密**只用公钥**(`skopeo --encryption-key jwe:pub.pem`),构建机不持解密秘钥;
> ② 解密私钥环是 **vendor-wide 全局**(`store.keyring`/`keyring.json`),随每个租户 AuthBundle 下发,
> 一份加密镜像所有租户可解;③ 不再按镜像注册 CEK,轮换=mint 新 kid;④ 删除了自定义 keyprovider,
> launcher 把租来的私钥喂给 `skopeo --decryption-key`,ocicrypt try-each 匹配 recipient。
> per-user 隔离仅保留在 `root_material`(派生各租户 app/disk 密钥)。下文 CEK/allowed_images 段落
> 保留为设计沿革;操作以 `DEPLOYMENT_GUIDE_CN.md`/`DEPLOYMENT.md` 为准。

> 状态：Draft v4 · 2026-06-01
> 范围：在客户无公网访问的 GCP VPC 内部署 dstack KMS 与 workload，由厂商（我们）通过密码学手段掌控授权数据（代码白名单、实例数量、时效），运维操作经一个 CLI 作为离线桥接完成。

> **v2 决策（相对 v1）**
> 1. **Root key 改为平台下发**：平台生成，经 attest 通道机密下发，连带简化 CEK 托管与 DR。代价：平台可解客户数据（§2 信任取舍）。
> 2. **可信时间简化**：假定 KMS 内时间可信；courier 时平台校验 guest 时间戳偏差（§7.2）。
> 3. **抗回滚暂不做**：保留 slot 抗克隆，回滚留 TODO（§6.2）。
>
> **v3 决策（相对 v2）**
> 4. **KMS core 零改动**：root key 由 sidecar 在 TEE 内接收并写入共享 volume，KMS core `depends_on` sidecar healthcheck 后再读文件启动——利用现有 `Keys::load()` 路径，core 无需修改（§5、§3.1）。
> 5. **CEK 不经 core**：CEK 由平台 TEE 外生成，随 AuthBundle 传给 sidecar。Launcher 用 KMS 签发的 TLS 证书（`get_app_key` 返回的 ca_cert 链）向 sidecar 做 mTLS；sidecar 验 cert 链 + cert 内嵌 measurement ∈ 白名单后直接下发 CEK。与 dstack disk/env key 完全独立（§8.2）。
>
> **v4 决策（相对 v3）**
> 6. **明确区分两类镜像**：Launcher 镜像与业务镜像是完全独立的两条路径，更新机制不同（§8）。Launcher 镜像被 TDX 度量（compose_hash），只能冷更新（重建 CVM）；业务镜像不被度量，由 launcher 在线管理，支持热更新。

---

## 1. 背景与目标

### 1.1 现状（已具备，不重做）

- **`dstack-cloud` CLI**（`meta-dstack-cloud/scripts/bin/dstack-cloud`）已实现 **"一个 GCP Confidential VM = 一个 workload"** 模型：直接 `gcloud compute instances create --confidential-compute-type=TDX`（C3 / a3-highgpu），**不依赖 vmm/QEMU**。CLI 负责构建 boot/shared/data 三块磁盘镜像、上传 GCS、创建实例。
- **shared 盘** 投递 `app-compose.json`、`.sys-config.json`（`kms_urls` / `gateway_urls` / `pccs_url` / `os_image_hash`）、`.instance_info`（`app_id`、`instance_id_seed`）、`.encrypted-env`。
- **KMS 信任雏形**：CLI 已能从 KMS 取 `env-encrypt` 公钥并用 secp256k1/keccak 验签，比对本地 `~/.config/dstack-cloud/kms-whitelist.json` 的 `trusted_signers`（当前为 TOFU 式，验不过交互确认）。
- **私有 registry 现状**（ttc-dstack-recipes）：GCP Artifact Registry + GCE 默认 SA 授 `artifactregistry.reader`，CVM 内用 metadata token 直接 `docker pull` —— **明文镜像、无加密、无"从公共 registry 同步"工具**。
- **KMS 密钥派生**：KMS 在 TEE 内自举 root key（`kms/src/onboard_service.rs`），按 `KDF(root_ca, [app_id, …])` 派生 `env-encrypt-key` / `app-disk-crypt-key`（`kms/src/main_service.rs`）。
- **Launcher 例子**（`dstack-examples/launcher`）只是**轮询骨架**：`while true; 每 5s get-latest.sh → 重写 compose → docker-compose up`，**无 KMS、无解密、无授权**。

### 1.2 目标

| # | 目标 | 落点 |
|---|------|------|
| G1 | KMS 与 workload CVM 全部位于客户**无公网** GCP VPC | 部署模型 |
| G2 | 厂商掌控**授权数据**：代码白名单、实例数量、时效 | 授权平台 + auth-api |
| G3 | 运维经 **CLI 离线桥接** 部署/管理 KMS（CLI 不可信，仅作管道） | CLI + courier 协议 |
| G4 | 运维经 CLI 部署 workload，自动连其私有 KMS | CLI + launcher |
| G5 | workload 加密发布到公共 registry，CLI 同步到 GCP 私有 registry | image sync + 完整性校验 |
| G6 | CVM 用 launcher 模式：初始只跑 launcher，拉加密镜像并解密运行 | launcher + 度量绑定 |
| G7 | launcher 经 KMS 取解密密钥 | KMS 密钥释放 + RA-TLS |
| G8 | CLI 从平台取授权数据塞进客户私有 KMS | AuthBundle 下发 |
| G9 | launcher 定期向 KMS 刷新授权，超时停服务 | Lease / kill-switch |

### 1.3 需要新建的组件（总览）

1. **Vendor Authority（在线授权平台）** —— 我们运营的服务。
2. **KMS sidecar**（新容器，加入 `kms/dstack-app/docker-compose.yaml`）—— 承载：courier 端点（接收平台下发 root key、AuthBundle）、auth webhook（替代 auth-eth）、slot/lease 簿记、CEK 向 launcher 下发、用量回执。**KMS core 零改动。**
3. **CLI 扩展** —— courier attestation、AuthBundle 下发、镜像同步、workload 部署。
4. **Launcher（增强版）** —— attest→向 sidecar 取 CEK/租约（mTLS）→拉加密镜像→解密→校验 digest→运行→定期刷租约→超时停。
5. **VPC 内 PCCS 镜像** —— TDX quote 验证 collateral。

---

## 2. 信任模型与威胁模型

### 2.1 主体

| 主体 | 位置 | 信任级别 |
|------|------|----------|
| Vendor Authority | 厂商在线 | 授权权威（root of trust） |
| Vendor 签名私钥 | 平台（HSM/KMS 保管） | 最高机密 |
| CLI | 客户运维笔记本 | **不可信管道**（可能被篡改/窃听） |
| 客户 KMS（TEE 内） | 客户 VPC | 受 TDX 保护的执行点；厂商通过 attestation 信任其度量 |
| Launcher / workload CVM（TEE 内） | 客户 VPC | 同上 |
| 客户运维 / 宿主环境 | 客户 GCP 项目 | **敌手**（见下） |

### 2.2 敌手能力（客户运维，拥有 GCP 项目 root）

可以：快照/恢复任意磁盘、克隆 VM、操纵 VM 系统时钟、读写 TEE 外任意文件、完全控制 VPC 网络（含截断 CLI 出口）、重放任何离线消息、在非 TEE 主机上伪造服务。

不能：攻破 TDX、读取 TEE 内密文/密钥、伪造 Vendor 平台签名、伪造合法的 TDX quote（measurement 由硬件保证）。

> **信任取舍（v2）**：本设计中 **root key 由平台生成并持有**（HSM 保管，每客户独立）。因此平台**在技术上能够派生客户的 env-encrypt-key / disk-key / 镜像 CEK，从而有能力解客户数据**。这是为换取「平台可派生密钥简化 CEK 托管」与「平台可重新下发 root 实现灾备」而做的取舍。若客户要求平台**不可解其数据**，则不能用平台下发 root 模式（需回退到 v1 的 KMS 自举 root + CEK 包装到 KMS 公钥方案）。该取舍需与客户在合同层面明确。

### 2.3 安全目标

- **S1 代码授权**：只有白名单内的 `(compose_hash, image_digest)` 能拿到密钥并运行。
- **S2 数量授权**：并发运行实例数 ≤ 平台签发的 slot 数。
- **S3 时效/吊销**：授权可设过期、可被吊销；超时实例自动停服。
- **S4 端到端完整性**：授权数据由平台签名、绑定到具体 KMS 身份；CLI 篡改无效。
- **S5 抗回滚**：客户无法通过快照恢复/克隆来重置计数或复活过期授权。

非目标：对客户隐藏其自身 workload（数据是客户的）；防止客户对自己基础设施做 DoS。

---

## 3. 总体架构

```
┌────────────────────────── 厂商在线 ──────────────────────────┐
│  Vendor Authority                                             │
│   - 客户/KMS 注册表（期望 measurement）                      │
│   - Vendor 签名私钥（HSM）+ root key 仓库（per customer）    │
│   - TDX quote 验证（可达 Intel PCS）                         │
│   - 镜像加密发布（TEE 外生成 CEK）+ cosign 签名              │
│   - 用量回执对账 / 计费                                      │
│  公共 Registry（加密镜像 + cosign 签名）                     │
└───────────────▲───────────────────────────┬─────────────────┘
                │  ① challenge/quote          │ ② 加密镜像
   (CLI 携带，离线 courier)                    │  (CLI 同步)
                │                             ▼
┌───────────────┴──────────────────── 客户 GCP VPC (无公网) ───┐
│  运维笔记本: dstack-cloud CLI (不可信管道)                    │
│     │ sealed-root + AuthBundle(含CEK)  │ GCP AR(私有,加密镜像)│
│     ▼                                  ▼                      │
│  ┌──────────────────── KMS CVM (TDX) ─────────────────────┐  │
│  │  ┌─ sidecar ──────────────────────────────────────────┐ │  │
│  │  │ • courier 端点（接收 sealed-root、AuthBundle+CEK）  │ │  │
│  │  │ • 解封 root → 写 kms-volume（启动前）              │ │  │
│  │  │ • auth webhook（验 AuthBundle 签名、白名单、slot）   │ │  │
│  │  │ • lease 签发/续租 + slot 绑定                       │ │  │
│  │  │ • mTLS 接 launcher → 验 KMS-CA cert + measurement  │ │  │
│  │  │   → 下发 CEK + lease                               │ │  │
│  │  │ • 用量回执生成                                      │ │  │
│  │  └────────────────────────────────────────────────────┘ │  │
│  │  ┌─ kms core（零改动）────────────────────────────────┐ │  │
│  │  │ depends_on: sidecar (healthcheck: volume ready)     │ │  │
│  │  │ Keys::load(kms-volume) → 派生 disk/env key          │ │  │
│  │  │ GetAppKey / auth webhook → sidecar                  │ │  │
│  │  └────────────────────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────┘  │
│                           │ mTLS (KMS-CA cert)                │
│              ┌────────────▼──── Workload CVM (TDX) ────────┐  │
│              │ Launcher: get_app_key→KMS core(disk/env key)│  │
│              │           → sidecar mTLS(CEK + lease)       │  │
│              │           → AR 拉加密镜像 → 解密 → 验digest │  │
│              │           → compose up → 定期刷 lease        │  │
│              └──────────────────────────────────────────────┘  │
│  ┌── PCCS 镜像（VPC 内，TDX collateral）──┐                    │
└──┴─────────────────────────────────────────┴───────────────────┘
```

### 3.1 KMS CVM 内部启动顺序

KMS 是一个跑在 TDX CVM 里的 dstack app，本身就是 docker-compose 多容器结构（现有：`kms` + `auth-api` + `helios`）。v3 把 `auth-api` 替换为我们自己的 `sidecar`，并新增启动依赖：

```yaml
# kms/dstack-app/docker-compose.yaml（改动概要）
services:
  sidecar:                          # 新容器，替代 auth-api + helios
    image: vendor/kms-sidecar:x.y
    volumes:
      - kms-volume:/kms             # 与 kms core 共享同一 volume
      - /var/run/dstack.sock:/var/run/dstack.sock   # 出 TDX quote
    ports:
      - "8001:8001"                 # courier 端点（CLI 打入）
      - "8002:8002"                 # mTLS 端点（launcher 打入）
    healthcheck:
      test: ["CMD", "test", "-f", "/kms/root-ca.key"]   # root 写好才 healthy
      interval: 5s
      timeout: 3s
      retries: 60                   # 等最多 5 分钟（含 courier 等待）

  kms:
    image: vendor/dstack-kms:x.y   # 现有 KMS core，零改动
    volumes:
      - kms-volume:/kms
      - /var/run/dstack.sock:/var/run/dstack.sock
    depends_on:
      sidecar:
        condition: service_healthy  # 等 root key 写好再起
    environment:
      - AUTH_WEBHOOK_URL=http://sidecar:8001/auth  # 把 webhook 指向 sidecar

volumes:
  kms-volume:
```

**启动流程**：
1. `sidecar` 起 → 如果 `kms-volume` 里已有 root key（重启场景）直接 healthy；
2. 如果是首次（volume 空），sidecar 等 CLI 发来 courier 包（sealed-root + AuthBundle）→ 解封 root → 写 volume → healthy；
3. `kms core` 起 → `Keys::load(/kms)` → 正常运行；
4. `kms core` 的 auth webhook 指向 `sidecar:8001/auth`，boot 授权决策全走 sidecar。

---

## 4. 数据结构与契约

所有签名用 Vendor 平台密钥（建议 **Ed25519** 主签 + secp256k1 兼容现有 KMS 验签链路二选一，下文以 `authority_sig` 统称）。所有结构 JSON（canonical / 排序键）后签名。

### 4.1 AuthBundle（平台 → KMS，经 CLI）

KMS 离线授权的根对象。**单调递增、抗回滚**。

```jsonc
{
  "schema_version": 1,
  "user_id": "cust-acme",
  "bundle_seq": 42,                       // 单调递增，KMS 拒绝 <= 已存最大值
  "issued_at": 1769800000,                // 平台 UTC 秒
  "expires_at": 1769886400,               // 绝对过期（见 §7 可信时间）
  "kms_identity": {
    "k256_pubkey": "0x02ab…",             // attestation 中绑定的 KMS 身份公钥
    "expected_mrtd": "…",                 // KMS OS 镜像期望度量（可多值）
    "expected_rtmr": ["…","…","…","…"]
  },
  "app_whitelist": [
    {
      "app_id": "40hex",

      // ── Launcher 镜像（被 TDX 度量，冷更新）──────────────────────────
      "allowed_launcher_hashes": [        // app-compose.json 的 compose_hash 白名单
        "sha256:cur…",                    // 当前版本
        "sha256:prev…"                    // 过渡期保留旧版本（支持回滚窗口）
      ],

      // ── 业务镜像（运行时热更新）──────────────────────────────────────
      "current_image_digest": "sha256:biz-new…",   // launcher 应切换到的目标版本
      "allowed_images": [
        {
          "digest": "sha256:biz-new…",
          "cek": "base64…"               // 该 digest 对应的 CEK（平台 TEE 外生成）
        },
        {
          "digest": "sha256:biz-old…",
          "cek": "base64…",
          "expires_at": 1770000000       // 旧版本回滚窗口，到期 sidecar 拒绝下发
        }
      ]
    }
  ],
  "slot_quota": 5,                        // 见 §6
  "revocations": {
    "launcher_hashes": [],               // 被吊销的 compose_hash
    "image_digests": [],                 // 被吊销的业务镜像 digest
    "slot_ids": []
  },
  "authority_sig": "…"
}
```

KMS 接收校验：①`authority_sig` 用 **出厂内置的平台公钥** 验；②`kms_identity.k256_pubkey == 自身 pubkey`；③`bundle_seq > 已持久化最大值`（抗回滚，§7）；④`expires_at` 未过（按 §7 可信时间口径）。

### 4.2 SlotToken（数量授权，可内联于 AuthBundle 或单独下发）

```jsonc
{
  "slot_id": "uuid",
  "user_id": "cust-acme",
  "app_id": "40hex",
  "not_before": 1769800000,
  "not_after": 1772479999,
  "authority_sig": "…"
}
```

### 4.3 Lease（KMS → Launcher，RA-TLS 内返回）

短时服务租约，launcher 必须在过期前续租。

```jsonc
{
  "instance_id": "40hex",
  "app_id": "40hex",
  "slot_id": "uuid",
  "issued_at": 1769800000,
  "expires_at": 1769803600,    // 短，建议 ≤1h
  "kms_sig": "…"               // KMS 签，launcher 用 KMS RA-TLS 证书验
}
```

### 4.4 UsageReceipt（KMS → 平台，经 CLI 回流，§9 对账）

```jsonc
{
  "user_id": "cust-acme",
  "kms_pubkey": "0x02ab…",
  "report_period": {"from": …, "to": …},
  "active_slots": [ {"slot_id":"…","app_id":"…","instance_id":"…","first_seen":…,"last_seen":…} ],
  "high_water_time": 1769886400,   // KMS 见过的最大可信时间（抗回滚审计）
  "kms_sig": "…"
}
```

---

## 5. Courier Attestation + Root Key 下发协议（平台 ↔ KMS，CLI 当信使）

目标：在 CLI 不可信、KMS 无公网的前提下，平台**远程证明 KMS 确在合规 TDX 内**，并把**平台生成的 root key 机密下发**给该 KMS，同时下发授权（AuthBundle，含 CEK）。

**v3 关键点**：transport 密钥生成、sealed root 接收与解封、root 写 volume——全部在 **sidecar** 里完成。KMS core 只是等 sidecar healthcheck 通过后 `Keys::load()` 读文件，**core 零改动**。sidecar 同样挂了 `/var/run/dstack.sock`，可独立出 TDX quote；quote 的 MRTD/RTMR 覆盖整个 CVM（包含 sidecar + core 在内的 app-compose.json measurement）。

```
平台                    CLI(笔记本)               KMS CVM / sidecar (VPC, 首次无 root)
 │  1. POST /challenge  │                          │
 │ ◀────────────────────┤  (customer_id)            │
 │  {nonce, authority_ts}│                          │
 ├─────────────────────▶│  2. 携入 VPC              │
 │                      ├── POST sidecar:8001/init ▶│ sidecar: 生成 transport X25519 keypair
 │                      │                          │ 读 kms_ts（guest 当前时间）
 │                      │                          │ report_data = SHA512(nonce‖transport_pub‖kms_ts)
 │                      │                          │ dstack.sock → TDX quote
 │                      │◀── {quote, transport_pub, kms_ts}
 │◀─────────────────────┤  3. 携出 VPC              │
 │  {quote, transport_pub, kms_ts, nonce}
 │  4. 平台验证：
 │     • quote 签名（Intel PCS，平台在线）
 │     • MRTD/RTMR ∈ 期望 KMS app-compose 集合
 │     • report_data == SHA512(nonce‖transport_pub‖kms_ts)
 │     • nonce 新鲜未用（防重放）
 │     • |kms_ts − authority_ts| ≤ SKEW_THRESHOLD（§7.2）
 │  5. 取该 customer root_key（HSM）
 │     sealed_root = HPKE(transport_pub, root_key)
 │     派生 KMS 签名公钥 → 写 CLI trusted_signers（去 TOFU）
 │  6. 组装 ProvisionPackage：
 │     { sealed_root, AuthBundle（含 CEK、白名单、slot_quota，authority_sig） }
 ├─────────────────────▶│  7. 携入 VPC              │
 │                      ├── POST sidecar:8001/install▶│ sidecar: transport_priv 解出 root_key
 │                      │                          │ 验 AuthBundle authority_sig
 │                      │                          │ 写 /kms/root-ca.key 等文件到 kms-volume
 │                      │                          │ 持久化 AuthBundle（白名单/CEK/slot_quota）
 │                      │                          │ → healthcheck 文件就绪 → healthy
 │                      │◀── {ack}                  │ （kms core 随后自动启动）
 │◀─────────────────────┤  8. 回执到平台             │
```

**后续 courier（定期续期/更新授权）**：跳过 transport/quote 部分，只走步骤 6–8（sidecar 有了 root，直接验签并更新 AuthBundle），同时上传 UsageReceipt 回执（§9）。

要点：
- **root key 机密性**：sealed_root 只能被绑定了该 `transport_pub` 的 TEE 解封，transport 私钥永不出 sidecar 内存。
- **去 TOFU**：平台下发 root → 预知 KMS 签名公钥（root 派生）→ 直接写 CLI `trusted_signers`，替换现有交互式 TOFU。
- **DR 重新下发**：KMS CVM 损毁 → 新实例重走 provision → 平台重发同一 root → 老 workload disk/env 密钥可恢复（§10.4）。
- **nonce 防重放 / measurement 白名单 / 平台公钥固化进 KMS 镜像**（度量的一部分，CLI 无法替换）。
- **CLI 全程仅搬运**：sealed_root、AuthBundle 端到端封装/签名，CLI 篡改即失败。

> **实现**：sidecar 是全新服务（Rust 或 Go），暴露 HTTP/prpc；core 仅在 docker-compose 加 `depends_on` + 指向 sidecar 的 `AUTH_WEBHOOK_URL`。**KMS core 代码零修改。**

---

## 6. 实例数量授权（S2）

裸计数器在"客户有 root + 可快照"的威胁下不可靠。采用 **平台签发 slot + KMS 绑定** 模型。

### 6.1 模型

- 平台按合同签发 `slot_quota`（或 N 张 `SlotToken`），随 AuthBundle 下发。
- 每个 launcher 启动时经 mTLS 向 **sidecar** 申请租约，sidecar：
  1. 校验 launcher cert 内嵌 compose_hash ∈ `allowed_launcher_hashes`（launcher 镜像白名单）；
  2. 取一个**未占用** slot，绑定 `slot_id → (instance_id, compose_hash)`，**持久化到 sidecar 存储**；
  3. 签发 Lease（sidecar 签名）。
- slot 与**业务镜像版本无关**——业务镜像热更新不影响 slot 绑定，无需重新申请 slot。
- **并发上限 = slot_quota**。已绑定 slot 仅对**同一 instance_id**续租；其它 instance 申请同 slot 被拒。
- slot 释放：Lease 过期且超过释放阈值未续 → slot 回收，可被新实例占用。

### 6.2 抗克隆（做） / 抗回滚（v1 暂不做，TODO）

- **抗克隆（v1 实现）**：客户克隆 CVM（同 `instance_id_seed`）→ 同 `instance_id`，会撞上"已被另一活跃实例占用"——KMS 拒绝第二个并发绑定（以最近续租活跃者为准）。
- **抗回滚（v1 暂不做 — TODO）**：客户可快照恢复 KMS 数据盘以重置 slot 绑定表/计数器，从而绕过数量上限。v1 **不做强抗回滚**，已知缺口接受。

> **TODO（抗回滚）**：后续可选方案——① TDX/vTPM 单调计数器或 sealed monotonic state（取决于 GCP Confidential VM 是否提供，见 §15 Q2）；② `bundle_seq` / 时间高水位持久化 + 倒退即拒绝告警；③ §9 用量回执到平台对账，由平台侧发现异常重置。当前阶段把"平台是数量权威、KMS 是执行点"作为模型，强保证延后。

---

## 7. 租约、可信时间与 Kill-switch（S3 / G9）

### 7.1 Launcher 续租循环

```
启动: attest→KMS→{CEK, Lease}
       拉密文→解密→验 digest→docker compose up
循环(每 T_refresh，建议 = lease_ttl/3):
   attest→KMS→续租
   成功: 更新本地 lease，继续
   失败:
      若 now < lease.expires_at + GRACE: 继续运行(容忍 KMS 抖动)
      若 now ≥ lease.expires_at + GRACE: 执行 stop_action
```

- `stop_action`：默认 **停 workload 容器**（`docker compose down`），launcher 自身保活并持续尝试续租；可配置升级为关机/擦运行时密钥。
- `GRACE`：fail-open 窗口，平衡可用性与可控性（建议默认 1×lease_ttl）。

### 7.2 可信时间（v2 简化方案）

v2 **假定 KMS 内部时间可信**，不做 v1 的 high-water 复杂方案。靠 courier 时的平台校验做粗校准：

- **Courier 时间锚**：每次 courier（§5 step 4），平台比对 KMS 上报的 `kms_ts` 与平台自身可信时间，`|kms_ts − authority_ts| > SKEW_THRESHOLD`（建议 ±5min）则**拒绝下发 root/AuthBundle**。这迫使 KMS 时钟在每次 courier 时落在可信窗口内。
- **两次 courier 之间**：KMS 用自身本地时钟判断 Lease/AuthBundle 的 `expires_at`，视为可信。
- **副作用即心跳**：AuthBundle 有 `expires_at`，客户必须周期性跑 CLI 去平台续取新 bundle（且每次都过时间偏差检查）才能不过期。**"运维不再来取授权"== 整套授权自然到期停服**，这是离线 kill-switch。
- **已知残余风险（接受）**：两次 courier 之间，拥有 root 的客户仍可操纵 KMS guest 时钟（TDX 下 guest 时间源自宿主，除非启用 `secure_time`）来延长本地判定的有效期。v2 接受此风险。
  - **TODO（加固）**：启用 dstack `secure_time`（app.json 已有该选项）作为时间锚；或回退到 v1 high-water（`effective_now = max(local, 见过的最大平台签名时间)`，时钟拨回无法延长租约）。

---

## 8. 镜像管理（G5 / G6 / G7，S1）

本系统涉及**两类完全独立的 Docker 镜像**，更新路径截然不同：

| | Launcher 镜像 | 业务镜像（workload） |
|---|---|---|
| **运行方** | dstack guest-agent（CVM 启动时） | Launcher（运行时动态管理） |
| **声明位置** | app-compose.json（`docker_compose_file`） | AuthBundle（`allowed_images`） |
| **TDX 度量** | ✅ 是（compose_hash 覆盖 app-compose.json） | ❌ 否 |
| **加密方式** | 不加密（boot 时 sidecar 尚未联系） | CEK 加密（ocicrypt） |
| **版本权威** | app-compose.json 中的 image digest | AuthBundle.current_image_digest |
| **更新方式** | **冷更新**（重建 CVM） | **热更新**（launcher 在线替换） |
| **白名单字段** | `allowed_launcher_hashes` | `allowed_images[].digest` |

### 8.1 Launcher 镜像——冷更新路径

Launcher 镜像的 digest 固化在 app-compose.json 里，是 TDX 度量的一部分。变更它必须重建 CVM：

```
Vendor 发布新 launcher 镜像:
  1. 推新镜像到公共 registry，得到 new_launcher_digest
  2. 平台更新：新 app-compose.json（image 改为 @new_launcher_digest）
               → 算出新 compose_hash
               → 签发新 AuthBundle（allowed_launcher_hashes 加入新 compose_hash，
                                   旧值保留过渡期后删除）

运维操作:
  dstack-cloud image sync vendor/launcher:v2   # 同步 launcher 镜像到 GCP AR
  dstack-cloud kms sync-auth                   # 推新 AuthBundle（新 compose_hash 进白名单）
  dstack-cloud workload deploy --delete        # 重建 workload CVM（新 app-compose.json）
```

**Launcher 的 app-compose.yaml 结构**（被度量，只含 launcher 容器本身）：

```yaml
services:
  launcher:
    image: us-central1-docker.pkg.dev/customer/repo/launcher@sha256:abc…  # 固定 digest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock   # 管理业务容器
      - /var/run/dstack.sock:/var/run/dstack.sock   # 出 TDX quote
    environment:
      - SIDECAR_URL=https://<kms-internal-ip>:8002
      - APP_ID=40hex
      - WORKLOAD_IMAGE=us-central1-docker.pkg.dev/customer/repo/workload
      # 只有 image 名，无 tag/digest——版本由 AuthBundle.current_image_digest 控制
    restart: unless-stopped
# 业务容器不在此处，由 launcher 运行时动态生成 compose 并调用 docker compose up 管理
```

### 8.2 业务镜像——热更新路径

业务镜像不参与度量，launcher 在线管理。度量覆盖靠 sidecar 的双重门控弥补：

> **CEK 释放门控：`(launcher compose_hash ∈ allowed_launcher_hashes) ∧ (requested digest ∈ allowed_images)`；launcher 解密后必须校验 `digest == 请求值` 才执行。**

**CEK 托管与下发流程：**

```
平台（TEE 外）:
  生成 CEK → ocicrypt 加密业务镜像 → 推公共 registry（+cosign 签名）
  CEK 写入 AuthBundle.allowed_images[].cek（authority_sig 覆盖整个 bundle）

Courier（§5）:
  CLI 把 AuthBundle → sidecar，sidecar 验 authority_sig → 持久化（含所有 CEK）

Launcher 启动（mTLS 流程）:
  1. get_app_key → KMS core 签发 RA-TLS cert（含 launcher measurement，链到 KMS CA）
  2. Launcher → sidecar:8002 mTLS
       Client cert: KMS core 签发的 RA-TLS cert（内嵌 launcher measurement）
       Server cert: sidecar 自身 cert（同一 KMS CA 签）
  3. Sidecar 验证：
       • cert 链到 KMS CA ✓
       • cert 内嵌 compose_hash ∈ allowed_launcher_hashes ✓
       • 申请的 image_digest ∈ allowed_images ✓（且未过 expires_at）
       • slot 可用，绑定（§6）✓
  4. Sidecar 返回：该 digest 对应的 CEK + Lease
  5. Launcher：从 GCP AR 拉加密镜像 → ocicrypt 解密 → 校验 digest → docker compose up
  6. 续租循环（§7.1）
```

**热更新循环（业务镜像版本切换）：**

```
主循环（每 POLL_INTERVAL ≈ 30s）:
  sidecar mTLS GET /version?app_id=X
  → { current_image_digest, bundle_seq }

  if bundle_seq 变化 且 current_image_digest != running_digest:
    1. 向 sidecar 取 new_digest 的 CEK（mTLS，失败→告警，继续跑旧版）
    2. 后台拉加密镜像（不打断当前 workload）
    3. ocicrypt 解密 → 校验 digest
    4. docker compose up --no-deps <service>（逐服务滚动替换）
    5. 健康检查窗口（默认 60s）：
         通过 → running_digest = new_digest，上报 sidecar
         失败 → 自动回滚到 old_digest（须仍在 allowed_images 且未过期）
```

**业务镜像版本发布操作（平台侧 + 运维侧）：**

```
Vendor（我们）:
  加密新版业务镜像，更新平台 AuthBundle：
    allowed_images += { digest: new_digest, cek: new_cek }
    current_image_digest = new_digest
    旧 digest 保留回滚窗口（建议 7 天），设 expires_at 后自动下线

运维操作（两步，顺序不强制，launcher 容忍镜像先到或后到）:
  dstack-cloud image sync vendor/workload:v2   # 同步加密业务镜像到 GCP AR
  dstack-cloud kms sync-auth                   # 推新 AuthBundle → sidecar 更新白名单

Launcher（无需重启 CVM）:
  下一个轮询周期（≤30s）自动发现版本变化并执行热更新
  或立即触发：dstack-cloud workload update <instance-name>
```

**mTLS 证书说明：**
- CEK 不经 KMS core，完全走 sidecar。
- Sidecar cert：sidecar 启动时调 KMS core 的现有 `SignCert` RPC（`kms_rpc.proto:107`）签发，或直接复用 `tmp_ca_cert`。
- CEK 明文仅存于 sidecar 内存和 launcher 内存（均在 TEE 内），不落盘。

**实现选型：**
- 推荐：ocicrypt + 自定义 keyprovider（launcher 侧 keyprovider 回调 sidecar:8002 取 CEK）。
- 备选：整镜像 AES-256-GCM 封装 → `docker load`（实现简单，失去分层缓存）。

### 8.3 Registry 同步完整性（G5）

两类镜像的同步都走 `dstack-cloud image sync`，处理方式相同：

1. 从公共 registry 按 **digest** 拉取镜像 + cosign 签名；
2. 用**平台公钥**验 cosign 签名（防镜像被替换）；
3. 按 digest 原样 re-push 到客户 GCP AR（业务镜像不解密）。

Launcher 拉取时以 digest 锚定，三处一致（平台白名单 / GCP AR / 拉取结果）才继续。

---

## 9. 用量回执与对账（S5 兜底 / 计费）

air-gap 下平台只控制"发了多少授权"，要观测"实际用了多少"需离线回流：

- KMS 周期性生成 `UsageReceipt`（§4.4），含活跃 slot 绑定、`high_water_time`、`bundle_seq`。
- CLI 在每次 courier 往返时把回执带回平台。
- 平台对账：
  - `active_slots` ≤ `slot_quota`？异常即告警/缩减下次授权。
  - `bundle_seq` / `high_water_time` 是否倒退（检测 KMS 被回滚重置）。
  - 用量计费。
- **运维不回流回执** → 平台不再签发新 bundle → 现有 bundle 到期停服（与 §7 心跳一致）。

---

## 10. air-gap 基础设施

### 10.1 PCCS / quote 验证 collateral

- 双向 RA-TLS 均需 Intel collateral（TCB info / QE identity / PCK CRL）；`pccs_url` 当前为空。
- VPC 内架 **PCCS 镜像**，`.sys-config.json.pccs_url` 指向它。
- collateral **会过期**：CLI courier 往返时顺带刷新 PCCS 缓存（平台在线拉 Intel PCS → CLI 带入 → 灌 PCCS）。
- 平台侧验 KMS quote 直接用其在线 PCS 访问。

### 10.2 OS 镜像 / TCB recovery 生命周期

- `os_image_hash` 烧进 `.sys-config.json` 并受白名单约束；Intel 微码更新或新 dstack OS 镜像会改 measurement。
- 流程：平台发布新镜像 hash → 更新 KMS 期望 measurement（§5）与 app 白名单 → CLI 分发新镜像 + 新 AuthBundle → 设过渡期同时允许新旧 measurement，再下线旧值。
- KMS 不能用 SPOT（见 10.4）。

### 10.3 网络模型（需与客户确认）

- **澄清"air-gap"程度**：CLI 出口在哪？（运维笔记本同时可达 VPC 与公网 = 半离线 courier；或纯 sneakernet 文件交换。）这决定 §5 协议是否需打包成离线文件包。
- **无公网 → gateway 的 ACME 签证不可用**：若 workload 需 ingress，仅走 VPC 内网 + `dstack-cloud fw`；对外暴露需客户自备内部 CA 或预置证书。
- 默认假设：workload 内网访问，不依赖公网 gateway。

### 10.4 KMS 灾备 / HA（S 之外的可用性）

- **v2 灾备天然成立**：root key 由平台生成并持有（§5），KMS CVM 损毁后，新实例重走 provision，平台**重新下发同一个 root_key**（仅交付给重新验证过的合规 measurement）→ 老 workload 的 disk/env 密钥可恢复。无需额外 escrow 流程。
- 可选 **HA 多节点**：多 KMS 实例各自从平台 provision 到同一 root（或 KMS 间 RA-TLS 复制，dstack 已有机制），降低单点恢复时延。
- **KMS 实例用 STANDARD provisioning**（非 SPOT），持久盘 + 重启；重启后若本地 root 仍在（已加密落盘）直接用，否则重走 provision。
- 代价同 §2 信任取舍：平台持 root 即可解客户数据。

---

## 11. 撤销与多租户

- **撤销**：AuthBundle.revocations 携带被吊销的 compose_hash / image_digest / slot_id；KMS 即时拒绝。配合短 Lease，撤销最长在 1×lease_ttl + 一次 courier 周期内生效。
- **多租户**：平台为每客户独立签名子密钥（或在 bundle 内绑 `customer_id`），KMS 出厂绑定其 `customer_id`，防一个客户授权被重放到另一处。
- **密钥轮换**：平台签名密钥轮换时，新公钥经 attest 通道下发并在 KMS 内维护"当前+下一把"双公钥过渡。

---

## 12. CLI 命令面（dstack-cloud 扩展）

```
# KMS 生命周期
dstack-cloud kms deploy            # 部署 KMS CVM（STANDARD, 持久盘）
dstack-cloud kms attest            # 跑 §5 courier：取 challenge→KMS quote→平台验→落 AuthBundle
dstack-cloud kms sync-auth         # 周期性：取新 AuthBundle + 回流 UsageReceipt + 刷 PCCS collateral
dstack-cloud kms status            # 显示 bundle_seq / 活跃 slot / high_water_time

# 镜像同步（launcher 镜像和业务镜像都用同一命令）
dstack-cloud image sync <ref>           # 从公共 registry 验 cosign 签名，push 到 GCP AR

# Workload（launcher CVM 生命周期）
dstack-cloud workload deploy            # 部署 launcher CVM（含 app-compose.json，指定 launcher 镜像）
dstack-cloud workload deploy --delete   # 重建 CVM（launcher 镜像冷更新时使用）
dstack-cloud workload update <name>     # 立即通知 launcher 检查业务镜像版本（跳过轮询等待）
dstack-cloud workload status/logs/stop/remove
```

- `kms attest` / `sync-auth` 是 courier 入口；离线场景产出/消费一个可签名校验的离线文件包（`*.authpack`）。
- CLI 内置平台 API 端点与客户凭据；但**安全不依赖 CLI**——所有授权端到端签名。

---

## 13. 启动与运行时序（workload 侧汇总）

```
── 首次部署（含 launcher 镜像确定）──────────────────────────────────
1. Vendor 发布 launcher 镜像 → 平台签发含 allowed_launcher_hashes 的 AuthBundle
2. dstack-cloud image sync vendor/launcher:v1       # launcher 镜像同步到 GCP AR
   dstack-cloud kms sync-auth                       # 推 AuthBundle 到 sidecar
3. dstack-cloud workload deploy
     → 造 shared 盘（app-compose 指定 launcher@digest，.sys-config{kms_urls,pccs_url}）
     → gcloud 建 TDX CVM

── CVM 启动序列 ──────────────────────────────────────────────────────
4. guest-agent RA-TLS → KMS core.get_app_key（disk/env key，现有链路不变）
5. Launcher 容器启动（由 guest-agent 按 app-compose.json 拉起）:
     a. get_app_key → KMS core 取 RA-TLS cert（含 launcher measurement，链到 KMS CA）
     b. mTLS → sidecar:8002
          sidecar 验: compose_hash ∈ allowed_launcher_hashes ✓
                      current_image_digest ∈ allowed_images ✓
                      slot 可用 ✓
          sidecar 返: current_image_digest 对应的 CEK + Lease
     c. 从 GCP AR 拉加密业务镜像（按 current_image_digest）
     d. ocicrypt 用 CEK 解密 → 校验 digest
     e. 生成业务 docker-compose.yaml（image = workload_image@current_digest）
     f. docker compose up（业务容器启动）

── 运行时循环 ────────────────────────────────────────────────────────
6. 每 POLL_INTERVAL（≈30s）:
     mTLS → sidecar GET /version → 检查 current_image_digest 是否变化
     若变化 → 热更新业务镜像（§8.2 热更新循环）
7. 每 T_refresh（≈lease_ttl/3）:
     mTLS → sidecar 续 Lease
     失败超 GRACE → docker compose down（停业务容器）

── Launcher 镜像冷更新（需重建 CVM）─────────────────────────────────
8. dstack-cloud image sync vendor/launcher:v2
   dstack-cloud kms sync-auth                       # 新 compose_hash 进白名单
   dstack-cloud workload deploy --delete            # 重建 CVM，旧业务容器随之停止
   # 新 CVM 启动后重走步骤 4–6，业务镜像从 current_image_digest 重新拉取
```

---

## 14. 分阶段实施计划

| 阶段 | 内容 | 交付的安全目标 |
|------|------|----------------|
| **P0** | **KMS sidecar**（新容器）：courier 端点（transport key + sealed root + AuthBundle 接收，§5）、auth webhook（替 auth-eth）、静态白名单；KMS core docker-compose 加 `depends_on` + `AUTH_WEBHOOK_URL` 指向 sidecar。**KMS core 零改动。** CLI `kms attest`。 | S1, S4 |
| **P1** | Sidecar 加：slot 绑定（抗克隆）+ Lease 签发/续租 + CEK mTLS 下发（§8.2）；launcher 续租循环 + kill-switch（§7.1）。 | S2, S3 |
| **P2** | 加密镜像（ocicrypt）+ CEK 托管链（§8）；launcher 解密/验 digest；CLI `image sync` + cosign 校验。 | S1(强化), G5/G6/G7 |
| **P3** | PCCS 镜像 + collateral 刷新；OS/TCB 生命周期；UsageReceipt 回执对账（§9）；撤销；KMS HA/DR；多租户密钥隔离。 | S5(完整), 运维闭环 |

---

## 15. 待确认问题（Open Questions）

1. **air-gap 程度**：CLI 是半离线（笔记本两边可达）还是纯 sneakernet？决定 courier 是否需离线文件包。
2. **root key 隐私取舍（v2 已定方向，待客户确认）**：接受「平台持 root → 平台可解客户数据」以换取密钥派生简化与 DR？若客户不接受，需回退 v1 自举 root 方案（§2 信任取舍）。
3. ~~**签名算法**~~ ✅ **已定：Ed25519**（平台 AuthBundle 签名）。
4. **stop_action 语义**：超时是停容器、关机、还是擦运行时密钥？是否允许客户配置？
5. ~~**镜像加密粒度**~~ ✅ **已定：标准 ocicrypt**（keyprovider gRPC，launcher 侧跑 keyprovider 进程回调 sidecar:8002 取 CEK）。
6. **gateway**：workload 是否需要对外 ingress？若需，无公网下证书方案。

**已转为 TODO（v1 暂不做，见正文）**：
- **抗回滚**（§6.2）：GCP Confidential VM 是否提供可用的 vTPM 单调计数 / sealed monotonic state 待调研；当前接受数量上限可被快照回滚绕过。
- **可信时间加固**（§7.2）：`secure_time` 或 high-water；当前假定 KMS 内时间可信 + courier 偏差检查。

---

## 附录 A：相关现有代码索引

- CLI：`meta-dstack-cloud/scripts/bin/dstack-cloud`
  - 部署：`deploy()`、`_create_shared_disk_image()`、`_check_and_upload_boot_image()`
  - env 加密：`_encrypt_env()`、`_get_app_encrypt_pub_key()`
  - 现有 KMS 验签/白名单：`_verify_signature()`、`_load_whitelist()`（`~/.config/dstack-cloud/kms-whitelist.json`）
  - sys-config（含 pccs_url/os_image_hash）：`_generate_sys_config()`
- KMS：`dstack/kms/src/onboard_service.rs`（bootstrap/root key/quote）、`dstack/kms/src/main_service.rs`（`get_app_key`、KDF 派生）
- auth 后端：`dstack/kms/auth-eth`（链上，要替换）、`dstack/kms/auth-simple`（本地 JSON，可借鉴）
- env 加密规范：`dstack/docs/encrypted-env-spec.md`；解密：`dstack/dstack-util/src/crypto.rs`
- Launcher 骨架参考：`github.com/Dstack-TEE/dstack-examples/tree/main/launcher`
- 私有 registry 参考：`github.com/Phala-Network/ttc-dstack-recipes`（`h100-tdx/`，GCP AR + SA IAM）

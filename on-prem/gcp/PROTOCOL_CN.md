<!-- SPDX-License-Identifier: Apache-2.0 -->
# 协议速览（GCP 私有化部署）

部署背后的密码学协议——**每条消息携带什么、每一跳校验什么**。命令见
[`QUICKSTART_CN.md`](QUICKSTART_CN.md);操作走查见
[`DEPLOYMENT_GUIDE_CN.md`](DEPLOYMENT_GUIDE_CN.md)。

> English: [`PROTOCOL.md`](PROTOCOL.md)

## 角色与信任根

| 角色 | 位置 | 持有 / 证明 |
|---|---|---|
| **Authority** | 厂商主机（在线） | Ed25519 **AuthBundle 签名私钥**(其公钥 = `AUTHORITY_PUBKEY`,**授权信任根**,被钉进被度量的 KMS compose);各租户 **KMS root**(P-256 root-CA + secp256k1 k256);**全局镜像密钥环**(EC P-256 私钥) |
| **Verifier** | 厂商主机 | 校验 TDX+vTPM quote、重放 event log、提取 `os_image_hash` / `compose_hash` / `key_provider` / `tcb_status` / `report_data` |
| **Courier CLI**（`kms_ctl.py` / `dstack-cloud`） | operator 主机 | **不可信中继**——只在 Authority 与 CVM 间搬运不透明 blob,从不是信任锚 |
| **key-broker** | KMS CVM 内（TEE） | 终结 courier;HPKE 解封 sealed root;验 AuthBundle;物化 KMS keyset;对 workload 提供 `bootAuth` + `lease` |
| **dstack-kms** | KMS CVM 内（TEE） | 从物化 keyset 启动,TLS `:8000` 服务,派生各 app 密钥 |
| **launcher** | workload CVM 内（TEE） | 向 key-broker 做 RA-TLS;租取镜像密钥环;解密 JWE 镜像;运行并监管业务 |
| **guest-agent** | 每个 CVM 内 | 产出 TDX+vTPM attestation 并绑定到 `report_data` |

**信任脊柱**:厂商只掌一个秘密(Ed25519 签名私钥)。它的公钥被**度量进** KMS compose——
所以被改过的 Authority 伪造不出 AuthBundle,被改过的 compose 会改变 `compose_hash`、在 provision 时被拒。

---

## 阶段 A —— KMS 开通（courier attest）

目标:把 root key 交给 KMS,**全程不让 operator 看到**,且只交给厂商密码学批准过的 CVM。

```
guest-agent  key-broker      CLI(operator)    Authority       Verifier
 │                │                │──challenge──▶│               │
 │                │                │◀───nonce─────│               │
 │                │◀─courier/init──│              │               │
 │                │ gen X25519 kp  │              │               │
 │                │ rd=SHA-512(…)  │              │               │
 │◀──Attest(rd)───│                │              │               │
 │─TDX+vTPM quote▶│                │              │               │
 │                │─tpub,ts,attest▶│              │               │
 │                │                │──provision──▶│               │
 │                │                │              │────verify────▶│
 │                │                │              │◀───verdict────│
 │                │                │              │ G1 quote✓     │
 │                │                │              │ G2 rd-bind✓   │
 │                │                │              │ G3 tcb✓       │
 │                │                │              │ G4 os_image✓  │
 │                │                │              │ G5 kp=tpm✓    │
 │                │                │              │ G6 compose✓   │
 │                │                │              │ HPKE-seal root│
 │                │                │              │ Ed25519-sign  │
 │                │                │              │ seq++         │
 │                │                │◀root+bundle──│               │
 │                │◀───install─────│              │               │
 │                │ verify sig     │              │               │
 │                │ seq strictly↑  │              │               │
 │                │ HPKE-open root │              │               │
 │                │ SAN = CVM IP   │              │               │
 │                │ keyset → _ready│              │               │
 │                │ kms → :8000    │              │               │
```

1. **challenge** —— CLI 用租户 API key 认证;Authority 返回无状态 HMAC `nonce`(带 TTL)。
2. **courier/init** —— key-broker 现场生成**每会话 X25519 transport 密钥对**,盖 `kms_ts`,
   算 `report_data = SHA-512(nonce ‖ transport_pub ‖ kms_ts_LE)`(64 字节),让 guest-agent
   对该 `report_data` 做完整 **TDX + vTPM** attestation。返回 `transport_pub`、`kms_ts`、
   attestation、`vm_config`。
3. **provision** —— Authority 重放校验 nonce(MAC + TTL)、检查时钟偏差 ≤ 300s,把 attestation
   交给 Verifier,再对返回的 verdict 跑下面六道 fail-closed 关卡(G1–G6)。通过后把 root 载荷
   (P-256 root-CA 私钥 + k256 标量 +
   domain)**HPKE 封到 `transport_pub`** → `sealed_root`,`bundle_seq` 自增,并对 AuthBundle
   做 **Ed25519 签名**(app 白名单 + 全局镜像密钥环 + os-image 白名单 + 吊销表)。
4. **courier/install** —— key-broker **用 compose 里钉死的 `AUTHORITY_PUBKEY` 验 AuthBundle 签名**,
   强制 **`bundle_seq` 严格递增**(抗回滚),用会话 transport 私钥 **HPKE 解封** `sealed_root`
   (只有这个 TEE 持有该私钥),把 **rpc 证书 SAN 设成 CVM 自己的内网 IP**,物化 dstack-kms
   keyset(`root-ca` / `tmp-ca` / `rpc` / `k256`),写 `_ready`。
5. **boot** —— dstack-kms 的 wait-loop 看到 `_ready` 就 exec,在 `:8000` 提供 TLS。它自己启动时
   调 key-broker `bootAuth/kms`,**再查**一遍 os-image + tcb + device(fail-closed)。

operator 的 CLI 全程只拿到两坨**不透明** blob(`sealed_root`、`auth_bundle`)。G2 是抗替换的命门:
一个没绑定到**我们的** `transport_pub` 的真 quote 也会被拒——所以中继的 CLI 换不进自己控制的密钥。

---

## 阶段 B —— Workload 启动（RA-TLS 租约）

目标:workload CVM 只有**重新自证**身份给(已起的)KMS 后才拿到镜像解密密钥;一旦停止自证就失去它。

```
 launcher(workload CVM)        key-broker(KMS CVM)
  │───────bootAuth/app(BootInfo)───────▶│
  │                                     │ os_image✓ tcb✓ app_id✓ compose✓ device✓
  │◀──────────────allowed───────────────│
  │──────────RA-TLS handshake──────────▶│
  │                                     │ mutual; launcher cert embeds TDX quote
  │─────────────get version────────────▶│
  │◀─────image_digest, bundle_seq───────│
  │────────────lease/acquire───────────▶│
  │                                     │ re-run gates; digest ∈ allowed_workload_digests
  │                                     │ bind slot_id → (instance, compose)
  │◀──────Lease(signed) + keyset────────│
  │  write privkeys → tmpfs             │
  │  ocicrypt JWE decrypt(image@digest) │
  │  run decrypted workload             │
  │─────lease/renew  (every ttl/3)─────▶│
  │  renew fail → re-acquire            │
  │  (re-runs every gate)               │
  │  past grace → stop workload         │
```

1. **bootAuth/app** —— 任何解密之前,key-broker 先按被度量的 `BootInfo`(os-image、tcb、app_id、
   compose_hash、device)把关 boot。
2. **RA-TLS** —— 双向 TLS,launcher 的客户端证书**内嵌它的 TDX quote**,所以 key-broker 认证的是
   **硬件**,不是某个 bearer token。
3. **lease/acquire** —— 重跑授权关卡,额外要求 `image_digest ∈ app.allowed_workload_digests`,
   把 **`slot_id`** 绑到 `(instance_id, compose_hash)`(抗克隆),返回**已签 Lease + keyset**
   (全局镜像私钥)。
4. **解密 + 运行** —— launcher 把租来的每个私钥喂给 `skopeo`;ocicrypt(原生 JWE,ECDH-ES)用其中
   作为镜像 recipient 的那把解密,然后运行。
5. **renew** —— 每 `ttl/3` 续租;续租失败触发完整重新 acquire(对**实时** AuthBundle 重跑**所有**
   关卡);若过宽限期仍失败,业务容器被**停掉**——授权是持续的,不是一次性的。

---

## Fail-closed 关卡（整个策略面）

| # | 关卡 | 在哪强制 | 何时拒绝 |
|---|---|---|---|
| G1 | quote 真实 | Authority/Verifier | TDX+vTPM quote 非硬件根 |
| G2 | `report_data` 绑定 | Authority | quote 未绑定本会话 `transport_pub`/nonce |
| G3 | tcb 状态 | Authority **+** key-broker | tcb ∉ 允许集(空/缺 ⇒ 拒) |
| G4 | os-image 哈希 | Authority **+** key-broker | os-image ∉ 白名单(**空 ⇒ 拒**) |
| G5 | key_provider == `tpm` | Authority | 磁盘非 vTPM 封(`kms`/`local`/`none`) |
| G6 | KMS compose 哈希 | Authority | compose ∉ kms-compose 白名单(**空 ⇒ 拒**) |
| G7 | AuthBundle 签名 | key-broker | 签名 ≠ 钉死的 `AUTHORITY_PUBKEY` |
| G8 | `bundle_seq` 单调 | key-broker | `new_seq ≤ stored_seq`(回滚) |
| G9 | app_id ∈ 白名单 | key-broker | app 未为该租户注册 |
| G10 | launcher compose 哈希 | key-broker | compose ∉ `allowed_launcher_digests` / 已吊销 |
| G11 | workload 镜像 digest | key-broker | digest ∉ `allowed_workload_digests` |
| G12 | 租约存活 | launcher | renew + 重 acquire 过宽限仍失败 ⇒ 停 workload |

每个基于列表的关卡都在**空列表**时拒绝——没配置的策略就是**关闭**的策略,绝不会变成放行。

## 密码学原语

- **Quote 绑定** —— `report_data = SHA-512(nonce ‖ transport_pub ‖ kms_ts_LE)`;Authority 用同一
  公式重算(G2)。把某一个具体 quote 绑死到某一个具体会话 transport 密钥。
- **Root 封装** —— HPKE(RFC 9180):`DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` +
  `AES-256-GCM`,base 模式,`info = "dstack-courier-root-v1"`。封到每会话 `transport_pub`,
  只有铸它的那个 TEE 内能解。
- **AuthBundle** —— 对规范化(`sort_keys`、紧凑)JSON 做 Ed25519 签名;用**度量进** KMS compose 的
  `AUTHORITY_PUBKEY` 验;`bundle_seq` 严格单调以抗回滚。
- **镜像加密** —— ocicrypt **原生 JWE**(ECDH-ES,EC P-256)。**只用公钥**加密
  (`skopeo copy --encryption-key jwe:pub.pem`),构建机不持任何解密秘钥。私钥租给已 attest 的
  launcher,launcher 以 `--decryption-key` 喂入;ocicrypt 逐一试匹配 recipient。
- **KMS root** —— P-256 root-CA(KMS KDF 抽其标量派生各 app/disk/env 密钥)+ secp256k1 k256
  (身份签名)。Authority 持有以做 DR;每次 provision 时 HPKE 封装。

## 信任边界（看两遍）

- **HPKE 端到端保护 KMS root** —— `sealed_root` 对目标 TEE 机密,中继的 operator 看不到 KMS root
  或任何派生密钥。
- **AuthBundle 是完整性保护,不是加密。** 它被签名(G7),所以 operator **伪造/篡改**不了它,但其
  `keyring`(全局镜像私钥)是**明文**穿过 courier 中继的。所以开通 KMS 的那个 operator **位于镜像
  机密性边界之内**——镜像加密防的是 registry、网络、镜像落盘,**而不是**这个 operator。这与设计中
  v2 既定取舍一致("平台/厂商可解客户数据");若你的威胁模型要把 operator 也排除在镜像密钥之外,需
  把 bundle 的 `keyring` 也 HPKE 封到 `transport_pub`。

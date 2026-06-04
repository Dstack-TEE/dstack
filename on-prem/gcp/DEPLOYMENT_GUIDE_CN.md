<!-- SPDX-License-Identifier: Apache-2.0 -->
# dstack 私有化部署向导（GCP）— 分角色 step-by-step

面向**客户自有 GCP 环境**的端到端部署。全程区分两个角色：

- **厂商侧（Vendor）** —— 掌控信任根，有公网。负责：起 Authority、生成镜像密钥、构建并加密镜像、注册授权白名单、把"安全 pin"（公钥 + 镜像 digest）填进 compose 模板。**从不接触客户 GCP。**
- **operator 侧（Operator）** —— 客户的 GCP 运维。负责：把镜像同步进自己的 Artifact Registry、部署 CVM、跑 courier、做出网硬化。**从不持有厂商签名私钥。**

每一步都标了 **【厂商】/【Operator】**，并逐条解释命令作用。本文用 shell 变量占位，按需替换。

---

## 总览：三个角色与信任模型

```
         ┌──────────────┐      【厂商主机 · 有公网】
         │  Authority   │      签发 AuthBundle、HPKE 封装根密钥、校验 KMS 远程证明
         │  + Verifier  │
         └──────┬───────┘
                │  HTTPS：challenge / provision
                ▼
 ╔══════════════════════════════════════╗   【Operator 跳板机 · 不可信中继】
 ║  ◆◆◆   C O U R I E R   (CLI)   ◆◆◆    ║   kms_ctl.py —— 在「厂商 Authority」与
 ║                                        ║   「in-VPC key-broker」之间搬运**封装好的
 ║  challenge → init → provision → install║   blob**(sealed root / 签名 AuthBundle /
 ║                                        ║   quote);自己看不到任何明文,KMS 无需公网
 ╚══════════════════╤═════════════════════╝
                │  经 IAP 隧道(KMS 无公网入站)
                ▼
         ┌──────────────┐      【客户 GCP · TDX+vTPM 机密虚机 · 静态内网 IP】
         │   KMS CVM    │      dstack-kms + key-broker:拿到根 → 派生各 app 密钥、租出镜像私钥环
         └──────┬───────┘
                │  mTLS(VPC 内网)
                ▼
         ┌──────────────┐      【客户 GCP · TDX+vTPM 机密虚机】
         │   业务 CVM    │      launcher:取镜像私钥 → JWE 解密 ocicrypt 加密镜像 → 运行业务容器
         └──────────────┘
```

> **Courier(CLI,`kms_ctl.py`)是整套设计的关键、且刻意「不可信」**:它横跨厂商与客户两个信任域做中继,让 KMS **无需任何公网入站**也能完成 provision。它只转发**密码学封装**的数据——根密钥被 HPKE 封到 KMS 的已证明传输公钥、AuthBundle 由厂商 Ed25519 签名、quote 由 verifier 校验——所以即便 courier(或运行它的 operator 机器)被攻陷,也拿不到根密钥明文、伪造不了授权。

**核心原理**：业务镜像被**层加密**（ocicrypt 原生 JWE，非对称 EC P-256——加密只用公钥）。解密所需**私钥**只在通过远程证明后、由 KMS 在 TEE 内租给 launcher。厂商通过 Authority 控制"哪台机器、跑哪个镜像"才拿得到私钥——客户的 GCP 管理员、GCP 本身都拿不到明文镜像和根密钥。镜像私钥是**全局**的（一份加密镜像发所有租户）；各租户的 app/disk 密钥由**各自独立的根**派生，跨租户隔离。

### 两侧职责分工

| | 厂商（Vendor） | Operator |
|---|---|---|
| Authority/Verifier | ✅ 跑在自己主机 | — |
| 镜像密钥环 | ✅ mint（私钥不出 Authority） | — |
| 构建/加密镜像 | ✅ 推到公共 registry | — |
| 同步到 AR | — | ✅ sync-image.sh |
| 授权白名单注册 | ✅（在自己 Authority 上） | — |
| compose 模板"安全 pin" | ✅ 填 pubkey + digest | — |
| 客户值（registry/IP） | — | ✅ user_config |
| 部署 CVM / courier | — | ✅ dstack-cloud |
| 出网硬化 | — | ✅ SWP/防火墙 |

### 部署前双方需商定的共享参数

| 参数 | 谁定 | 厂商怎么用 | operator 怎么用 |
|---|---|---|---|
| **KMS 静态内网 IP**（如 `10.128.15.220`） | 双方约定 | **无需配置**（key-broker 自测 CVM IP 当证书 SAN） | 预留该地址 + 绑 `private_ip` + 设 `kms_urls`/`KMS_HOST` |
| **AR 路径** `${REGION}-docker.pkg.dev/${PROJECT}/${AR_REPO}` | operator | — | sync 目标 + `DSTACK_REGISTRY` |
| **workload app_id**（40 hex） | 厂商 | 注册 + 写进 workload compose | 写进 `app.json` |
| **镜像 digests**（key-broker/dstack-kms/launcher/业务镜像） | 厂商（构建产出） | pin 进 compose / 注册 | — |
| **AUTHORITY_PUBKEY** | 厂商（Authority 产出） | pin 进 KMS compose | — |

> ⚠️ **务必在首次 provision 前就把 KMS 绑定到规划好的静态 IP。** KMS 证书 SAN 由 key-broker 在 install 时**自测 CVM 自身内网 IP** 自动生成,所以只要 CVM 已绑静态 IP,SAN 就自动 == `kms_urls`,双方都无需配 `KMS_DOMAIN`。**部署后再改 KMS IP** 才需要重新 provision——而无 SSH 环境下改不了已装证书,要销毁重建整台 KMS(详见附录)。少数"KMS 前面挂 DNS 名/LB"的场景可用 `kms_ctl.py attest --kms-domain <name>` 覆盖。

---

## 前置条件

### 工具

| 工具 | 厂商 | Operator | 说明 |
|---|---|---|---|
| `docker` + compose | ✅ | ✅ | Authority 栈 / 镜像构建 |
| `skopeo` (≥1.13) | ✅ | ✅ | JWE 加密 / 同步 |
| `dstack-cloud` | — | ✅ | 部署 CVM（**须支持 `private_ip`，见下**） |
| `gcloud` | — | ✅ | GCP 资源 + IAP 隧道 |
| `openssl`/`python3` | ✅ | — | 密钥/JSON |

> ⚠️ **`dstack-cloud` 必须支持 `gcp_config.private_ip` 绑定静态内网 IP。** stock 版的 `GcpConfig` 没有 `private_ip` 字段 → 从 app.json 加载时被丢弃（且 `prepare`/`deploy` 会重写 app.json 抹掉它），建实例也不传 `--private-network-ip` → CVM 拿**临时 IP**，KMS 地址不可预知、证书 SAN 对不上。补丁：①`GcpConfig` 加 `private_ip: str = ""`；②建实例参数 `if config.private_ip:` 追加 `--subnet=default`（若未指定）+ `--private-network-ip={private_ip}`。已上游：**Dstack-TEE/dstack PR #709**。

### GCP 一次性资源（Operator）

```bash
export PROJECT=<your-gcp-project>  REGION=us-central1  ZONE=${REGION}-a
export AR_REPO=dstack-private
export AR=${REGION}-docker.pkg.dev/${PROJECT}/${AR_REPO}
export BUCKET=gs://${PROJECT}-dstack

# 启用 API（compute=TDX 虚机, artifactregistry=私有镜像, networkservices/security=SWP 出网硬化）
gcloud services enable compute.googleapis.com artifactregistry.googleapis.com \
  networksecurity.googleapis.com networkservices.googleapis.com --project=$PROJECT
# 私有镜像仓库（CVM 经 Private Google Access 从这里拉，无公网）
gcloud artifacts repositories create $AR_REPO --repository-format=docker \
  --location=$REGION --project=$PROJECT
# dstack-cloud 部署用的 GCS 桶（放 boot/shared 盘镜像）
gcloud storage buckets create $BUCKET --project=$PROJECT --location=$REGION
```

---

# 第一部分 ▶ 厂商侧（Vendor）

> 厂商在自己有公网的主机上完成 V1–V5，产出交付物（镜像 @ 公共 registry、填好的 compose 模板、AUTHORITY_PUBKEY、已注册的白名单），再交接给 operator。

## V1【厂商】启动 Authority（+ Verifier）

**目的**：起厂商的授权中枢。它持久化**每租户独立的根密钥**、托管**全局镜像密钥环**、签发 Ed25519 的 **AuthBundle**、并用 **dstack-verifier** 校验 KMS 的 TDX+vTPM 证明。

```bash
cd on-prem        # docker-compose.authority.yml 所在目录

# 厂商密钥/配置（勿入库）。注意：**不需要** KMS_DOMAIN——KMS 证书 SAN 由 key-broker 在
# install 时自测 CVM 内网 IP 自动生成（见 O4），vendor 不必知道客户的 KMS 地址。
cat > .env.authority <<EOF
AUTHORITY_SIGNING_KEY=$(openssl rand -hex 32)     # Ed25519 种子，落盘持久化 → 公钥稳定
AUTHORITY_NONCE_SECRET=$(openssl rand -hex 32)    # 无状态 challenge nonce 的 HMAC 密钥
AUTHORITY_ADMIN_TOKEN=$(openssl rand -hex 16)     # 管理接口 Bearer token（多租户必设）
REQUIRE_ATTESTATION=true                          # 生产必须 true：provision 必须带可验证的 quote
ALLOWED_TCB_STATUSES=UpToDate,SWHardeningNeeded
EOF
export ADMIN_TOKEN=$(grep AUTHORITY_ADMIN_TOKEN .env.authority | cut -d= -f2)
export AUTHORITY=http://localhost:8083

# 起 authority + verifier。--env-file 让容器拿到上面的 env（改 env 要 up -d 重建，restart 不重载 env）
docker compose --env-file .env.authority -f docker-compose.authority.yml up -d --build

# 取签名公钥——整个信任链的根，KMS compose 要 pin 它
curl -s $AUTHORITY/api/v1/authority-pubkey      # → {"pubkey":"TCIj…NmU="}
```

- `docker compose … up -d`：拉起 `authority`（FastAPI :8083）和 `verifier`（dcap-qvl）。`authority` 把 `./authority` 源码挂载进容器，改完重启即生效。
- `authority-pubkey`：返回 Ed25519 公钥。**记下它**（下文记作 `$PUBKEY`），V5 要字面写进 KMS compose 的 `AUTHORITY_PUBKEY`。

## V2【厂商】mint 全局镜像密钥（取公钥）

**目的**：生成一把"用一段时间"的全局镜像加密密钥（EC P-256）。私钥进 Authority 的全局 keyring、永不出 API；只返回**公钥**用于加密镜像。

```bash
curl -s -X POST $AUTHORITY/api/v1/admin/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"kid":"vendor-2026h1"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["pub_pem"])' > pub.pem
cat pub.pem      # -----BEGIN PUBLIC KEY-----  这就是 V3 加密用的 jwe:pub.pem
```

- `POST /admin/keys {kid}`：mint 一把密钥进**全局** keyring（vendor-wide，非 per-user）。`kid` 是密钥名（会进镜像 annotation）。返回 `pub_pem`（公钥），私钥不返回。
- 公钥不敏感，可放 CI；**构建机只有公钥，泄露也解不了任何镜像**。
- 轮换：再 mint 新 `kid`（如 `vendor-2026h2`），旧 kid 留在 keyring 直到对应镜像下线；撤销 `DELETE /admin/keys/<kid>`。

## V3【厂商】构建镜像 + JWE 加密业务镜像 + 推公共 registry

**目的**：构建 dstack 组件镜像，并把业务镜像加密成"没私钥跑不起来"，全部推到厂商的**公共 registry**（如 `cr.kvin.wang`）。加密层无明文，可放公共仓库。

```bash
export PUBREG=cr.kvin.wang        # 厂商公共 registry

# 1) 构建组件镜像（构建上下文 = 仓库根）。dstack-kms 可直接用官方 dstacktee/dstack-kms。
docker build -f on-prem/key-broker/Dockerfile -t $PUBREG/key-broker:latest .
docker build -f on-prem/launcher/Dockerfile   -t $PUBREG/launcher:latest   .
docker push $PUBREG/key-broker:latest
docker push $PUBREG/launcher:latest
# dstack-kms：docker pull dstacktee/dstack-kms:latest && docker tag … $PUBREG/dstack-kms:latest && push

# 2) 用全局公钥 JWE 加密业务镜像 → 推公共 registry（每层层密钥用公钥包好）
skopeo copy --encryption-key jwe:pub.pem \
  docker://<your-app:tag> \
  docker://$PUBREG/<your-app>-enc:latest

# 3) 记下各镜像 digest（V5 要字面 pin 进 compose；operator sync 后 AR digest 与此一致）
for img in key-broker launcher dstack-kms <your-app>-enc; do
  echo "$img: $(skopeo inspect docker://$PUBREG/$img:latest --format '{{.Digest}}')"
done
```

- `docker build … key-broker/launcher`：镜像内 `cargo build --release`，产出无外部依赖的运行镜像。
- `skopeo copy --encryption-key jwe:pub.pem`：用公钥把每层加密（ocicrypt 原生 JWE）。**注意 `jwe:` 前缀只用于加密**；解密时 `--decryption-key <priv.pem>` 不带前缀。
- `skopeo inspect --format '{{.Digest}}'`：取 manifest digest。`skopeo copy` 是确定性的，operator 同步到 AR 后 digest **不变**，所以厂商可直接 pin 这组 digest。

## V4【厂商】计算 compose_hash + 注册授权白名单

**目的**：在 Authority 里注册"什么 OS、什么 KMS compose、什么 app + launcher/workload digest"才放行。`compose_hash` 跨客户一致（因客户值都在 `${VAR}`/user_config，不进度量），厂商**预算一次、注册一次**。

先把 V3 的 digest + V1 的 pubkey 填进 compose 模板并算 hash（详见 V5；这里假设已填好 `deploy/kms-prod`、`deploy/launcher-prod`）：

```bash
# compose_hash = sha256(app-compose.json)（权威算法 = dstack-util sha256_file）
dstack-cloud -C deploy/kms-prod      prepare >/dev/null
dstack-cloud -C deploy/launcher-prod prepare >/dev/null
KMS_COMPOSE_HASH=$(sha256sum deploy/kms-prod/shared/app-compose.json      | cut -d' ' -f1)
LN_COMPOSE_HASH=$( sha256sum deploy/launcher-prod/shared/app-compose.json | cut -d' ' -f1)

export USER_ID=acme-prod
export APP_ID=<workload-app-id-40hex>     # 厂商选定的业务 app id
export OS_IMAGE_HASH=<见 O4 measure 取得>  # dstack OS 镜像的 UKI 哈希
export IMAGE_DIGEST=sha256:<V3 业务镜像 digest>

# (a) 建租户（多租户时把返回的 API key 分发给该客户 operator）
curl -s -X POST $AUTHORITY/api/v1/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"user_id\":\"$USER_ID\"}"

# (b) 注册允许的 OS 镜像哈希（bootAuth + 私钥租约都查；空=拒）
curl -s -X POST $AUTHORITY/api/v1/admin/os-images \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"hash\":\"$OS_IMAGE_HASH\"}"

# (c) 注册允许的 KMS compose 哈希（KMS provision 身份白名单的一项）
curl -s -X POST $AUTHORITY/api/v1/admin/kms-compose-hashes \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"hash\":\"$KMS_COMPOSE_HASH\"}"

# (d) 注册业务 app + 双重 digest 闸门 + 当前镜像版本指针
curl -s -X POST $AUTHORITY/api/v1/admin/users/$USER_ID/images \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"app_id\":\"$APP_ID\",
       \"allowed_launcher_digests\":[\"$LN_COMPOSE_HASH\"],
       \"image_digest\":\"$IMAGE_DIGEST\"}"
```

- `prepare` + `sha256sum app-compose.json`：dstack 把 `docker-compose.yaml` 以**字面原文**（含 `${VAR}`）存进 `app-compose.json`，其 sha256 就是 CVM 证书将携带的 `compose_hash`。客户值在 user_config 不进此文件，故 hash 跨客户一致。
- `os-images` / `kms-compose-hashes`：全局策略，KMS provision 时校验 KMS 自身身份（os + key_provider=tpm + compose）。
- `users/$USER_ID/images`：注册业务 app。`allowed_launcher_digests`=允许的 launcher compose 哈希（硬闸门）；`image_digest`→同时设为 `allowed_workload_digests` 和 `current_image_digest`（版本指针，launcher 按它拉镜像）。**解密私钥来自全局 keyring，不在此注册。**

## V5【厂商】填 compose 模板（安全 pin）+ 交付

**目的**：把"安全 pin"（公钥 + 各镜像 digest + app_id + 业务镜像路径名）字面写进 compose 模板。客户相关的 registry/IP 保留为 `${VAR}`，由 operator 的 user_config 在运行期注入。这样模板**度量一致、跨客户复用**。

```bash
# 从 committed 模板拷出，填 pin（也可直接交付填好的模板给 operator）
cp -a deploy-templates/kms      deploy/kms-prod
cp -a deploy-templates/workload deploy/launcher-prod
```

KMS compose（`deploy/kms-prod/docker-compose.yaml`）填：
- `key-broker` 镜像 → `${DSTACK_REGISTRY}/key-broker@sha256:<V3 key-broker digest>`
- `dstack-kms` 镜像 → `${DSTACK_REGISTRY}/dstack-kms@sha256:<V3 dstack-kms digest>`
- `AUTHORITY_PUBKEY=<V1 $PUBKEY 字面量>`（**绝不来自变量**，启用 AuthBundle 验签）
- 保留字面 `${DSTACK_REGISTRY}` / `${SWP_PROXY}`

workload compose（`deploy/launcher-prod/docker-compose.yaml`）填：
- `launcher` 镜像 → `${DSTACK_REGISTRY}/launcher@sha256:<V3 launcher digest>`
- `APP_ID=<$APP_ID 字面量>`、`WORKLOAD_IMAGE=${DSTACK_REGISTRY}/<your-app>-enc`（不含 tag，digest 来自 Authority `current_image_digest`）
- 保留字面 `${KMS_HOST}`（`KMS_URL`/`KEY_BROKER_URL=https://${KMS_HOST}:8000|8002`）

**交付给 operator**：① 公共 registry 里的 4 个镜像；② 填好 pin 的两个 compose 模板（+ prelaunch.sh）；③ `AUTHORITY_PUBKEY`；④ 已在 Authority 注册好白名单。Authority 持续在线（courier 要连）。

---

# 第二部分 ▶ Operator 侧

> Operator 在自己的 GCP 上完成 O1–O7。只填客户值（registry/IP），不碰厂商签名私钥。

## O1【Operator】同步镜像到 AR

**目的**：把厂商公共 registry 的 4 个镜像同步进自己的私有 AR，供无公网 CVM 经 PGA 拉取。

```bash
# scripts/config.env 需含 AR_LOCATION/AR_PROJECT/AR_REPO
for img in dstack-kms key-broker launcher <your-app>-enc; do
  scripts/sync-image.sh "cr.kvin.wang/$img:latest" "$img:latest"
done
```

- `sync-image.sh`：`skopeo copy --all` 按摘要逐层搬运，用 `gcloud auth print-access-token` 作 AR 凭证。加密层原样复制、**digest 与公共 registry 一致**（与厂商 pin 的 digest 相同）。
- 末行打印 `<AR-ref>@<digest>`，可与 V3/V5 的 digest 核对。

## O2【Operator】预留静态 IP + 准备 deploy 目录 + user_config

**目的**：落实商定的 KMS 静态 IP，把厂商交付的模板放进实例目录，填客户值，并让 dstack-cloud 指向我们的 KMS。

```bash
# 预留 KMS / launcher 的静态内网 IP（remove/deploy 后地址不变 → 证书 SAN/kms_urls 才稳定）
gcloud compute addresses create dstack-kms-prod-ip      --region=$REGION \
  --subnet=default --addresses=10.128.15.220 --project=$PROJECT
gcloud compute addresses create dstack-launcher-prod-ip --region=$REGION \
  --subnet=default --addresses=10.128.15.230 --project=$PROJECT

# 放厂商交付的模板（含 pin）；deploy/ 被 gitignore，是 per-customer 状态
cp -a <vendor-delivered>/kms      deploy/kms-prod
cp -a <vendor-delivered>/workload deploy/launcher-prod

# 填 app.json 的 GCP 字段（这些不进 compose_hash）
#   kms-prod:      project/zone/bucket、private_ip=10.128.15.220、key_provider=tpm
#   launcher-prod: 同上、private_ip=10.128.15.230、app_id=<$APP_ID>、key_provider=kms

# 客户值（明文 JSON，经 shared 盘投递为 /dstack/.host-shared/.user-config）
cat > deploy/kms-prod/.user-config <<EOF
{ "DSTACK_REGISTRY": "$AR", "SWP_PROXY": "10.128.0.53:80" }
EOF
cat > deploy/launcher-prod/.user-config <<EOF
{ "DSTACK_REGISTRY": "$AR", "KMS_HOST": "10.128.15.220" }
EOF

# 让 dstack-cloud 全局配置的 kms_urls 指向我们的 KMS（否则默认连公网 kms.tdxlab.dstack.org）
dstack-cloud config-edit      # services.kms_urls = ["https://10.128.15.220:8000"]
```

- 预留地址 = 规划的 KMS 静态 IP（`10.128.15.220`）。dstack-cloud（含 #709 patch）用 app.json 的 `private_ip` 绑定它；key-broker 之后自测到的 CVM IP 就是它 → 证书 SAN 自动匹配。
- `.user-config`：prelaunch 在 CVM 内读它，校验后写 `/dstack/.env` 供 compose 展开 `${VAR}`。**只放路径/IP，不放 digest**（注入防护）。
- `kms_urls`：业务 CVM 的 guest-agent 用它做 GetAppKey（key_provider=kms）。主机名 `10.128.15.220` 必须 == KMS 证书 SAN。

## O3【Operator】部署 KMS CVM

**目的**：在 GCP 建 KMS 的 TDX 机密虚机，绑定静态 IP，从 AR 拉起 key-broker + dstack-kms。

```bash
dstack-cloud -C deploy/kms-prod prepare        # 生成 shared/（app-compose、sys-config、.instance_info）
dstack-cloud -C deploy/kms-prod deploy         # 建 TDX 虚机，绑定 private_ip=10.128.15.220
dstack-cloud -C deploy/kms-prod fw allow 8001 8002   # 放行 IAP → key-broker（courier 8001 / mTLS 8002）
```

- `prepare`：把 compose/prelaunch 归一化成 `app-compose.json`（compose_hash 来源），生成内网 IP/OS 哈希等 sys-config。
- `deploy`：上传 boot/shared 盘镜像、创建实例。**确认输出 `Internal IP: 10.128.15.220`**（绑定成功）。
- `fw allow`：开 IAP 入站到 courier/mTLS 端口（无公网 IP，仅 IAP 可达）。

## O4【Operator】courier provision KMS

**目的**：经 courier（CLI 中继 Authority ↔ in-VPC key-broker）把根密钥安全灌进 KMS。KMS 无公网也能完成。

```bash
# 首次：取 OS 镜像哈希（只读，不释放根），填回厂商的 EXPECTED_OS_IMAGE_HASH / V4 的 os-images，
# 并写 auth_hash.txt 让 CVM 自身也 pin（否则 BootInfo.os_image_hash 为空被 fail-closed 拒）
gcloud compute start-iap-tunnel dstack-kms-prod 8001 --local-host-port=localhost:8001 \
  --project=$PROJECT --zone=$ZONE &
python3 authority/kms_ctl.py measure --user-id $USER_ID \
  --kms-url http://localhost:8001 --authority-url $AUTHORITY   # 打印 os_image_hash 等

# provision（脚本封装了隧道 + 四步 courier）
scripts/provision-kms.sh        # = kms_ctl.py attest
```

四步 courier：① **challenge**（Authority 发 HMAC nonce）→ ② **courier/init**（key-broker 出 TDX+vTPM 证明，`report_data=SHA512(nonce‖transport_pub‖kms_ts)` 绑定本次传输密钥）→ ③ **provision**（Authority 经 verifier 校验 quote + **KMS 身份白名单**后 HPKE 封装根密钥 + 签 AuthBundle）→ ④ **courier/install**（key-broker 验签、HPKE 解封根、落地 keyset）。

> **KMS 身份白名单**（释放根密钥前的三项稳定校验，刻意不用 `mr_aggregated`——GCP PCR0 每实例都变）：①`os_image_hash` ∈ os-images；②`key_provider==tpm`；③`compose_hash` ∈ `allowed_kms_compose_hashes`。这三项跨重部署稳定。
>
> **install 时 key-broker 自测 KMS rpc 证书 SAN**：取 CVM 自身内网 IP（连 `169.254.169.254` 的 UDP socket 的 `local_addr`）当 SAN → 自动 == operator 的 `kms_urls`。authority **不需要**知道这个 IP。前面挂 DNS/LB 的少数场景：`kms_ctl.py attest --kms-domain <name>` 覆盖。
>
> install 后 key-broker 写 `/kms/_ready`，KMS 容器的等待循环自动 `exec dstack-kms`——**无需 SSH 重启**。

## O5【Operator】验证 KMS serving

**目的**：确认 KMS 已从下发的根启动、对外 TLS、且证书 SAN = 静态 IP（否则业务 CVM 连不上）。

```bash
gcloud compute start-iap-tunnel dstack-kms-prod 8000 --local-host-port=localhost:18000 \
  --project=$PROJECT --zone=$ZONE &
curl -sk https://localhost:18000/prpc/KMS.GetMeta | head -c 80   # → {"ca_cert":"-----BEGIN CERT…
echo | openssl s_client -connect localhost:18000 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName                     # → IP Address:10.128.15.220
```

- `GetMeta` 返回 `ca_cert`/`k256_pubkey` 即 KMS 已 serving。
- 证书 SAN **必须是 `IP Address:10.128.15.220`**（= key-broker install 时自测到的 CVM IP，ra_tls 自动出 IP SAN）。若是 `DnsName:kms.local`，说明自测失败回落到了 fallback——检查 CVM 是否真的绑了静态 IP（见附录）。

## O6【Operator】部署业务 CVM

**目的**：起 launcher，在 TEE 内取镜像私钥、JWE 解密、运行业务容器，全程无公网。

```bash
dstack-cloud -C deploy/launcher-prod prepare
dstack-cloud -C deploy/launcher-prod deploy    # 确认 Internal IP: 10.128.15.230
```

启动链路（自动）：guest-agent `key_provider=kms` → 向 KMS（`10.128.15.220:8000`，证书 SAN 匹配）GetAppKey 拿 app 密钥 + KMS 派生 CA → launcher 调 guest-agent `get_tls_key` 拿 **KMS 签发、带 app_info 扩展的 RA-TLS 客户端证书** → 连 key-broker（`10.128.15.220:8002` mTLS）申请**密钥租约**（key-broker 验链 + 从扩展取 app_id/compose_hash/os_image 校验白名单后返回**全局镜像私钥环**）→ launcher 把私钥写 tmpfs、喂 `skopeo --decryption-key` 按摘要解密 → `docker load` → compose 起容器。租约有 TTL，断租超宽限期停业务容器。

## O7【Operator】验证 E2E

```bash
gcloud compute start-iap-tunnel dstack-launcher-prod 9100 --local-host-port=localhost:19100 \
  --project=$PROJECT --zone=$ZONE &
curl -s http://localhost:19100/status | python3 -m json.tool
```

期望：
```json
{ "app_id": "<$APP_ID>", "workload_image": "…/<your-app>-enc",
  "running_digest": "sha256:<业务镜像 digest>",  ← JWE 解密后跑的就是注册的镜像
  "lease_active": true, "workload_running": true, "bundle_seq": <N>, "last_error": null }
```

`lease_active` + `workload_running` = true 即全链路通。无 SSH 时也可经 guest-agent `:8090` 拉容器日志（`public_logs:true`）。

---

# 第三部分 ▶ 出网域名白名单硬化（Operator，推荐）

**目的**：让两台 CVM 只能访问被批准的目的地——业务 CVM 彻底无公网，KMS 仅能到 Intel PCS。用网络标签 `dstack-cvm` 只作用于这两台。

- **① Private Google Access**：子网开 PGA；CVM 用 `/etc/hosts` 把 `*.googleapis.com`/`*.pkg.dev` 钉到私有 VIP `199.36.153.10`。AR/GCS 走 Google 私网。
- **② 业务 CVM 全锁**：`dstack-cvm` 标签 + 摘外网 IP + egress-deny（只放行内网/PGA VIP:443/SWP/metadata）。AR 经 PGA、KMS 经内网。
- **③ KMS 经明文 SWP 出 Intel PCS**：dcap-qvl 的 rustls **不信任**自签代理证书且无处加 CA，故把 GCP **Secure Web Proxy 建成明文端点**（`ports:[80]`，不配证书），rustls 用明文 `CONNECT` 对 Intel 端到端 TLS，SWP 按 SNI 做白名单。白名单必须含**两个** Intel 域名：`api.trustedservices.intel.com` **和** `certificates.trustedservices.intel.com`（少一个 KMS 验业务 CVM 的 quote 时 `tunnel error`）。KMS compose 设 `HTTP_PROXY=http://${SWP_PROXY}`。

> 一键脚本 `scripts/setup-swp.sh`（pga/gateway/hosts/lockdown/verify 各阶段）。验证：CVM 内 `curl -x http://<SWP_IP>:80 https://api.trustedservices.intel.com/...`=200，直连 `https://www.google.com` 超时。

---

# 第四部分 ▶ 接口与安全模型（生产无 SSH / fail-closed）

生产**不装 sshd**；一切交互走专门设计的 HTTP API。

| 端点 | 端口/传输 | 用途 |
|------|-----------|------|
| `/courier/init`、`/courier/install` | 8001,IAP | provision（出证明、装 HPKE 封装的根 + 验签 AuthBundle） |
| `/bootAuth/kms`、`/bootAuth/app` | 8001,本地 | KMS 授权 webhook：校验自身/各 app 的 app_id/compose_hash 是否在白名单 |
| `/healthz`、`/version`、`/usage-receipt` | 8001 | 就绪、当前镜像摘要+bundle_seq、签名用量回执 |
| `/lease/acquire`、`/lease/renew` | 8002,**mTLS** | 给业务 CVM 下发镜像私钥环 + 租约 |
| launcher `/status`、`/healthz` | 9100 | 只读运行状态（摘要/租约/seq/是否运行/错误类别） |

**API 防泄漏**：管理端点只回 HPKE 封装/加密 blob、签名/公钥、布尔+非敏感元数据（mint 只回公钥，根密钥/私钥环**任何明文端点都不返回**）。**唯一私钥出口 = mTLS `/lease/acquire`**，且绑定已远证 + 已授权的 launcher。无内省/调试/文件/exec 端点。错误响应可含文件路径但**不含密钥内容**。

**Fail-closed 原则**：所有授权/校验**默认拒绝**——空白名单/缺配置/缺证明一律拒，无任何"关安全检查"的旁路开关。强制门：os-images 白名单（bootAuth + 租约都查，空=拒）、`key_provider==tpm` + `compose_hash` ∈ 白名单（KMS provision）、租约要求 launcher 出**已远证的 RA-TLS 证书**（无证则拒，空 keyring 也拒）、TCB ∈ `allowed_tcb_statuses`。

---

# 附录 ▶ 常见问题（实测踩坑）

- **`deploy` 后 Internal IP 不是预留的静态地址** → `dstack-cloud` 没有 `private_ip` patch（见前置条件，Dstack-TEE/dstack #709）。stock 版会丢弃 `private_ip` 并重写 app.json 抹掉它，需打 patch 并重新写回 `app.json` 的 `private_ip`。

- **`certificate not valid for name "<IP>"; only valid for DnsName("kms.local")`**（业务 CVM boot loop / guest-agent GetAppKey 失败）→ KMS 证书 SAN 不是 CVM IP。SAN 由 key-broker 在 install 时**自测 CVM 内网 IP** 生成,正常情况自动 == `kms_urls`;见到 `kms.local`(fallback)说明:① CVM **没绑静态 IP**(检查 dstack-cloud `private_ip` patch + `deploy` 输出的 Internal IP);或 ② 自测被环境阻断。要点:`kms_urls`/`KMS_HOST` 用 CVM 的实际内网 IP;dstack-kms 的 ra-tls 要支持 IP SAN(mainline / 官方 `dstacktee/dstack-kms` 已支持)。**改 KMS IP 后须重新 provision;无 SSH 时不能就地改证书,要销毁重建整台 KMS CVM(含 data disk)**——`provision --reset` 靠 SSH 擦 `/kms` 会失败、跑着的 dstack-kms 无法在线重启。重建:`remove` → 重新预留/绑定静态 IP + 改 `kms_urls`/`KMS_HOST` → `deploy` → `provision`(SAN 自动跟到新 IP)。

- **provision 403 `not in whitelist`** → 旧 `mr_aggregated` 机制（GCP PCR0 每实例变）；现机制 key 在 `os_image_hash+key_provider=tpm+compose_hash`。**故意改 KMS compose** 会合法 403，需把新 `compose_hash` 加进 `allowed_kms_compose_hashes`。

- **`invalid quote: Failed to get collateral: …certificates.trustedservices.intel.com…: tunnel error`** → SWP 白名单漏了 `certificates.trustedservices.intel.com`（两个 Intel 域名都要放）。

- **`Boot denied: OS image is not allowed`** → 业务 CVM 的 `os_image_hash` 为空。建 `~/.dstack/images/<os_image>/auth_hash.txt`=OS 哈希，prepare 会写进 vm_config。

- **AR 拉取 `Unauthenticated`** → CVM 的 prelaunch 要用实例 SA 的 metadata token `docker login` 到 AR（dstack OS 的 python 无 `json`，用 `sed` 解析 token）。

- **skopeo JWE 解密 `missing private key`** → 私钥须是 **PKCS#8**（`-----BEGIN PRIVATE KEY-----`；SEC1 的 `EC PRIVATE KEY` ocicrypt 不收，Authority mint 已用 PKCS#8）。解密 `--decryption-key <priv.pem>` **不带** `jwe:` 前缀。

- **launcher `GetTlsKey returned 404`** → guest-agent prpc 路径应是裸方法名 **`/GetTlsKey`**（不是 `/prpc/…` 也不是 `/DstackGuest.GetTlsKey`）。

> 完整实测链路：KMS（fail-closed + IP SAN cert + 经明文 SWP 出 Intel）→ 业务 CVM `key_provider=kms` 启动取钥解盘 → launcher `get_tls_key` 拿 KMS 签发 RA-TLS 证书 → key-broker 双向 mTLS → 租约 + **全局镜像私钥环** → skopeo `--decryption-key` JWE 解密 → 业务容器运行。零 insecure 开关，全程无 SSH。

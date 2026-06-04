<!-- SPDX-License-Identifier: Apache-2.0 -->
# 快速设置（GCP 私有化部署）

用编排脚本把部署压到**个位数命令**。原理/每步细节见
[`DEPLOYMENT_GUIDE_CN.md`](DEPLOYMENT_GUIDE_CN.md)。

> English: [`QUICKSTART.md`](QUICKSTART.md)。

## 关键:大多数命令不是"每次部署"都跑

| 频率 | 谁 | 命令 |
|---|---|---|
| **一次性** | 厂商 | `./deploy-authority.sh`（起 Authority+Verifier） |
| **每发布版一次** | 厂商 | `./vendor-release.sh`（build/加密/推镜像 + 算 hash + 注册全局策略 + 填模板） |
| **每新增客户一次** | 厂商 | `./vendor-add-tenant.sh <user_id>`（建租户 + 注册 app，复用全局 hash） |
| **每个环境一次** | operator | `./setup-swp.sh`（可选,出网硬化）、预留 IP（脚本内自动） |
| **每次部署** | operator | `./operator-deploy.sh all` |

参数化 compose 让 os/compose/app 哈希**跨客户一致**,所以新客户对厂商只是 1 条 `vendor-add-tenant.sh`。

## 前置安装（每台机器一次）

干净机器从零装（Debian/Ubuntu；其它发行版换包管理器）：

```bash
# 1) 系统工具
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl python3 python3-pip \
    skopeo docker.io docker-compose-v2

# 2) python 依赖（kms_ctl.py 用 requests;dstack-cloud 的 env 加密用 cryptography）
pip3 install --break-system-packages requests cryptography

# 3) gcloud:装 SDK(https://cloud.google.com/sdk/docs/install)后登录 + 设项目
gcloud auth login                      # 或 gcloud auth activate-service-account --key-file=…
gcloud config set project <PROJECT>

# 4) dstack-cloud —— 单文件 Python CLI,放进 PATH(如 /usr/local/bin),并 chmod +x。
#    必须带 private_ip 绑定补丁(Dstack-TEE/dstack #709):合入后取自 dstack 仓库
#    scripts/bin/dstack-cloud,否则按 #709 自行打补丁。它依赖上面 pip 装的 cryptography。

# 5) 取仓库 + 填配置
git clone <dstack-repo> && cd dstack/on-prem/gcp/scripts
cp config.env.example config.env && "$EDITOR" config.env
```

**config.env 各侧必填**：
- **厂商**（vendor-release / add-tenant）:`AUTHORITY_URL`、`AUTHORITY_ADMIN_TOKEN`、`PUBREG`、`IMAGE_KID`、`APP_ID`、`WORKLOAD_SRC`、`WORKLOAD_NAME`、`OS_VERSION`、`DSTACK_KMS_SRC`。运行前先 `docker login "$PUBREG"`(推镜像要认证)。
- **operator**（operator-deploy）:`GCP_PROJECT`、`GCP_ZONE`、`AR_LOCATION/AR_PROJECT/AR_REPO`、`PUBREG`、`WORKLOAD_NAME`、`OS_VERSION`、`KMS_IP`、`LAUNCHER_IP`、`USER_ID`、`AUTHORITY_URL`、`SWP_PROXY`(KMS compose 必需)。`OS_VERSION` 用**带点**的发布名(如 `dstack-cloud-nvidia-0.6.1`),脚本自动推导 app.json/目录用的横线名。

> 一次性 GCP 资源（AR 仓库 + GCS 桶 + 启用 API）见
> [`DEPLOYMENT_GUIDE_CN.md`](DEPLOYMENT_GUIDE_CN.md) 的"前置条件"。`operator-deploy.sh`
> 会自动初始化 dstack-cloud 的全局配置(`~/.config/dstack-cloud/config.json`:
> `image_search_paths` / `gcp` / `kms_urls`)。镜像同步(`sync`)只需 gcloud 认证。

## 厂商侧（在自己有公网的主机）

```bash
cd on-prem/gcp/scripts
./deploy-authority.sh                 # 一次性:起 Authority+Verifier,打印 AUTHORITY_PUBKEY
./vendor-release.sh                   # 每发布版:产出镜像 @ PUBREG + 填好 pin 的 deploy/ 模板 + 注册全局策略
./vendor-add-tenant.sh acme           # 每客户:建租户 acme + 注册 app(打印其 API key)
```

**交付给该 operator**:① `$PUBREG` 里的 4 个镜像;② 填好 pin 的 `deploy/kms/`、`deploy/launcher/`;③ `AUTHORITY_PUBKEY`;④ 租户 API key。Authority 保持在线（courier 要连）。

## operator 侧（在自己的 GCP）

把厂商交付的 `deploy/kms`、`deploy/launcher` 放好,填 `config.env`（`KMS_IP`/`LAUNCHER_IP`/`OS_VERSION`/`PUBREG`/`AR_*`/`USER_ID`/`AUTHORITY_URL`/`SWP_PROXY`），然后:

```bash
cd on-prem/gcp/scripts
./operator-deploy.sh all              # sync 镜像→AR + pull OS + 部署 KMS(+provision+验证) + 部署 launcher(+验证)
# 或分步:
#   ./operator-deploy.sh sync         # 同步镜像 + 拉 OS 版本
#   ./operator-deploy.sh kms          # 部署 KMS CVM + courier provision + 验 serving/SAN
#   ./operator-deploy.sh launcher     # 部署业务 CVM + 验 E2E /status
./setup-swp.sh                        # 可选:出网域名白名单硬化
```

`operator-deploy.sh` 自动做:预留静态 IP、填 app.json 的 GCP 字段、写 `.user-config`、配 `kms_urls`、`prepare`/`deploy`/`fw`/`provision`、并跑验证（KMS GetMeta+证书 SAN、launcher `/status`）。

## day-2

- **业务版本更新 / 密钥轮换**（厂商）:改好后重跑 `./vendor-release.sh`,再对每个在线租户 `./vendor-add-tenant.sh <user_id>` 更新 + `kms_ctl.py sync-auth` 推新 bundle;operator `./operator-deploy.sh sync` 同步新镜像。
- **重部署 / 改 IP / 换 OS**（operator）:改 `config.env` 后重跑 `./operator-deploy.sh kms|launcher`。
- **监控**:launcher `/status`、Authority `usage-receipt`。

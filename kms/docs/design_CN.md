# Dstack - KMS protocol

## CVM 启动模式

宿主机部署https://github.com/MoeMahhouk/gramine-sealing-key-provider

teepod内包装成vsock服务提供给cvm调用： `CVM —> teepod —> gramine-key-provider`

### 一次性模式

KMS❌，tproxy❌，local-key-provider❌

app-id == compose-hash, 不相等拒绝启动

无key provider

启动中生成临时app key

RTMR里添加key-provider-info: none

关机后磁盘状态丢失

不支持app升级

### 独立模式

KMS❌，tproxy❌，local-key-provider✅

app-id == compose-hash, 不相等拒绝启动

通过本机gramine-sealing-key-provider获取app key

RTMR里添加 key-provider-info: {”type”: “sgx-local”, “mr”: “<sgx mr>”}

重启vm磁盘状态保留

不支持app升级

### 常规模式

KMS✅，tproxy✅，local-key-provider❌

允许app-id ≠ compose-hash, 由kms决定是否允许启动（GetAppKey时决定是否下发key）

app compose需包含控制合约字段

通过kms获取app key

RTMR里添加 key-provider-info: {”type”: “kms”, “id”: “<kms-id>”}

重启vm磁盘状态保留

支持app升级

## KMS App

部署在**独立模式**CVM中

通过host端口映射暴露rpc

启动参数：

控制合约

chain id

address

链RPC配置若干（或light client配置）

组件（containers）

dstack-kms

提供rpc GetAppKey来申请app key

RPC中verify app的quote

提取检查如下BootInfo

```rust
BootInfo {
	mrtd（代表vBIOS固件)
	rtmr[4]
	image_hash // = hash_of(kernel_hash, kernel_args_hash, initrd_hash, rootfs_hash)
	// App 
	app-id
	compose-hash
	instance-id
	device-id
}
```

调用external rpc检查上述环境信息是否许可启动？

dstack-kms-backend-eth

提供rpc查询启动许可，对接链

1. 先向kms控制合约查询启动许可
2. 若1通过，向app控制合约查询启动许可

Andrew’s replicator

用来同步kms root key

chain light client（optional）

compose文件中定义多少个实例（连接哪些链）

第一个实例启动后生成kms root key。人工将appid，pubkey，tdx quote登记到kms控制合约中。

后续实例通过replicator从已有实例获取root key。

链上合约的作用

控制kms版本升级

控制replicator交接密钥

## 常规App部署

compose中需填写控制合约用于控制其允许升级的compose-hash, 以及tcb

当不填写时，kms将其指向一个DAO控制的默认合约? 或不允许升级？或必填？

## 合约接口

KMS控制合约

```rust
// 用于登记首次KMS产生的key信息：app-id, pubkey，tdx quote
tx bootstrap(FirstKmsInfo)
// 注册许可的TCB环境
tx allowBios(mrtd)
tx allowImage(image_hash)
tx banBios(mrtd)
tx banImage(image_hash)
// 用于决定是否允许kms密钥交接
query isKmsAllowed(BootInfo) -> bool
// 用于初筛app TCB info
query isAppAllowed(BootInfo) -> bool
```

App控制合约

```rust
// 细筛 TCB info and app info
query isAppAllowed(BootInfo) -> bool
```

## TODO list

teepod实现VSOCK server代理key-provider请求到gramine-sealing-key-provider

reproduciable gramine-sealing-key-provider

guest实现三种启动模式

KMS

启动信息提取，external RPC查询启动许可

dstack-kms-backend-eth（提供RPC，对接链）

集成andrew的replicatoor（或实现在kms内部）

Docker image

Solidity contract

guest实现编译时输出image hash（需要模拟ccel log生产过程）
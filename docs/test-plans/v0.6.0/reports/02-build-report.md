# 构建与镜像产物报告

## Release 资料

11 个 Rust release 目标、VMM UI、KMS auth 依赖和合约测试资料均已构建。`prek run --all-files` 通过。

## Yocto production image

冻结点原样 clean build 的最终结果：**FAIL（发布阻断）**。

Rootfs 组装时 DNF 无法找到 `kernel-module-fuse`：

```text
No match for argument: kernel-module-fuse
kernel-module-fuse is neither a recipe nor a generated package.
```

最终 kernel `.config` 是 `CONFIG_FUSE_FS=y`，即 FUSE 编入内核而不是 module，因此不会生成 `kernel-module-fuse` RPM；但 `dstack-rootfs-base.inc` 仍强制安装该包。这是冻结提交可重复触发的产品 packaging 错误，不是网络问题。

为继续后续测试，仅在隔离 worktree 删除这一个不可能存在的 package dependency。使用该**测试补丁**后 production image 构建成功。它不能作为“冻结提交原样构建 PASS”。

构建过程中还发生一次 `proxy.golang.org` wget exit 4；保留下载缓存重试后成功，判定为暂态网络故障。首次使用默认 64×64 并发造成主机 swap thrash；中止后清理全部 active recipes，并以 `BB_NUMBER_THREADS=12`、`PARALLEL_MAKE=-j12` 恢复。强制中止遗留的 partial outputs 已显式 `do_clean` 后重建。

## 测试补丁产物

| 产物 | SHA-256 | 大小 |
|---|---|---:|
| `dstack-0.6.0.tar.gz` | `f1582390165f5057fe87a7ce43145acc678d5aab76d9cad1eaf6c96da9fb5ec9` | 582 MiB |
| `dstack-0.6.0-uki.tar.gz` | `10eb3591cf70800a79fccbc3cded24abc0c78654891270caf7ff5631f8155395` | 581 MiB |

Bare tar 解包后，`sha256sum -c sha256sum.txt` 对 OVMF、kernel、initramfs、metadata 和四种 measurement CBOR 全部通过。Rootfs verity image、`ovmf-sev.fd` 和 `digest.txt` 均存在。Metadata 核对结果：

- version `0.6.0`；
- git revision `dc3b95117f518a752c0726ecd44ba7888a25cc49`；
- production (`is_dev=false`)；
- unified TDX/SEV firmware metadata；
- OS digest `91bc72e3ca6f283cc0549d761ee436d381d1e8c4ddc4c23354e05c9bbccfdec1`。

## Warnings

成功的测试补丁构建报告 59 个 warning。除 OVMF 三处 assignment whitespace 外，kernel configcheck 包含大量 requested/not-found symbol；详见 `08-findings-and-risks.md`。必须以最终 `.config`/运行态而不是 warning 文本本身判断安全影响。

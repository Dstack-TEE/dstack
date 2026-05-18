# Guest Image Command-Line Tool Inventory

This section documents the command-line tools available inside production dstack guest OS images. The guest image is a minimal Yocto-based Linux environment, not a full general-purpose Linux distribution.

Use this inventory when writing `init_script`, `pre_launch_script`, operational scripts, or troubleshooting instructions that run inside a CVM.

## Version Pages

- [v0.5.4](./guest-image-tools/v0.5.4.md)
- [v0.5.4.1](./guest-image-tools/v0.5.4.1.md)
- [v0.5.5](./guest-image-tools/v0.5.5.md)
- [v0.5.6](./guest-image-tools/v0.5.6.md)
- [v0.5.6.1](./guest-image-tools/v0.5.6.1.md)
- [v0.5.7](./guest-image-tools/v0.5.7.md)
- [v0.5.8](./guest-image-tools/v0.5.8.md)
- [v0.5.9](./guest-image-tools/v0.5.9.md)
- [v0.5.10](./guest-image-tools/v0.5.10.md)

## Compatibility Overview

| Version | Major tool additions / notes |
|---|---|
| v0.5.4 / v0.5.4.1 | Baseline: Bash, BusyBox, curl, jq, systemd tools, Docker, WireGuard, legacy iptables. |
| v0.5.5 | Adds ext4/XFS tools such as `resize2fs`, `mkfs.ext4`, `mkfs.xfs`, `xfs_growfs`. |
| v0.5.6 | Adds GPT tools such as `sgdisk`, `gdisk`, `fixparts`. |
| v0.5.6.1 | Adds `rsync`, FUSE helpers, and Sysbox commands. |
| v0.5.7 | Adds `parted` and `partprobe`. |
| v0.5.8 | No major userspace command additions; nftables kernel support exists, but no `nft` command. |
| v0.5.9 | No major userspace command additions; ipset kernel support exists, but no `ipset` command. |
| v0.5.10 | Adds `nft` and `python3`; `iptables` remains legacy backend. |

## Stable Baseline for v0.5.4+ Scripts

For scripts that need to work across v0.5.4 and later, the safest baseline is:

```text
bash + BusyBox userland + curl + jq + systemd tools + docker + WireGuard + legacy iptables
```

Recommended guard pattern:

```bash
need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing command: $1" >&2
        exit 1
    }
}

need curl
need jq
need docker
need iptables
```

Do not assume GNU extensions for BusyBox-provided commands, and do not assume optional tools such as `nft`, `parted`, `rsync`, `ipset`, `conntrack`, `ss`, `tc`, or `ethtool` unless the target version page lists them.

## Development Images

Development images (`dstack-dev-*`) include additional debugging tools such as `ssh`, `sshd`, `strace`, `tcpdump`, `gdb`, `gdbserver`, and `vim`. These tools are not part of the production image inventory unless listed on a version page.

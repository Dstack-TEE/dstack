# Guest Image Command-Line Tool Inventory

This section documents the command-line tools available inside production dstack guest OS images. The guest image is a minimal Yocto-based Linux environment, not a full general-purpose Linux distribution.

Use this inventory when writing `init_script`, `pre_launch_script`, operational scripts, or troubleshooting instructions that run inside a CVM.

## Version Pages

- [v0.5.1](./guest-image-tools/v0.5.1.md)
- [v0.5.3](./guest-image-tools/v0.5.3.md)
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
| v0.5.1 | Same core tool set as the v0.5.4 baseline, minus `fusermount3`/`mount.fuse3` and `pigz`; includes `qemu-ga` (removed in later versions). |
| v0.5.3 | Adds FUSE helpers (`fusermount3`, `mount.fuse3`); drops `qemu-ga`. Still no `pigz`. |
| v0.5.4 / v0.5.4.1 | Baseline: Bash, BusyBox, curl, jq, systemd tools, Docker, WireGuard, legacy iptables. Adds `pigz` (takes over the `gzip`/`gunzip`/`zcat` names). |
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

## BusyBox Option Caveats

Every 0.5.x image builds BusyBox 1.36.1 from the same pinned poky (kirkstone) defconfig, so applet behavior is identical across versions. A command being listed does NOT mean all of its common options exist — the defconfig disables several sub-features:

| Applet | Missing | Cause | Workaround |
|---|---|---|---|
| `head` | `-c` (byte count) | `CONFIG_FEATURE_FANCY_HEAD` off | `dd bs=1 count=N` |
| `dd` | `ibs=`, `obs=`, `conv=` | `CONFIG_FEATURE_DD_IBS_OBS` off | `bs=`, `count=`, `if=`, `of=`, `skip=`, `seek=` all work |
| `passwd` | `--stdin` | BusyBox applet has no such option | see Password and Account Management below |
| — | `chpasswd`, `cryptpw`, `mkpasswd` | `CONFIG_CHPASSWD` / `CONFIG_CRYPTPW` / `CONFIG_MKPASSWD` off | `openssl passwd -6` |

`head -c` under `set -e` is a boot killer: the pipeline fails, the script dies, and the CVM never reaches `running`. This exact failure shipped in Phala Cloud pre-launch script v0.0.17 (see Phala-Network/phala-cloud-monorepo#1936 follow-up).

## Password and Account Management

The images carry only the BusyBox `passwd` applet plus the `su`/`login` binaries from shadow — no `chpasswd`, `usermod`, `chage`, `cryptpw`, or `mkpasswd` in any version. The only reliable non-interactive way to set a password is to write the crypt hash into `/etc/shadow` directly; `openssl` is present in every image (pulled in via ca-certificates):

```bash
HASH=$(openssl passwd -6 "$PASSWORD")
sed -i "s|^root:[^:]*:|root:${HASH}:|" /etc/shadow
```

**Never lock accounts you still need to reach over SSH.** The dev-image sshd is OpenSSH built without PAM (`DISTRO_FEATURES` has no `pam`), and PAM-less OpenSSH treats a locked account (`!` prefix in the `/etc/shadow` password field, what `passwd -l` writes) as *deny all authentication* — public-key login is rejected too, unlike on PAM-enabled distros where locking only disables password auth. This locked users out of their dev CVMs in pre-launch v0.0.17 (Phala-Network/phala-cloud-monorepo#1936).

## Development Images

Development images (`dstack-dev-*`) include additional debugging tools such as `ssh`, `sshd`, `strace`, `tcpdump`, `gdb`, `gdbserver`, and `vim`. These tools are not part of the production image inventory unless listed on a version page.

Two dev-image traits matter for scripts:

- `sshd` is OpenSSH built without PAM — see the locked-account warning in Password and Account Management.
- The images are built with `debug-tweaks`, so root's `/etc/shadow` password field starts out empty; scripts that key off "is a root password set" will take their empty-password branch on every fresh dev CVM.

## Build Tree Note

Pages up to v0.5.10 reference revisions of the standalone `meta-dstack` repository. From v0.5.11 the Yocto build tree lives inside the dstack repository under `os/yocto/`, so later version pages will reference dstack repository revisions instead.

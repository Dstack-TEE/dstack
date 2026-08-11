# Guest netfilter capabilities

Which packet-filtering capabilities a dstack guest image provides, and which
firewall path an application running nested container managers (Incus, LXD,
libvirt, a nested Docker) should expect to work.

Applications that only publish ports through docker-compose do not need this
page: dstack's own networking and Docker's published ports work on every image.
It matters when something inside the CVM programs its own bridges and firewall
rules.

## One dataplane: nftables

Every netfilter frontend in the image writes to nftables. `iptables`,
`ip6tables` and `ebtables` are the nft-backed frontends, so Docker's rules,
dstack's own `DSTACK_WG` chain and anything a tenant workload writes all land
in one ruleset that a single `nft list ruleset` can show.

This matters more than tidiness. The legacy and nf_tables rulesets register at
the same netfilter hooks but cannot see each other, so on a mixed image the
effective ruleset is only knowable by querying both. A container manager that
selects a firewall driver by probing which ruleset is already in use gets
steered by whatever Docker happened to do — which is what made Incus managed
bridges fail on 0.5.x, where the frontends were legacy.

Both backends reach this the same way, but from different directions:

| | `os/yocto` | `os/mkosi` |
| --- | --- | --- |
| Frontend | `xtables-nft-multi`, linked in `iptables_%.bbappend` | Debian's nft frontend |
| How it is guaranteed | built explicitly by the recipe | asserted in `parity.json` |
| `NETFILTER_XTABLES_LEGACY` in kernel | `y` (from `netfilter.scc`) | not set |
| Legacy frontends still present | yes, as `*-legacy` | binaries exist, no kernel tables |

Neither image *removes* the legacy binaries, so `iptables-legacy` remains
callable. On Yocto it still works, because that kernel keeps the legacy tables;
on mkosi it has no tables behind it. Use the unsuffixed commands.

## Capability matrix

Everything listed is a loadable module (`=m`) unless stated. Values were read
from a built `kernel-config` artifact for Yocto, and from the `.config` that
`x86_64_defconfig` plus `os/mkosi/components/kernel/kernel.config` produces for
mkosi.

| Capability | Kconfig symbol | Yocto | mkosi | Since |
| --- | --- | --- | --- | --- |
| nftables core | `NF_TABLES` | yes | yes | 0.5.x |
| xtables-over-nftables | `NFT_COMPAT` | yes | yes | 0.5.x |
| nftables bridge family | `NF_TABLES_BRIDGE` | yes | yes | 0.6.1 (mkosi) |
| bridge meta / reject | `NFT_BRIDGE_META`, `NFT_BRIDGE_REJECT` | yes | yes | 0.6.1 |
| ebtables framework | `BRIDGE_NF_EBTABLES` | yes | yes | 0.5.x |
| ebtables matches | `BRIDGE_EBT_ARP`, `_IP`, `_IP6`, `_AMONG`, `_LIMIT`, `_VLAN` | yes | yes | 0.6.1 |
| ebtables legacy tables | `BRIDGE_NF_EBTABLES_LEGACY`, `BRIDGE_EBT_T_*` | **no** | **no** | — |
| CHECKSUM target | `NETFILTER_XT_TARGET_CHECKSUM` | yes | yes | 0.6.1 (mkosi) |
| IPv4 tables | `IP_NF_IPTABLES` | yes | built in | 0.5.x |
| IPv4 legacy tables | `IP_NF_IPTABLES_LEGACY` | yes | **no** | — |
| IPv6 tables | `IP6_NF_IPTABLES` | yes | built in | 0.6.1 (Yocto) |
| IPv6 NAT / filter / mangle | `IP6_NF_NAT`, `IP6_NF_FILTER`, `IP6_NF_MANGLE` | yes | n/a | 0.6.1 (Yocto) |
| ipset | `IP_SET` and the hash/bitmap set types | yes | yes | 0.5.x |

Userspace: both images ship `iptables` and `nftables`. `ebtables` is the
nft-backed frontend from the same multi-call binary, not the standalone legacy
package.

Three entries deserve a note.

**The legacy ebtables tables are deliberately absent.**
`BRIDGE_NF_EBTABLES` builds only the matches, targets and watchers; since the
6.15 legacy-tables split the tables and `ebtables.ko` itself hang off
`BRIDGE_NF_EBTABLES_LEGACY`, which defaults to `n`. Nothing on an nft frontend
uses them — `ebtables-nft` emits nft bridge rules and reaches the `ebt_*`
match modules through `nft_compat`.

**The IPv6 legacy tables on Yocto are for completeness, not for the default
path.** The nft frontend synthesises whatever table it is asked for, so
`ip6tables` needs no `ip6table_nat` module. They are enabled because that
kernel keeps `NETFILTER_XTABLES_LEGACY` on and has the full IPv4 legacy set, so
IPv6 being the one missing family meant `ip6tables-legacy` could not even list
a table.

**`CHECKSUM` is still required.** The DHCP path of a managed bridge appends
`-j CHECKSUM --checksum-fill` so dnsmasq's replies reach guests with
checksum-offloading virtio NICs. On an nft frontend that is programmed through
`nft_compat`, which still needs the `xt_CHECKSUM` module.

## Running a nested bridge manager alongside Docker

Having the capabilities is not the whole story. Docker sets the `FORWARD` chain
policy to `drop`, and `br_netfilter` is loaded with
`net.bridge.bridge-nf-call-iptables = 1`, so frames bridged between two
containers on someone else's bridge still traverse that chain. nftables base
chains in different tables are evaluated independently at the same hook, so a
manager that installs its own `accept` rules in its own table — Incus creates
`table inet incus` with `policy accept` and per-bridge accept rules — does not
override Docker's `drop`. The bridge comes up, DHCP works, containers get
addresses, and then nothing can talk to anything.

This is the long-standing interaction between Docker's forward policy and
libvirt/LXD/Incus-style bridge managers, and it is what every distribution that
defaults to the nftables frontend already behaves like.

It is, however, a behaviour change for the Yocto image, which programmed the
legacy tables before dstack 0.6.1. On that path Incus selected its xtables
driver and installed its accept rules with
`iptables -I filter FORWARD -i <bridge> -j ACCEPT` — into Docker's *own* chain,
ahead of the policy — so forwarding worked without any extra rule. Under the
nftables driver the accept lands in a separate table and no longer pre-empts
Docker's policy. In practice the older image could not create a working managed
bridge at all (that is what #1032 reports), so few deployments will have relied
on it, but a setup that used the reported workaround of disabling DHCP and IPv6
will now need the rule below.

One rule per managed bridge fixes it:

```sh
iptables -w 5 -I DOCKER-USER -i <bridge> -o <bridge> -j ACCEPT
ip6tables -w 5 -I DOCKER-USER -i <bridge> -o <bridge> -j ACCEPT
```

Measured in a CVM with Incus 6.0.4 and two system containers on a managed
bridge: 100% packet loss before, 0% after, for both IPv4 and IPv6.

One benefit of the single nftables dataplane is that this is now diagnosable.
`nft list ruleset` shows Docker's `policy drop` and Incus's accept rules
together; when the two lived in different rulesets, neither `iptables -L` nor
`nft list ruleset` alone showed both halves of the interaction.

## Adding a capability

Kernel configuration lives in two fragments, one per backend:

- `os/yocto/layers/meta-dstack/recipes-kernel/linux/files/dstack-docker.cfg`
- `os/mkosi/components/kernel/kernel.config`

Their bridge-filtering blocks are deliberately identical. Keep them that way:
that is the capability the two images silently disagreed on.

A fragment line is a request, not a guarantee. Kconfig silently drops a symbol
whose dependencies are unmet, and silently clamps a tristate to the value of
what it depends on — `CONFIG_BRIDGE_NF_EBTABLES=y` under `CONFIG_BRIDGE=m`
becomes `=m`, and the build still succeeds. Check the produced `.config` rather
than assuming, with `os/common/scripts/check-kernel-config.sh <.config>
<fragment...>`; both backends run it, mkosi during the kernel build and Yocto
in `os/yocto/scripts/export-artifacts.sh` before anything is published.

On the Yocto backend a module also has to be *packaged* into the rootfs.
`RDEPENDS:${KERNEL_PACKAGE_NAME}-base` is cleared in
`layers/meta-dstack/conf/machine/dstack.conf`, so the image contains only the
`kernel-module-*` packages named explicitly in
`layers/meta-dstack/recipes-core/images/dstack-rootfs-base.inc` plus those
pulled in by `RRECOMMENDS` — notably the `ip6table_*` and `xt_checksum` modules
recommended by the `iptables` recipe, which are installed only once the kernel
actually builds them. The mkosi backend runs a full `modules_install`, so every
module its config produces is present.

# Program netfilter through nftables, not the legacy xtables tables.
#
# Without libnftnl this recipe builds only the legacy binaries, so every rule
# on the image -- Docker's, dstack's own DSTACK_WG chain, and any a tenant
# workload writes -- lands in the legacy tables. The legacy and nf_tables
# rulesets register at the same netfilter hooks but cannot see each other, so
# the resulting ruleset is only knowable by querying both, and a container
# manager that picks a firewall driver by probing which ruleset is in use is
# steered onto its legacy path by Docker alone. os/mkosi already programs
# nftables, because Debian's iptables defaults to the nft frontend; this makes
# the two guest images agree.
PACKAGECONFIG:append = " libnftnl"

# The recipe's own do_install only redirects the IPv4 frontends when libnftnl
# is enabled, which would leave ip6tables and ebtables on the legacy tables and
# reintroduce the split this change exists to remove. xtables-nft-multi
# implements all of them and dispatches on argv[0].
#
# ebtables is included here rather than installing the standalone ebtables
# recipe: that one is legacy-only, registers /usr/sbin/ebtables through
# update-alternatives, and would collide with this symlink.
DSTACK_NFT_FRONTENDS = "ip6tables ip6tables-save ip6tables-restore ebtables ebtables-save ebtables-restore"

do_install:append() {
    for frontend in ${DSTACK_NFT_FRONTENDS}; do
        ln -sf ${sbindir}/xtables-nft-multi ${D}${sbindir}/$frontend
    done
}

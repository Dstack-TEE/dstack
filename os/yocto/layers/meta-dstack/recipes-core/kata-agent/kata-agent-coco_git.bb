SUMMARY = "Kata agent with CoCo initdata support for dstack guest images"
DESCRIPTION = "Modern Rust Kata agent built with init-data and agent-policy features, used to boot dstack rootfs as a Kata/CoCo guest image."
HOMEPAGE = "https://github.com/kata-containers/kata-containers"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=86d3f3a95c324c9479bd8986968f4327"

SRCREV = "d7be140eee9f96452a6120c65320cef8be1c7ecc"
SRC_URI = "git://github.com/kata-containers/kata-containers.git;protocol=https;branch=main \
           file://0001-kata-agent-build-with-rust-1.92.patch \
"

PV = "0.1.0+git"

inherit cargo_bin systemd

# Build only the in-guest agent.  Enable the two features required by the
# CoCo/Kata initdata flow:
# - init-data: read the initdata block device and extract aa.toml/cdh.toml/policy.rego
# - agent-policy: initialize the Kata agent policy engine from policy.rego
# Seccomp/devicemapper are intentionally left out for this first MVP to keep
# the dependency surface small.
CARGO_FEATURES = "kata-agent/init-data kata-agent/agent-policy"
EXTRA_CARGO_FLAGS = "--no-default-features -p kata-agent"

do_compile[network] = "1"

SYSTEMD_PACKAGES = "${@bb.utils.contains('DISTRO_FEATURES','systemd','${PN}','',d)}"
SYSTEMD_SERVICE:${PN} = "${@bb.utils.contains('DISTRO_FEATURES','systemd','kata-agent.service','',d)}"
# Do not start kata-agent in a normal dstack boot.  Kata runtime should boot the
# image with systemd.unit=kata-containers.target (or otherwise explicitly start
# kata-agent.service) when this rootfs is used as a Kata guest image.
SYSTEMD_AUTO_ENABLE:${PN} = "disable"

PROVIDES += "kata-agent"
RPROVIDES:${PN} += "kata-agent"
RDEPENDS:${PN} += "bash systemd"

KATA_AGENT_VERSION ?= "${PV}"
KATA_AGENT_API_VERSION ?= "0.0.1"

kata_agent_generate_file() {
    src="$1"
    dst="$2"
    install -d "$(dirname "$dst")"
    sed \
        -e 's|@AGENT_NAME@|kata-agent|g' \
        -e 's|@AGENT_VERSION@|${KATA_AGENT_VERSION}|g' \
        -e 's|@API_VERSION@|${KATA_AGENT_API_VERSION}|g' \
        -e 's|@BINDIR@|${bindir}|g' \
        -e 's|@COMMIT@|${SRCREV}|g' \
        -e 's|@VERSION_COMMIT@|${KATA_AGENT_VERSION}-${SRCREV}|g' \
        "$src" > "$dst"
}

do_configure() {
    cargo_bin_do_configure

    # Kata normally creates this file from src/agent/Makefile.  We build via
    # cargo_bin from the workspace root, so generate the small version module
    # here instead of invoking Kata's Makefile.
    kata_agent_generate_file \
        ${S}/src/agent/src/version.rs.in \
        ${S}/src/agent/src/version.rs
}

do_compile() {
    cargo_bin_do_compile
}

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${CARGO_BINDIR}/kata-agent ${D}${bindir}/kata-agent

    # The agent-policy feature initializes OPA before initdata is parsed.
    # Ship Kata's allow-all policy as the default baseline; initdata
    # policy.rego can still replace it after initdata extraction.
    install -d ${D}${sysconfdir}/kata-opa
    install -m 0644 ${S}/src/kata-opa/allow-all.rego \
        ${D}${sysconfdir}/kata-opa/default-policy.rego

    if ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'true', 'false', d)}; then
        install -d ${D}${systemd_system_unitdir}
        kata_agent_generate_file \
            ${S}/src/agent/kata-agent.service.in \
            ${D}${systemd_system_unitdir}/kata-agent.service
        install -m 0644 ${S}/src/agent/kata-containers.target \
            ${D}${systemd_system_unitdir}/kata-containers.target
        install -m 0644 ${S}/src/agent/kata-extension-mount@.service \
            ${D}${systemd_system_unitdir}/kata-extension-mount@.service

        install -d ${D}${libexecdir} ${D}${systemd_unitdir}/system-generators
        install -m 0755 ${S}/src/agent/kata-extension-mount.sh \
            ${D}${libexecdir}/kata-extension-mount.sh
        install -m 0755 ${S}/src/agent/kata-extension-umount.sh \
            ${D}${libexecdir}/kata-extension-umount.sh
        install -m 0755 ${S}/src/agent/kata-extension-mount-generator.sh \
            ${D}${systemd_unitdir}/system-generators/kata-extension-mount-generator
    fi
}

FILES:${PN} += " \
    ${sysconfdir}/kata-opa/default-policy.rego \
    ${systemd_system_unitdir}/kata-agent.service \
    ${systemd_system_unitdir}/kata-containers.target \
    ${systemd_system_unitdir}/kata-extension-mount@.service \
    ${libexecdir}/kata-extension-mount.sh \
    ${libexecdir}/kata-extension-umount.sh \
    ${systemd_unitdir}/system-generators/kata-extension-mount-generator \
"

# Cargo embeds build paths into binaries; allow TMPDIR references.
INSANE_SKIP:${PN} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"

SUMMARY = "Confidential Containers guest components for dstack guest images"
DESCRIPTION = "Initial, independent integration of selected Confidential Containers guest-components: attestation-agent, confidential-data-hub, and REST API server."
HOMEPAGE = "https://github.com/confidential-containers/guest-components"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=86d3f3a95c324c9479bd8986968f4327"

SRCREV = "3f931d10197d242675fa558d263aa740cc196c2f"
SRC_URI = "git://github.com/confidential-containers/guest-components.git;protocol=https;branch=main \
           file://coco-attestation-agent.service \
           file://coco-confidential-data-hub.service \
           file://coco-api-server-rest.service \
           file://attestation-agent.conf \
           file://confidential-data-hub.conf \
           file://ocicrypt_config.json \
           file://pause-config.json \
           file://coco-pause.c \
"

PV = "0.1.0+git"

inherit cargo_bin systemd

# Keep this first cut TDX-focused while enabling the CoCo KBS resource path:
# - attestation-agent: ttRPC server plus the Linux TSM_REPORTS based TDX attester.
# - attestation-agent/kbs: serve KBS attestation tokens to CDH's cc_kbc path.
# - confidential-data-hub/kbs: enable the KBS KBC plugin in addition to
#   offline_fs_kbc.  Runtime still selects the backend through cdh.toml or
#   agent.aa_kbc_params, so offline_fs_kbc remains usable.
# - api-server-rest: REST bridge exposing both AA and CDH APIs on loopback.
CARGO_FEATURES = " \
    attestation-agent/bin \
    attestation-agent/ttrpc \
    attestation-agent/tdx-attester \
    attestation-agent/rust-crypto \
    attestation-agent/kbs \
    confidential-data-hub/bin \
    confidential-data-hub/ttrpc \
    confidential-data-hub/kbs \
"

EXTRA_CARGO_FLAGS = " \
    --no-default-features \
    -p attestation-agent --bin ttrpc-aa \
    -p confidential-data-hub --bin ttrpc-cdh \
    -p api-server-rest --bin api-server-rest \
"

# This layer's cargo_bin class intentionally lets cargo resolve crates directly.
# guest-components also has git dependencies, so network access is required here.
do_compile[network] = "1"

SYSTEMD_PACKAGES = "${@bb.utils.contains('DISTRO_FEATURES','systemd','${PN}','',d)}"
SYSTEMD_SERVICE:${PN} = "${@bb.utils.contains('DISTRO_FEATURES','systemd','coco-attestation-agent.service coco-confidential-data-hub.service coco-api-server-rest.service','',d)}"
# In the Kata/CoCo MVP the modern kata-agent is responsible for launching
# AA/CDH/api-server-rest after it has parsed initdata.  Keep the standalone
# systemd units installed for manual/non-Kata testing, but do not auto-start
# them to avoid racing/double-starting the agent-owned processes.
SYSTEMD_AUTO_ENABLE:${PN} = "disable"

do_configure() {
    cargo_bin_do_configure
}

do_compile() {
    # Kata's confidential/guest-pull path asks the guest kata-agent to synthesize
    # the Kubernetes sandbox ("pause") container from a pre-baked bundle at
    # /pause_bundle.  The agent only copies args[0] from that bundle into the
    # generated rootfs, so keep this executable static and self-contained.
    ${CC} ${CFLAGS} -static -fno-pie -no-pie ${UNPACKDIR}/coco-pause.c \
        -o ${WORKDIR}/coco-pause ${LDFLAGS}

    export TARGET_CC="${WRAPPER_DIR}/cc-wrapper.sh"
    export TARGET_CXX="${WRAPPER_DIR}/cxx-wrapper.sh"
    export CC="${WRAPPER_DIR}/cc-wrapper.sh"
    export CXX="${WRAPPER_DIR}/cxx-wrapper.sh"
    export BUILD_CC="${WRAPPER_DIR}/cc-native-wrapper.sh"
    export BUILD_CXX="${WRAPPER_DIR}/cxx-native-wrapper.sh"
    export TARGET_LD="${WRAPPER_DIR}/linker-wrapper.sh"
    export LD="${WRAPPER_DIR}/linker-wrapper.sh"
    export PKG_CONFIG_ALLOW_CROSS="1"

    # cargo_bin.bbclass normally clears LDFLAGS.  Some rustls/aws-lc-sys
    # dependencies compile and execute tiny C feature-test programs when
    # BUILD_SYS and TARGET_SYS are both x86_64.  The target GCC's default ELF
    # interpreter path is not runnable on the build host, so use the build-host
    # dynamic linker only for those build-script probes.  The final Rust target
    # link still goes through linker-wrapper.sh, generated during do_configure
    # with the normal target LDFLAGS.
    export LDFLAGS="${BUILD_LDFLAGS}"

    export RUSTFLAGS="${RUSTFLAGS}"
    export SSH_AUTH_SOCK="${SSH_AUTH_SOCK}"

    # This "DO_NOT_USE_THIS" option of cargo is currently the only way to
    # configure a different linker for host and target builds when RUST_BUILD ==
    # RUST_TARGET.
    export __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS="nightly"
    export CARGO_UNSTABLE_TARGET_APPLIES_TO_HOST="true"
    export CARGO_UNSTABLE_HOST_CONFIG="true"
    export CARGO_TARGET_APPLIES_TO_HOST="false"
    export CARGO_TARGET_${CARGO_TARGET_LINKER_NAME}_LINKER="${WRAPPER_DIR}/linker-wrapper.sh"
    export CARGO_HOST_LINKER="${WRAPPER_DIR}/linker-native-wrapper.sh"
    export CARGO_BUILD_FLAGS="-C rpath"
    export CARGO_PROFILE_RELEASE_DEBUG="true"

    # The CC crate defaults to using CFLAGS when compiling everything. We can
    # give it custom flags for compiling on the host.
    export HOST_CXXFLAGS=""
    export HOST_CFLAGS=""

    bbnote "which rustc:" `which rustc`
    bbnote "rustc --version" `rustc --version`
    bbnote "which cargo:" `which cargo`
    bbnote "cargo --version" `cargo --version`
    bbnote cargo build ${CARGO_BUILD_FLAGS}
    cargo build ${CARGO_BUILD_FLAGS}
}

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${CARGO_BINDIR}/ttrpc-aa ${D}${bindir}/ttrpc-aa
    install -m 0755 ${CARGO_BINDIR}/ttrpc-cdh ${D}${bindir}/ttrpc-cdh
    install -m 0755 ${CARGO_BINDIR}/api-server-rest ${D}${bindir}/api-server-rest

    # Modern kata-agent's built-in CoCo launch plan still looks for the
    # historical CoCo rootfs paths under /usr/local/bin.  Provide compatibility
    # symlinks while keeping the real binaries in ${bindir}.
    install -d ${D}${prefix}/local/bin
    ln -sf ${bindir}/ttrpc-aa ${D}${prefix}/local/bin/attestation-agent
    ln -sf ${bindir}/ttrpc-cdh ${D}${prefix}/local/bin/confidential-data-hub
    ln -sf ${bindir}/api-server-rest ${D}${prefix}/local/bin/api-server-rest

    install -d ${D}${sysconfdir}
    install -m 0644 ${UNPACKDIR}/attestation-agent.conf ${D}${sysconfdir}/attestation-agent.conf
    install -m 0644 ${UNPACKDIR}/confidential-data-hub.conf ${D}${sysconfdir}/confidential-data-hub.conf
    install -m 0644 ${UNPACKDIR}/ocicrypt_config.json ${D}${sysconfdir}/ocicrypt_config.json

    # Legacy monolithic-rootfs locations consumed by kata-agent when no CoCo
    # extension image is mounted.
    install -d ${D}/pause_bundle/rootfs
    install -m 0644 ${UNPACKDIR}/pause-config.json ${D}/pause_bundle/config.json
    install -m 0755 ${WORKDIR}/coco-pause ${D}/pause_bundle/rootfs/pause

    if ${@bb.utils.contains('DISTRO_FEATURES', 'systemd', 'true', 'false', d)}; then
        install -d ${D}${systemd_system_unitdir}
        install -m 0644 ${UNPACKDIR}/coco-attestation-agent.service ${D}${systemd_system_unitdir}/coco-attestation-agent.service
        install -m 0644 ${UNPACKDIR}/coco-confidential-data-hub.service ${D}${systemd_system_unitdir}/coco-confidential-data-hub.service
        install -m 0644 ${UNPACKDIR}/coco-api-server-rest.service ${D}${systemd_system_unitdir}/coco-api-server-rest.service
    fi
}

FILES:${PN} += " \
    ${systemd_system_unitdir}/coco-attestation-agent.service \
    ${systemd_system_unitdir}/coco-confidential-data-hub.service \
    ${systemd_system_unitdir}/coco-api-server-rest.service \
    ${sysconfdir}/attestation-agent.conf \
    ${sysconfdir}/confidential-data-hub.conf \
    ${sysconfdir}/ocicrypt_config.json \
    ${prefix}/local/bin/attestation-agent \
    ${prefix}/local/bin/confidential-data-hub \
    ${prefix}/local/bin/api-server-rest \
    /pause_bundle \
"

# Cargo embeds build paths into binaries; allow TMPDIR references.
INSANE_SKIP:${PN} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"

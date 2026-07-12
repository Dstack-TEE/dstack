SUMMARY = "NVIDIA GPU attestation CLI"
DESCRIPTION = "Builds NVIDIA's nvattest CLI. dstack-util setup runs it at boot to gate readiness on local GPU TEE attestation (app-compose requirements.verify_gpu)."
HOMEPAGE = "https://github.com/NVIDIA/attestation-sdk"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=e620fc90e76c4aa0c3efdd1673ca0b3b"

SRC_URI = " \
    git://github.com/NVIDIA/attestation-sdk.git;protocol=https;branch=main \
    file://10-nvidia-gpu-ordering.conf \
"
SRCREV = "9d12801cea8a198ea0f29640dfaf8a4017c841c5"

OECMAKE_SOURCEPATH = "${S}/nv-attestation-cli"

inherit cmake pkgconfig

# The SDK embeds the regorus Rego policy engine (Rust, via Corrosion), so a
# Rust toolchain is required. Use the prebuilt toolchain from meta-rust-bin
# (cargo-bin-native pulls rust-bin-cross-${TARGET_ARCH}), the same toolchain
# dstack-guest builds with -- NOT oe-core's rust-native (bootstraps rustc from
# source, very expensive).
DEPENDS += " \
    cargo-bin-native \
    curl \
    openssl \
    libxml2 \
    xmlsec1 \
    spdlog \
    nlohmann-json \
    nvidia \
"

RDEPENDS:${PN} += " \
    ca-certificates \
    nvidia \
    nvidia-fabricmanager \
    nvidia-persistenced \
"

EXTRA_OECMAKE += " \
    -DBUILD_TESTING=OFF \
    -DNVAT_BUILD_TESTS=OFF \
    -DNVAT_BUILD_SAMPLES=OFF \
    -DCMAKE_SKIP_RPATH=ON \
    -DFETCHCONTENT_FULLY_DISCONNECTED=OFF \
    -DUSE_SYSTEM_DEPS=ON \
"

# Keep cargo state inside the workdir (Corrosion invokes cargo for regorus).
export CARGO_HOME = "${WORKDIR}/cargo_home"
export RUST_BACKTRACE = "1"

# rustc does not inherit the C toolchain's -ffile-prefix-map, so the regorus
# static lib embedded in libnvat would otherwise carry TMPDIR paths
# ([buildpaths] QA / reproducibility issue).
export RUSTFLAGS = "--remap-path-prefix=${WORKDIR}=/usr/src/debug/${PN}/${PV}"

# Corrosion invokes cargo with host triple == target triple
# (x86_64-unknown-linux-gnu). Cargo would then link host-side build scripts
# with the cross gcc but without the target sysroot (cannot find Scrt1.o/-lc).
# Split host vs target linker config the same way meta-rust-bin's cargo_bin
# class does: build scripts link with the native toolchain.
do_compile:prepend() {
    mkdir -p ${WORKDIR}/wrappers
    echo "#!/bin/sh" > ${WORKDIR}/wrappers/linker-native-wrapper.sh
    echo "${BUILD_CC} ${BUILD_LDFLAGS} \"\$@\"" >> ${WORKDIR}/wrappers/linker-native-wrapper.sh
    chmod +x ${WORKDIR}/wrappers/linker-native-wrapper.sh

    export __CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS="nightly"
    export CARGO_UNSTABLE_TARGET_APPLIES_TO_HOST="true"
    export CARGO_UNSTABLE_HOST_CONFIG="true"
    export CARGO_TARGET_APPLIES_TO_HOST="false"
    export CARGO_HOST_LINKER="${WORKDIR}/wrappers/linker-native-wrapper.sh"
}

# Network is needed at configure/compile time because:
#  - nv-attestation-cli CMake FetchContent: CLI11, nlohmann-json (+ fmt/spdlog
#    headers)
#  - nv-attestation-sdk-cpp CMake FetchContent: Corrosion, regorus, jwt-cpp
#  - Corrosion runs cargo, which fetches the regorus-ffi crate dependencies
# All refs are pinned (git tags/commits) upstream. TODO: vendor these via
# SRC_URI + cargo vendor for a fully offline, reproducible fetch.
do_configure[network] = "1"
do_compile[network] = "1"

do_install() {
    DESTDIR=${D} cmake --install ${B} --prefix ${prefix}

    if [ ! -x ${D}${bindir}/nvattest ]; then
        bbfatal "nvattest binary was not produced by the build"
    fi

    # cargo/Corrosion leaves host-side proc-macro dylibs in the build tree;
    # make sure none of them ever end up in the image (only libnvat is a
    # real target library).
    find ${D}${libdir} -maxdepth 1 -name 'lib*.so*' ! -name 'libnvat.so*' -delete

    # Make dstack-prepare (which runs the attestation) start after the nvidia
    # userspace services it depends on.
    install -d ${D}${systemd_system_unitdir}/dstack-prepare.service.d
    install -m 0644 ${UNPACKDIR}/10-nvidia-gpu-ordering.conf \
        ${D}${systemd_system_unitdir}/dstack-prepare.service.d/10-nvidia-gpu-ordering.conf
}

FILES:${PN} += " \
    ${systemd_system_unitdir}/dstack-prepare.service.d/10-nvidia-gpu-ordering.conf \
    ${libdir}/lib*.so \
    ${libdir}/lib*.so.* \
"
FILES_SOLIBSDEV = ""
FILES:${PN}-dev:remove = "${libdir}/lib*.so"

INSANE_SKIP:${PN} += "dev-so already-stripped"

require nvidia-container-toolkit.inc

SUMMARY = "NVIDIA Container Toolkit for Yocto"

GO_INSTALL = "${GO_IMPORT}/cmd/..."
# The go-nvml symbol lookup functions *require* lazy dynamic symbol resolution
SECURITY_LDFLAGS = ""
LDFLAGS += "-Wl,-z,lazy"
GO_LINKSHARED = ""

REQUIRED_DISTRO_FEATURES = "virtualization"

inherit go go-mod features_check

do_compile() {
    echo "Current directory: $(pwd)"
    ls -alh
    oe_runmake -C ${S}/src/${GO_IMPORT} cmds
    
}

install_bin_stripped() {
    install -m 0755 ${S}/src/${GO_IMPORT}/$1 ${D}${bindir}/$1
    ${STRIP} --remove-section=.note.gnu.build-id ${D}${bindir}/$1
    ${STRIP} --remove-section=.note.go.buildid ${D}${bindir}/$1
}

do_install() {
    # Create the target directories in the image file system
    install -d ${D}${bindir}
    
    # Copy each binary to the target directory
    install_bin_stripped nvidia-container-runtime
    install_bin_stripped nvidia-container-runtime.cdi
    install_bin_stripped nvidia-container-runtime-hook
    install_bin_stripped nvidia-container-runtime.legacy
    install_bin_stripped nvidia-ctk

    ln -sf nvidia-container-runtime-hook ${D}${bindir}/nvidia-container-toolkit

    # create config.toml
    # Ensure the installation directory exists
    install -d ${D}/etc/nvidia-container-runtime
    # Install the config.toml file
    install -m 0644 ${UNPACKDIR}/config.toml ${D}/etc/nvidia-container-runtime/config.toml
}

INSANE_SKIP:${PN} += "already-stripped buildpaths textrel"
INSANE_SKIP:${PN}:append = "already-stripped buildpaths textrel"
FILES_${PN} += "/usr/local/*"

RDEPENDS:${PN} = "\
    libnvidia-container \
    "
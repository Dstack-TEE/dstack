SUMMARY = "OpenZFS on Linux and FreeBSD"
DESCRIPTION = "OpenZFS on Linux and FreeBSD"
LICENSE = "CDDL-1.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=7087caaf1dc8a2856585619f4a787faa"
HOMEPAGE = "https://github.com/openzfs/zfs"

SRCREV = "743334913e5a5f60baf287bcc6d8a23515b02ac5"
SRC_URI = "git://github.com/openzfs/zfs;protocol=https;branch=zfs-2.4-release \
           file://0001-Define-strndupa-if-it-does-not-exist.patch \
"


# Using both 'module' and 'autotools' classes seems a bit odd, they both
# define a do_compile function.
# That's why we opt for module-base, also this prevents module splitting.
inherit module-base pkgconfig autotools bash-completion

DEPENDS = "virtual/kernel zlib util-linux libtirpc openssl curl"

PACKAGECONFIG ?= "${@bb.utils.filter('DISTRO_FEATURES', 'systemd sysvinit', d)}"

PACKAGECONFIG[pam] = "--enable-pam --with-pamconfigsdir=${datadir}/pam-configs --with-pammoduledir=${libdir}/security, --disable-pam"
PACKAGECONFIG[systemd] = "--enable-systemd,--disable-systemd,"
PACKAGECONFIG[sysvinit] = "--enable-sysvinit,--disable-sysvinit,"

EXTRA_OECONF:append = " \
    --disable-pyzfs \
    --with-linux=${STAGING_KERNEL_DIR} --with-linux-obj=${STAGING_KERNEL_BUILDDIR} \
    --with-mounthelperdir=${base_sbin} \
    --with-udevdir=${base_libdir}/udev \
    --with-systemdunitdir=${systemd_system_unitdir} \
    --with-systemdgeneratordir=${nonarch_base_libdir}/systemd/system-generators \
    --with-systemdpresetdir=${nonarch_base_libdir}/systemd/system-preset \
    --with-systemdmodulesloaddir=${sysconfdir}/module-load.d \
    --without-dracutdir \
"

EXTRA_OEMAKE:append = " \
    INSTALL_MOD_PATH=${D}${root_prefix} \
"

do_install:append() {
    # /usr/share/zfs contains the zfs-tests folder which we do not need:
    rm -rf ${D}${datadir}/zfs

    rm -rf ${D}${datadir}/initramfs-tools
}

FILES:${PN} += "\
    ${nonarch_base_libdir}/modules \
    ${systemd_system_unitdir} \
    ${nonarch_base_libdir}/systemd/system-generators \
    ${nonarch_base_libdir}/systemd/system-preset \
    ${sysconfdir}/modules-load.d/${BPN}.conf \
    ${sysconfdir}/default/${BPN} \
    ${sysconfdir}/sudoers.d/${BPN} \
    ${sysconfdir}/${BPN} \
    ${base_libdir}/udev \
    ${sbindir} \
    ${bindir} \
    ${libexecdir}/${BPN} \
    ${libdir} \
"

FILES:${PN}-dev += "\
    ${prefix}/src/zfs-${PV} \
    ${prefix}/src/spl-${PV} \
"
# Skip buildpaths QA check for kernel modules
INSANE_SKIP:${PN} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"

# Not yet ported to rv32
COMPATIBLE_HOST:riscv32 = "null"
# conflicting definition of ABS macro from asm/asm.h from kernel
COMPATIBLE_HOST:mips = "null"
# FTBFS on aarch64 with 6.2+ kernel see https://github.com/openzfs/zfs/issues/14555
COMPATIBLE_HOST:aarch64 = "null"

SUMMARY = "Transport-Independent RPC library"
DESCRIPTION = "Libtirpc is a port of Suns Transport-Independent RPC library to Linux"
SECTION = "libs/network"
HOMEPAGE = "http://sourceforge.net/projects/libtirpc/"
BUGTRACKER = "http://sourceforge.net/tracker/?group_id=183075&atid=903784"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://COPYING;md5=f835cce8852481e4b2bbbdd23b5e47f3 \
                    file://src/netname.c;beginline=1;endline=27;md5=f8a8cd2cb25ac5aa16767364fb0e3c24"

SRC_URI = "${SOURCEFORGE_MIRROR}/libtirpc/libtirpc-${PV}.tar.bz2"
SRC_URI[sha256sum] = "1e0b0c7231c5fa122e06c0609a76723664d068b0dba3b8219b63e6340b347860"

# SRC_URI += "file://0001-__rpc_dtbsize-rlim_cur-instead-of-rlim_max.patch"

S = "${UNPACKDIR}/libtirpc-${PV}"

inherit autotools pkgconfig

DISABLE_STATIC = ""
EXTRA_OECONF = "--disable-gssapi --enable-static"

# Append -fPIC to CFLAGS and fix GCC 15 compatibility
CFLAGS:append = " -fPIC -Wno-error=incompatible-pointer-types -Wno-error=int-conversion -std=gnu17"

do_install:append() {
    rm -r ${D}${sysconfdir} ${D}${datadir} ${D}${libdir}/pkgconfig
    rm ${D}${libdir}/*.so*
    cp -r ${D}${includedir}/tirpc ${D}${includedir}/tirpc-1.3.4
}

inherit nopackages

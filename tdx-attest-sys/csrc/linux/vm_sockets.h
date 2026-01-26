// SPDX-FileCopyrightText: VMware, Inc.
// SPDX-FileCopyrightText: Linux kernel contributors
//
// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

/*
 * Minimal vendored version of linux/vm_sockets.h for MUSL compatibility.
 *
 * This header provides the minimal definitions needed by tdx_attest.c
 * without pulling in glibc-specific headers that conflict with MUSL.
 *
 * Based on: Linux kernel include/uapi/linux/vm_sockets.h
 * Original copyright: VMware, Inc.
 */

#ifndef _VM_SOCKETS_H
#define _VM_SOCKETS_H

#include <stdint.h>
#include <sys/socket.h>

/* AF_VSOCK = PF_VSOCK = 40 */
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

/* Use this as the destination CID in an address when referring to the host
 * (any process other than the hypervisor).
 */
#define VMADDR_CID_HOST 2

/* Address structure for vSockets. The address family should be set to
 * AF_VSOCK.
 */
struct sockaddr_vm {
    sa_family_t svm_family;           /* Address family: AF_VSOCK */
    unsigned short svm_reserved1;     /* Reserved, must be zero */
    unsigned int svm_port;            /* Port, in host byte order */
    unsigned int svm_cid;             /* Context ID (CID) */
    uint8_t svm_flags;                /* Flags */
    unsigned char svm_zero[sizeof(struct sockaddr) -
                           sizeof(sa_family_t) -
                           sizeof(unsigned short) -
                           sizeof(unsigned int) -
                           sizeof(unsigned int) -
                           sizeof(uint8_t)];
};

#endif /* _VM_SOCKETS_H */

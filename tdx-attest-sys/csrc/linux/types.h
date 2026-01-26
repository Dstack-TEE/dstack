// SPDX-FileCopyrightText: Linux kernel contributors
//
// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

/*
 * Minimal vendored linux/types.h for MUSL compatibility.
 *
 * Provides kernel-style type aliases (__u8, __u16, __u32, __u64)
 * using standard C types from stdint.h.
 */

#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#include <stdint.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;

/* Kernel-style sa_family_t if not already defined */
#ifndef __kernel_sa_family_t
typedef unsigned short __kernel_sa_family_t;
#endif

#endif /* _LINUX_TYPES_H */

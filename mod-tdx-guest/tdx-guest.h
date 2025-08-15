// SPDX-FileCopyrightText: © 2022 Intel Corporation
// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
/*
 * Userspace interface for TDX guest driver
 *
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _UAPI_LINUX_TDX_GUEST_H_
#define _UAPI_LINUX_TDX_GUEST_H_

#include <linux/ioctl.h>
#include <linux/types.h>

/* Length of the REPORTDATA used in TDG.MR.REPORT TDCALL */
#define TDX_REPORTDATA_LEN              64

/* Length of TDREPORT used in TDG.MR.REPORT TDCALL */
#define TDX_REPORT_LEN                  1024

/**
 * struct tdx_report_req - Request struct for TDX_CMD_GET_REPORT0 IOCTL.
 *
 * @reportdata: User buffer with REPORTDATA to be included into TDREPORT.
 *              Typically it can be some nonce provided by attestation
 *              service, so the generated TDREPORT can be uniquely verified.
 * @tdreport: User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT].
 */
struct tdx_report_req {
	__u8 reportdata[TDX_REPORTDATA_LEN];
	__u8 tdreport[TDX_REPORT_LEN];
};

/*
 * TDX_CMD_GET_REPORT0 - Get TDREPORT0 (a.k.a. TDREPORT subtype 0) using
 *                       TDCALL[TDG.MR.REPORT]
 *
 * Return 0 on success, -EIO on TDCALL execution failure, and
 * standard errno on other general error cases.
 */
#define TDX_CMD_GET_REPORT0              _IOWR('T', 1, struct tdx_report_req)

#define TDX_CMD_EXTEND_RTMR _IOR('T', 3, struct tdx_extend_rtmr_req)
#define TDX_CMD_EXTEND_RTMR2 _IOW('T', 3, struct tdx_extend_rtmr_req)
#define TDX_EXTEND_RTMR_DATA_LEN 48
struct tdx_extend_rtmr_req
{
	u8 data[TDX_EXTEND_RTMR_DATA_LEN];
	u8 index;
};

#endif /* _UAPI_LINUX_TDX_GUEST_H_ */

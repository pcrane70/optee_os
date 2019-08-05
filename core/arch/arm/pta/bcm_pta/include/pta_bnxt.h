/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef PTA_BNXT_H
#define PTA_BNXT_H

#define BNXT_SERVICE_UUID \
		{0x6272636D, 0x2019, 0x0716,  \
		{0x42, 0x43, 0x4D, 0x5F, 0x53, 0x43, 0x48, 0x49} }

enum {
	PTA_BNXT_FASTBOOT = 0,
} pta_bnxt_cmd;

#define BNXT_TA_NAME		"pta_bnxt.ta"
#endif /* PTA_BNXT_H */

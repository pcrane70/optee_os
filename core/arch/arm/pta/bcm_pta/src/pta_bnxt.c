// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm-include/bnxt.h>
#include <io.h>
#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <pta_bnxt.h>
#include <string.h>
#include <util.h>


static TEE_Result create_ta(void)
{
	DMSG("create entry point for static ta \"%s\"", BNXT_TA_NAME);
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
	DMSG("destroy entry point for static ta \"%s\"", BNXT_TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[4] __unused,
			       void **ppSessionContext __unused)
{
	DMSG("open entry point for static ta \"%s\"", BNXT_TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for static ta \"%s\"", BNXT_TA_NAME);
}


static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID,
				 uint32_t nParamTypes __unused,
				 TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", nCommandID, BNXT_TA_NAME);

	switch (nCommandID) {
	case PTA_BNXT_FASTBOOT:
		DMSG("BNXT FASTBOOT\n");
		if (bnxt_load_fw(1) != BNXT_SUCCESS)
			return TEE_ERROR_TARGET_DEAD;
		break;
	default:
		DMSG("%d Not supported %s\n", nCommandID, BNXT_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = BNXT_SERVICE_UUID,
		   .name = BNXT_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);

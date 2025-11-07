// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Nuclei - All Rights Reserved
 */

#include "common.h"
#include <trace.h>
#include <kernel/panic.h>
#include <initcall.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>

void* mailbox_base;

register_phys_mem(MEM_AREA_IO_SEC, NUCLEI_MAILBOX_BASE, NUCLEI_MAILBOX_SIZE);

static TEE_Result nuclei_hsm_cryp_init(void)
{
	TEE_Result res = TEE_SUCCESS;

	res = nuclei_register_cipher();
	if (res) {
		EMSG("Failed to register to cipher: %#"PRIx32, res);
		panic();
	}
	res = nuclei_register_hash();
	if (res) {
		EMSG("Failed to register to hash: %#"PRIx32, res);
		panic();
	}
	res = nuclei_register_hmac();
	if (res) {
		EMSG("Failed to register to hmac: %#"PRIx32, res);
		panic();
	}
	res = nuclei_register_rsa();
	if (res) {
		EMSG("Failed to register to rsa: %#"PRIx32, res);
		panic();
	}
	/* map mailbox region */
	mailbox_base = (void *)core_mmu_get_va(NUCLEI_MAILBOX_BASE, MEM_AREA_IO_SEC,
		NUCLEI_MAILBOX_SIZE);

	return TEE_SUCCESS;
}

early_init(nuclei_hsm_cryp_init);
// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Nuclei - All Rights Reserved
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <string.h>
#include <utee_defines.h>
#include <utee_types.h>
#include <tee/cache.h>
#include <kernel/tee_misc.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>

#include "common.h"
#include "nuclei_hsm_abi.h"
#include "mailbox.h"

#define OP_ALG(alg)	((SECURE_SERVICE_CRYP_##alg << 4) & 0xF)
#define ALG_MODE(mod)	(SECURE_SERVICE_CRYP_##mod & 0xF)

/*
 * Definition of flags tagging which key(s) is required
 */
#define NEED_KEY1  BIT(0)
#define NEED_KEY2  BIT(1)
#define NEED_IV    BIT(2)
#define NEED_TWEAK BIT(3)

/*
 * Definition of key size
 */
struct cipher_defkey {
	uint8_t min; /* Minimum size */
	uint8_t max; /* Maximum size */
	uint8_t mod; /* Key modulus */
};
/*
 * Cipher Algorithm definition
 */
struct cipheralg {
	uint32_t type;             /* Algo type for operation */
	uint8_t size_block;        /* Computing block size */
	uint8_t require_key;       /* Tag defining key(s) required */
	struct cipher_defkey def_key; /* Key size accepted */
};

struct cipherdata {
	mailbox_cryp_cmd_in_token cmd_desc;        /* cmd descriptor */
	const struct cipheralg *alg; /* Reference to the algo constants */
};
/*
 * Constants definition of the AES algorithm
 */
static const struct cipheralg aes_alg[] = {
	[TEE_CHAIN_MODE_ECB_NOPAD] = {
		.type = OP_ALG(AES) | ALG_MODE(ECB),
		.size_block = TEE_AES_BLOCK_SIZE,
		.require_key = NEED_KEY1,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
	},
	[TEE_CHAIN_MODE_CBC_NOPAD] = {
		.type = OP_ALG(AES) | ALG_MODE(CBC),
		.size_block = TEE_AES_BLOCK_SIZE,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
	},
	[TEE_CHAIN_MODE_CTR] = {
		.type = OP_ALG(AES) | ALG_MODE(CTR),
		.size_block = TEE_AES_BLOCK_SIZE,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
	},
};

static const struct cipheralg sm4_alg[] = {
	[TEE_CHAIN_MODE_ECB_NOPAD] = {
		.type = OP_ALG(SM4) | ALG_MODE(ECB),
		.size_block = TEE_AES_BLOCK_SIZE,
		.require_key = NEED_KEY1,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
	},
	[TEE_CHAIN_MODE_CBC_NOPAD] = {
		.type = OP_ALG(SM4) | ALG_MODE(CBC),
		.size_block = TEE_AES_BLOCK_SIZE,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
	},
	[TEE_CHAIN_MODE_CTR] = {
		.type = OP_ALG(SM4) | ALG_MODE(CTR),
		.size_block = TEE_AES_BLOCK_SIZE,
		.require_key = NEED_KEY1 | NEED_IV,
		.def_key = { .min = 16, .max = 32, .mod = 8 },
	},
};

static TEE_Result do_check_keysize(const struct cipher_defkey *def,
					 size_t keysize)
{
	if (keysize >= def->min && keysize <= def->max && !(keysize % def->mod))
		return TEE_SUCCESS;

	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result nuclei_cipher_initialize(struct drvcrypt_cipher_init *dinit)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct cipherdata *cipherdata = dinit->ctx;
	const struct cipheralg *alg = NULL;

	if (!cipherdata)
		return ret;

	alg = cipherdata->alg;

	/* Check if all required keys are defined */
	if (alg->require_key & NEED_KEY1) {
		if (!dinit->key1.data || !dinit->key1.length)
			goto out;

		ret = do_check_keysize(&alg->def_key, dinit->key1.length);
		if (ret != TEE_SUCCESS) {
			EMSG("Bad Key 1 size");
			goto out;
		}
		/* Copy the key 1 */
		memcpy(cipherdata->cmd_desc.key, dinit->key1.data,
			dinit->key1.length);
	}

	if (alg->require_key & NEED_IV) {
		if (!dinit->iv.data || !dinit->iv.length)
			goto out;

		if (dinit->iv.length != alg->size_block) {
			EMSG("Bad IV size %zu (expected %" PRId32 ")",
				     dinit->iv.length, alg->size_block);
			goto out;
		}

		/* Copy the IV */
		memcpy(cipherdata->cmd_desc.iv, dinit->iv.data,
			dinit->iv.length);
	}
	/* Save the operation direction */
	cipherdata->cmd_desc.cryp.cmd_cfg.encryp = (dinit->encrypt == true) ? 0 : 1;

	cipherdata->cmd_desc.cryp.cmd_cfg.key_length = SECURE_SERVICE_CRYP_KEY_128BITS;
	if (dinit->key1.length == 32)
		cipherdata->cmd_desc.cryp.cmd_cfg.key_length = SECURE_SERVICE_CRYP_KEY_256BITS;
	else if (dinit->key1.length == 24)
		cipherdata->cmd_desc.cryp.cmd_cfg.key_length = SECURE_SERVICE_CRYP_KEY_192BITS;
	else if (dinit->key1.length == 16)
		cipherdata->cmd_desc.cryp.cmd_cfg.key_length = SECURE_SERVICE_CRYP_KEY_128BITS;

	cipherdata->cmd_desc.cryp.cmd_cfg.key_sel = SECURE_SERVICE_CRYP_KEY_SEL_CFG;

	ret = TEE_SUCCESS;

out:
	return ret;
}

static TEE_Result nuclei_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	struct cipherdata *cipherdata = dupdate->ctx;
	int8_t mailbox_num;
	uint32_t rbuf[32]={0};
	uint32_t timeout = 100;
	uint8_t *aligned_outbuf = NULL;
	uint32_t outbuf_len = 0;
	uint32_t cache_line_sz;
	uint8_t local_buffer[64] __aligned(64);

	if (dupdate->src.length < cipherdata->alg->size_block ||
	    dupdate->src.length % cipherdata->alg->size_block) {
			EMSG("Bad payload/cipher size %zu bytes",
				dupdate->src.length);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/* flush src data to physical memory */
	cache_operation(TEE_CACHEFLUSH, dupdate->src.data,
			dupdate->src.length);
	cache_line_sz = cache_get_max_line_size();
	outbuf_len = (dupdate->src.length + cache_line_sz - 1) & ~(cache_line_sz - 1);
	if (outbuf_len > 64) {
		aligned_outbuf = alloc_cache_aligned(outbuf_len);
		if (aligned_outbuf == NULL) {
			EMSG("alloc_cache_aligned size %d fail", outbuf_len);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
	} else {
		aligned_outbuf = local_buffer;
	}
	cipherdata->cmd_desc.cryp.header.opcode = SECURE_SERVICE_OPCODE_CRYP;
	cipherdata->cmd_desc.cryp.input_data_addr_low = virt_to_phys(dupdate->src.data);
	cipherdata->cmd_desc.cryp.input_data_addr_hig = virt_to_phys(dupdate->src.data) >> 32;
	cipherdata->cmd_desc.cryp.length = dupdate->src.length;
	cipherdata->cmd_desc.cryp.input_data_length = dupdate->src.length;
	cipherdata->cmd_desc.cryp.output_data_length = dupdate->src.length;
	cipherdata->cmd_desc.cryp.output_data_addr_low = virt_to_phys(aligned_outbuf);
	cipherdata->cmd_desc.cryp.output_data_addr_hig = virt_to_phys(aligned_outbuf) >> 32;
	cipherdata->cmd_desc.cryp.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_ALL;

	do {
		mailbox_num = mailbox_avaliable_linked_num();
		if (mailbox_num != -1)
			break;
		timeout--;
	} while(timeout != 0);

	if (mailbox_num == -1) {
		EMSG("no available mailbox\n");
		return TEE_ERROR_BUSY;
	}

	mailbox_secure_service_host_send((uint32_t *)(&cipherdata->cmd_desc), SECURE_SERVICE_OPCODE_CRYP, mailbox_num);
	mailbox_secure_service_host_receive(rbuf, mailbox_num);

	if (rbuf[0] & BIT(31)) {
		EMSG("hsm crypto err:%x\n",(rbuf[0] >> 24) & 0x1F);
		return TEE_ERROR_GENERIC;
	}
	/* Here maybe need to improve */
	cache_operation(TEE_CACHEINVALIDATE, aligned_outbuf, outbuf_len);
	memcpy(dupdate->dst.data, aligned_outbuf, dupdate->dst.length);
	if(outbuf_len > 64)
		free(aligned_outbuf);

	return TEE_SUCCESS;
}

static void nuclei_cipher_final(void *ctx __unused)
{
}

static void nuclei_cipher_free(void *ctx)
{
	if (ctx) {
		//do_free_intern(ctx);
		free(ctx);
	}
}

static void nuclei_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	struct cipherdata *dst = dst_ctx;
	struct cipherdata *src = src_ctx;

	DMSG("Copy State context (%p) to (%p)", src_ctx, dst_ctx);

	dst->alg = src->alg;
	memcpy(&dst->cmd_desc, &src->cmd_desc, sizeof(mailbox_cryp_cmd_in_token));

	/* maybe this function need to support suspend, but hsm may not support */
}

static const struct cipheralg *get_cipheralgo(uint32_t algo)
{
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int algo_md = TEE_ALG_GET_CHAIN_MODE(algo);
	const struct cipheralg *ca = NULL;

	switch (algo_id) {
	case TEE_MAIN_ALGO_AES:
		if (algo_md < ARRAY_SIZE(aes_alg))
			ca = &aes_alg[algo_md];
		break;

	case TEE_MAIN_ALGO_SM4:
		if (algo_md < ARRAY_SIZE(sm4_alg))
			ca = &sm4_alg[algo_md];
		break;

	default:
		break;
	}

	return ca;
}

/*
 * Allocate the SW cipher data context.
 *
 * @ctx   [out] Caller context  variable
 * @algo  Algorithm ID of the context
 */
static TEE_Result nuclei_cipher_allocate(void **ctx, uint32_t algo)
{
	struct cipherdata *cipherdata = NULL;
	const struct cipheralg *alg = NULL;

	alg = get_cipheralgo(algo);
	if (!alg) {
		EMSG("Algorithm not supported");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	cipherdata = malloc(sizeof(*cipherdata));
	if (!cipherdata) {
		EMSG("Allocation Cipher data error");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memset(&cipherdata->cmd_desc, 0, sizeof(mailbox_cryp_cmd_in_token));
	cipherdata->cmd_desc.cryp.cmd_cfg.algo = (alg->type >> 4) & 0xF;
	cipherdata->cmd_desc.cryp.cmd_cfg.mode = alg->type & 0xF;

	cipherdata->alg = alg;

	*ctx = cipherdata;

	return TEE_SUCCESS;
}

static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = nuclei_cipher_allocate,
	.free_ctx = nuclei_cipher_free,
	.init = nuclei_cipher_initialize,
	.update = nuclei_cipher_update,
	.final = nuclei_cipher_final,
	.copy_state = nuclei_cipher_copy_state,
};

TEE_Result nuclei_register_cipher(void)
{
	return drvcrypt_register_cipher(&driver_cipher);
}

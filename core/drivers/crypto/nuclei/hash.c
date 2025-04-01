// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Nuclei - All Rights Reserved
 */

#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <string.h>
#include <utee_defines.h>
#include "common.h"
#include "nuclei_hsm_abi.h"
#include "mailbox.h"

#define CACHED_DATA_LEN	64

/*
 * Hash algorithm definition
 */
struct hashalg {
	uint8_t type;        /* Algo type for operation */
	uint8_t size_digest; /* Digest size */
	uint8_t size_block;  /* Computing block size */
};

struct hashctx {
	uint8_t data_buf[CACHED_DATA_LEN];    /* should be aligned by 4byte */
	uint32_t free_len;                    /* data buffer free length */
	mailbox_hash_cmd_in_token cmd_desc;   /* cmd descriptor */
	const struct hashalg *alg;            /* Reference to the algo constants */
};

struct crypto_hash {
	struct crypto_hash_ctx hash_ctx; /* Crypto Hash API context */
	struct hashctx *ctx;             /* Hash Context */
};

#define OP_ALG(alg)	((SECURE_SERVICE_HASH_##alg) & 0xF)

static const struct hashalg hash_alg[] = {
	{
		/* md5 */
		.type = OP_ALG(MD5),
		.size_digest = TEE_MD5_HASH_SIZE,
	},
	{
		/* sha1 */
		.type = OP_ALG(SHA1),
		.size_digest = TEE_SHA1_HASH_SIZE,
	},
	{
		/* sha224 */
		.type = OP_ALG(SHA224),
		.size_digest = TEE_SHA224_HASH_SIZE,
	},
	{
		/* sha256 */
		.type = OP_ALG(SHA256),
		.size_digest = TEE_SHA256_HASH_SIZE,
	},
	{
		/* sha384 */
		.type = OP_ALG(SHA384),
		.size_digest = TEE_SHA384_HASH_SIZE,
	},
	{
		/* sha512 */
		.type = OP_ALG(SHA512),
		.size_digest = TEE_SHA512_HASH_SIZE,
	},
	{
		/* sm3 */
		.type = OP_ALG(SM3),
		.size_digest = TEE_SM3_HASH_SIZE,
	},
};

static struct crypto_hash *to_hash_ctx(struct crypto_hash_ctx *ctx)
{
	assert(ctx && ctx->ops == &hash_ops);

	return container_of(ctx, struct crypto_hash, hash_ctx);
}

/* data: 4byte aligned */
static TEE_Result nuclei_hsm_calc_hash(void *data, uint32_t len,
			struct cmd_cfg_t cfg, void *digest, uint32_t digest_len)
{
	mailbox_hash_cmd_in_token hash_cmd = {0};
	int8_t mailbox_num;
	uint32_t timeout = 100;
	uint32_t rbuf[32] = {0};

	hash_cmd.hash.header.opcode = SECURE_SERVICE_OPCODE_HASH;
	hash_cmd.hash.input_data_addr_hig = virt_to_phys(data) >> 32;
	hash_cmd.hash.input_data_addr_low = virt_to_phys(data);
	hash_cmd.hash.input_data_length = len;
	hash_cmd.hash.length = len;
	hash_cmd.hash.cmd_cfg = cfg;
	/* For hsm side using @@ */
	hash_cmd.hash.key_data_addr_low =
		*(uint32_t *)(&hash_cmd.hash.cmd_cfg);
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
	cache_operation(TEE_CACHEFLUSH, data, len);
	mailbox_secure_service_host_send((uint32_t *)(&hash_cmd),
		SECURE_SERVICE_OPCODE_HASH, mailbox_num);
	mailbox_secure_service_host_receive(rbuf, mailbox_num);
	if (rbuf[0] & BIT(31)) {
		EMSG("hsm crypto err:%x\n",(rbuf[0] >> 24) & 0x1F);
		return TEE_ERROR_GENERIC;
	}
	if (digest) {
		for (int i=0; digest_len > 0; i++) {
			((uint32_t*)digest)[i] = TEE_U32_BSWAP(rbuf[2+i]);
			digest_len -= 4;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result do_hash_init(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	memset(&hash->ctx->cmd_desc, 0, sizeof(mailbox_hash_cmd_in_token));
	hash->ctx->cmd_desc.hash.header.opcode = SECURE_SERVICE_OPCODE_HASH;
	hash->ctx->cmd_desc.hash.cmd_cfg.algo = hash->ctx->alg->type;
	hash->ctx->cmd_desc.hash.cmd_cfg.mode = SECURE_SERVICE_HASH_MODE;
	hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = 0xF;
	hash->ctx->free_len = CACHED_DATA_LEN;

	return TEE_SUCCESS;
}

static TEE_Result do_hash_update(struct crypto_hash_ctx *ctx,
				 const uint8_t *data, size_t len)
{
	TEE_Result ret;

	struct crypto_hash *hash = to_hash_ctx(ctx);
	/*
	 * if len <= free_len, cache data to data_buf,
	 * else if len > free_len
	 *    if free_len < CACHED_DATA_LEN
	 *        send cached data to HSM, set free_len to CACHED_DATA_LEN
	 *        if len < CACHED_DATA_LEN, means can cache data to data_buf,wait next time to send
     *        else direct send data to HSM
     *    else
     *        direct send data to HSM
	 */
	if (hash->ctx->free_len >= len) {
		memcpy(&hash->ctx->data_buf[CACHED_DATA_LEN - hash->ctx->free_len],
			data, len);
		hash->ctx->free_len -= len;
		return TEE_SUCCESS;
	} else {
	    if (hash->ctx->free_len < CACHED_DATA_LEN) {
		    /* First send cached data to HSM */
			if (hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl == 0xF)
				hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_INIT;
			else if (hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl == SECURE_SERVICE_IN_INIT)
				hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_UPDATE;

			ret = nuclei_hsm_calc_hash(hash->ctx->data_buf,
					CACHED_DATA_LEN - hash->ctx->free_len,
					hash->ctx->cmd_desc.hash.cmd_cfg, NULL, 0);
			if (ret != TEE_SUCCESS)
				return ret;
			hash->ctx->free_len = CACHED_DATA_LEN;
			/* check if cache data */
			if (len < CACHED_DATA_LEN) {
				memcpy(&hash->ctx->data_buf[CACHED_DATA_LEN - hash->ctx->free_len], data, len);
				hash->ctx->free_len -= len;
				return TEE_SUCCESS;
			}
		}
		if (hash->ctx->free_len == CACHED_DATA_LEN) {
			if (hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl == 0xF)
				hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_INIT;
			else if (hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl == SECURE_SERVICE_IN_INIT)
				hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_UPDATE;

			ret = nuclei_hsm_calc_hash((void*)data, len, hash->ctx->cmd_desc.hash.cmd_cfg, NULL, 0);
		}
	}

	return ret;
}

static TEE_Result do_hash_final(struct crypto_hash_ctx *ctx, uint8_t *digest,
				size_t len)
{
	TEE_Result ret;
	struct crypto_hash *hash = to_hash_ctx(ctx);

	if (hash->ctx->free_len < CACHED_DATA_LEN) {
		if (hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl == 0xF)
			hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_ALL;
		else
			hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_END;
		ret = nuclei_hsm_calc_hash(hash->ctx->data_buf, CACHED_DATA_LEN - hash->ctx->free_len,
			hash->ctx->cmd_desc.hash.cmd_cfg, digest, len);
	} else {
		hash->ctx->cmd_desc.hash.cmd_cfg.in_ctrl = SECURE_SERVICE_IN_END;
		ret = nuclei_hsm_calc_hash(NULL, 0, hash->ctx->cmd_desc.hash.cmd_cfg, digest, len);
	}

	return ret;
}

static void do_hash_free(struct crypto_hash_ctx *ctx)
{
	struct crypto_hash *hash = to_hash_ctx(ctx);

	if (hash->ctx) {
		free(hash->ctx);
	}

	free(hash);
}

static void do_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
			       struct crypto_hash_ctx *src_ctx)
{
	struct crypto_hash *hash_src = to_hash_ctx(src_ctx);
	struct crypto_hash *hash_dst = to_hash_ctx(dst_ctx);

	(void)hash_src;
	(void)hash_dst;
}

/*
 * Registration of the hash Driver
 */
static const struct crypto_hash_ops hash_ops = {
	.init = do_hash_init,
	.update = do_hash_update,
	.final = do_hash_final,
	.free_ctx = do_hash_free,
	.copy_state = do_hash_copy_state,
};

static const struct hashalg *nuclei_hash_get_alg(uint32_t algo)
{
	uint8_t hash_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int idx = hash_id - TEE_MAIN_ALGO_MD5;

	if (idx > ARRAY_SIZE(hash_alg))
		return NULL;

	return &hash_alg[idx];
}

/*
 * Allocate the internal hashing data context
 *
 * @ctx    [out] Caller context variable
 * @algo   Algorithm ID
 */
static TEE_Result nuclei_hash_allocate(struct crypto_hash_ctx **ctx,
				     uint32_t algo)
{
	struct crypto_hash *hash = NULL;
	struct hashctx *hash_ctx = NULL;
	const struct hashalg *alg = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

	DMSG("Allocate Context (%p) algo %" PRId32, ctx, algo);

	*ctx = NULL;

	alg = nuclei_hash_get_alg(algo);
	if (!alg)
		return TEE_ERROR_NOT_IMPLEMENTED;

	hash = malloc(sizeof(*hash));
	if (!hash)
		return TEE_ERROR_OUT_OF_MEMORY;

	hash_ctx = memalign(4, sizeof(*hash_ctx));
	if (!hash_ctx) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	memset(hash_ctx, 0, sizeof(*hash_ctx));
	hash_ctx->alg = alg;
	hash->hash_ctx.ops = &hash_ops;
	hash->ctx = hash_ctx;

	*ctx = &hash->hash_ctx;

	DMSG("Allocated Context (%p)", hash_ctx);

	return TEE_SUCCESS;

err:
	free(hash);

	if (hash_ctx)
		free(hash_ctx);

	return ret;
}

TEE_Result nuclei_register_hash(void)
{
	return drvcrypt_register_hash(&nuclei_hash_allocate);
}

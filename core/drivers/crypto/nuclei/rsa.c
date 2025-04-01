// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Nuclei - All Rights Reserved
 */

#include <assert.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <drvcrypt_math.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <string.h>
#include <utee_defines.h>
#include "common.h"
#include "nuclei_hsm_abi.h"
#include "mailbox.h"
/*
 * Definition of the maximum bits of Exponent e
 * Refer to sp800-56b
 */
#define MAX_BITS_EXP_E 256

static void do_free_keypair(struct rsa_keypair *s);

/*
 * rsa private key to decryt
 * m=c^d mod n
 */
static TEE_Result decrypt_nopad(struct drvcrypt_rsa_ed *rsa_data)
{
	int8_t mailbox_num;
	uint32_t rbuf[32] = {0};
	uint32_t timeout = 100;
	acryp_in_token_t acryp_in_token = {0};
	struct rsa_keypair *priv_key;
	uint32_t n_len,d_len;
	uint8_t *n_buf,*d_buf, *cipher_buf;

	assert(rsa_data.key.isprivate == true);

	priv_key = (struct rsa_keypair*)rsa_data->key.key;
	n_len = crypto_bignum_num_bytes(priv_key->n);
	n_buf = malloc(n_len);
	if (n_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	memset(n_buf, 0, n_len);
	crypto_bignum_bn2bin(priv_key->n, n_buf);

	/* make D buffer len is same as n_len*/
	d_buf = malloc(n_len);
	if (d_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	memset(d_buf, 0, n_len);
	/* calc D real length */
	d_len = crypto_bignum_num_bytes(priv_key->d);
	crypto_bignum_bn2bin(priv_key->d, d_buf + n_len - d_len);
	/*
	 * rsa hsm crypt will write result data to input_signdata_addr_low,
	 * so,here malloc buffer to hold message data
	 */
	cipher_buf = malloc(rsa_data->cipher.length);
	if (cipher_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(cipher_buf, rsa_data->cipher.data, rsa_data->cipher.length);

	cache_operation(TEE_CACHEFLUSH, cipher_buf, n_len);
	cache_operation(TEE_CACHEFLUSH, n_buf, n_len);
	cache_operation(TEE_CACHEFLUSH, d_buf, n_len);
	acryp_in_token.input_data_addr_low = virt_to_phys(d_buf);
	acryp_in_token.input_data_addr_hig = virt_to_phys(d_buf) >> 32;
	acryp_in_token.length = n_len/4;
	acryp_in_token.input_data_length = n_len/4;
	acryp_in_token.input_signdata_addr_low = virt_to_phys(cipher_buf);
	acryp_in_token.input_signdata_addr_hig = virt_to_phys(cipher_buf) >> 32;
	acryp_in_token.input_key_addr_low = virt_to_phys(n_buf);
	acryp_in_token.input_key_addr_hig = virt_to_phys(n_buf) >> 32;

	acryp_in_token.header.opcode = SECURE_SERVICE_OPCODE_ACRYP;
	acryp_in_token.cmd_cfg.algo = SECURE_SERVICE_ACRYP_MOD_EXP;
	acryp_in_token.cmd_cfg.mode = SECURE_SERVICE_ACRYP_MOD_EXP_SPECIFY;
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
	mailbox_secure_service_host_send((uint32_t *)(&acryp_in_token), SECURE_SERVICE_OPCODE_ACRYP, mailbox_num);
	mailbox_secure_service_host_receive(rbuf, mailbox_num);
	if (rbuf[0] & BIT(31)) {
		EMSG("hsm crypto err:%x\n",(rbuf[0] >> 24) & 0x1F);
		return TEE_ERROR_GENERIC;
	}
	cache_operation(TEE_CACHEINVALIDATE, cipher_buf, n_len);
	memcpy(rsa_data->message.data, cipher_buf, n_len);
	rsa_data->message.length = n_len;
	free(n_buf);
	free(d_buf);
	free(cipher_buf);

	return TEE_SUCCESS;
}

/*
 * rsa public key to encryt
 * cipher data = message ^ E mod N
 */
static TEE_Result encrypt_nopad(struct drvcrypt_rsa_ed *rsa_data)
{
	int8_t mailbox_num;
	uint32_t rbuf[32] = {0};
	uint32_t timeout = 100;
	acryp_in_token_t acryp_in_token = {0};
	struct rsa_public_key *pub_key;
	uint32_t n_len,e_len;
	uint8_t *n_buf, *e_buf, *msg_buf;

	assert(rsa_data.key.isprivate == false);

	pub_key = (struct rsa_public_key*)rsa_data->key.key;
	n_len = crypto_bignum_num_bytes(pub_key->n);
	n_buf = malloc(n_len);
	if (n_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	memset(n_buf, 0, n_len);
	crypto_bignum_bn2bin(pub_key->n, n_buf);

	/* make E buffer len is same as n_len*/
	e_buf = malloc(n_len);
	if (e_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	memset(e_buf, 0, n_len);
	/* calc E real length */
	e_len = crypto_bignum_num_bytes(pub_key->e);
	crypto_bignum_bn2bin(pub_key->e, e_buf + n_len - e_len);
	/*
	 * rsa hsm crypt will write result data to input_signdata_addr_low,
	 * so,here malloc buffer to hold message data
	 */
	msg_buf = malloc(rsa_data->message.length);
	if (msg_buf == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(msg_buf, rsa_data->message.data, rsa_data->message.length);

	cache_operation(TEE_CACHEFLUSH, msg_buf, n_len);
	cache_operation(TEE_CACHEFLUSH, n_buf, n_len);
	cache_operation(TEE_CACHEFLUSH, e_buf, n_len);
	acryp_in_token.input_data_addr_low = virt_to_phys(e_buf);
	acryp_in_token.input_data_addr_hig = virt_to_phys(e_buf) >> 32;
	acryp_in_token.length = n_len/4;
	acryp_in_token.input_data_length = n_len/4;
	acryp_in_token.input_signdata_addr_low = virt_to_phys(msg_buf);
	acryp_in_token.input_signdata_addr_hig = virt_to_phys(msg_buf) >> 32;
	acryp_in_token.input_key_addr_low = virt_to_phys(n_buf);
	acryp_in_token.input_key_addr_hig = virt_to_phys(n_buf) >> 32;

	acryp_in_token.header.opcode = SECURE_SERVICE_OPCODE_ACRYP;
	acryp_in_token.cmd_cfg.algo = SECURE_SERVICE_ACRYP_MOD_EXP;
	acryp_in_token.cmd_cfg.mode = SECURE_SERVICE_ACRYP_MOD_EXP_SPECIFY;
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
	mailbox_secure_service_host_send((uint32_t *)(&acryp_in_token), SECURE_SERVICE_OPCODE_ACRYP, mailbox_num);
	mailbox_secure_service_host_receive(rbuf, mailbox_num);
	if (rbuf[0] & BIT(31)) {
		EMSG("hsm crypto err:%x\n",(rbuf[0] >> 24) & 0x1F);
		return TEE_ERROR_GENERIC;
	}
	cache_operation(TEE_CACHEINVALIDATE, msg_buf, n_len);
	memcpy(rsa_data->cipher.data, msg_buf, n_len);
	rsa_data->cipher.length = n_len;
	free(n_buf);
	free(e_buf);
	free(msg_buf);

	return TEE_SUCCESS;
}

static TEE_Result do_alloc_keypair(struct rsa_keypair *key,
				   size_t size_bits)
{
	/* Initialize all input key fields to 0 */
	memset(key, 0, sizeof(*key));

	/* Allocate the Public Exponent to maximum size */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_keypair;

	/* Allocate the Private Exponent [d = 1/e mod LCM(p-1, q-1)] */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err_alloc_keypair;

	/* Allocate the Modulus (size_bits) [n = p * q] */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_keypair;

	/* Allocate the prime number p of size (size_bits / 2) */
	key->p = crypto_bignum_allocate(size_bits / 2);
	if (!key->p)
		goto err_alloc_keypair;

	/* Allocate the prime number q of size (size_bits / 2) */
	key->q = crypto_bignum_allocate(size_bits / 2);
	if (!key->q)
		goto err_alloc_keypair;

	/* Allocate dp (size_bits / 2) [d mod (p-1)] */
	key->dp = crypto_bignum_allocate(size_bits / 2);
	if (!key->dp)
		goto err_alloc_keypair;

	/* Allocate dq (size_bits / 2) [d mod (q-1)] */
	key->dq = crypto_bignum_allocate(size_bits / 2);
	if (!key->dq)
		goto err_alloc_keypair;

	/* Allocate qp (size_bits / 2) [1/q mod p] */
	key->qp = crypto_bignum_allocate(size_bits / 2);
	if (!key->qp)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	do_free_keypair(key);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result do_alloc_publickey(struct rsa_public_key *key,
				     size_t size_bits)
{
	memset(key, 0, sizeof(*key));

	/* Allocate the Public Exponent to maximum size */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_publickey;

	/* Allocate the Modulus (size_bits) [n = p * q] */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_publickey;

	return TEE_SUCCESS;

err_alloc_publickey:
	crypto_bignum_free(key->e);
	crypto_bignum_free(key->n);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static void do_free_publickey(struct rsa_public_key *key)
{
	if (key) {
		crypto_bignum_free(key->n);
		crypto_bignum_free(key->e);
	}
}

static void do_free_keypair(struct rsa_keypair *key)
{
	if (key) {
		crypto_bignum_free(key->e);
		crypto_bignum_free(key->d);
		crypto_bignum_free(key->n);
		crypto_bignum_free(key->p);
		crypto_bignum_free(key->q);
		crypto_bignum_free(key->qp);
		crypto_bignum_free(key->dp);
		crypto_bignum_free(key->dq);
	}
}

static TEE_Result do_gen_keypair(struct rsa_keypair *key, size_t kb)
{
	(void)key;
	(void)kb;

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSASSA_PSS:
		return encrypt_nopad(rsa_data);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result do_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSASSA_PSS:
		return decrypt_nopad(rsa_data);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static const struct drvcrypt_rsa driver_rsa = {
	.alloc_keypair = do_alloc_keypair,
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.free_keypair = do_free_keypair,
	.gen_keypair = do_gen_keypair,
	.encrypt = do_encrypt,
	.decrypt = do_decrypt,
	.optional.ssa_sign = NULL,
	.optional.ssa_verify = NULL,
};

TEE_Result nuclei_register_rsa(void)
{
	return drvcrypt_register_rsa(&driver_rsa);
}

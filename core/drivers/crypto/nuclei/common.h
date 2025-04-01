/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Nuclei - All Rights Reserved
 */

#ifndef __DRIVERS_CRYPTO_NUCLEI_HSM_COMMON_H
#define __DRIVERS_CRYPTO_NUCLEI_HSM_COMMON_H

#include <tee_api_types.h>

TEE_Result nuclei_register_cipher(void);
TEE_Result nuclei_register_hash(void);
TEE_Result nuclei_register_hmac(void);
TEE_Result nuclei_register_rsa(void);

#endif /* __DRIVERS_CRYPTO_NUCLEI_HSM_COMMON_H */

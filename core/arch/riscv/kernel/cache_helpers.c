/*
 * Copyright (c) 2017, Linaro Limited. All rights reserved.
 * Copyright (c) 2024, Nuclei Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <kernel/cache_helpers.h>
#include <util.h>

#define CACHE_LINE_SHIFT                6
#define CACHE_LINE_SIZE                 (1 << CACHE_LINE_SHIFT)
#define CACHE_LINE_MASK                 (~((1 << CACHE_LINE_SHIFT) - 1))

#define CSR_MCACHE_ICACHE_EN            BIT(0)
#define CSR_MCACHE_ICACHE_PF_EN         BIT(6)
#define CSR_MCACHE_ICACHE_CANCLE_EN     BIT(7)
#define CSR_MCACHE_DCACHE_EN            BIT(16)

#define CSR_CCM_SBEGINADDR              0x5CB
#define CSR_CCM_SCOMMAND                0x5CC

typedef enum CCM_CMD {
    CCM_DC_INVAL = 0x0,                 /*!< Unlock and invalidate D-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_DC_WB = 0x1,                    /*!< Flush the specific D-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_DC_WBINVAL = 0x2,               /*!< Unlock, flush and invalidate the specific D-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_DC_LOCK = 0x3,                  /*!< Lock the specific D-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_DC_UNLOCK = 0x4,                /*!< Unlock the specific D-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_DC_WBINVAL_ALL = 0x6,           /*!< Unlock and flush and invalidate all the valid and dirty D-Cache lines */
    CCM_DC_WB_ALL = 0x7,                /*!< Flush all the valid and dirty D-Cache lines */
    CCM_DC_INVAL_ALL = 0x17,            /*!< Unlock and invalidate all the D-Cache lines */
    CCM_IC_INVAL = 0x8,                 /*!< Unlock and invalidate I-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_IC_LOCK = 0xb,                  /*!< Lock the specific I-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_IC_UNLOCK = 0xc,                /*!< Unlock the specific I-Cache line specified by CSR CCM_XBEGINADDR */
    CCM_IC_INVAL_ALL = 0xd              /*!< Unlock and invalidate all the I-Cache lines */
} CCM_CMD_Type;


static void ccm_cache_ops(size_t start_addr, size_t end_addr, CCM_CMD_Type type)
{
	size_t cache_aligned;

	cache_aligned = start_addr & CACHE_LINE_MASK;
	write_csr(CSR_CCM_SBEGINADDR, cache_aligned);
	for (; cache_aligned < end_addr; cache_aligned += CACHE_LINE_SIZE) {
		write_csr(CSR_CCM_SCOMMAND, type);
	}
}

void dcache_cleaninv_range(void *addr, size_t size)
{
	ccm_cache_ops((size_t)addr, (size_t)addr + size, CCM_DC_WBINVAL);
}

void dcache_clean_range(void *addr, size_t size)
{
	ccm_cache_ops((size_t)addr, (size_t)addr + size, CCM_DC_WB);
}

void dcache_inv_range(void *addr, size_t size)
{
	ccm_cache_ops((size_t)addr, (size_t)addr + size, CCM_DC_INVAL);
}

void icache_inv_all(void)
{
	write_csr(CSR_CCM_SCOMMAND, CCM_IC_INVAL_ALL);
	/* maybe need to operate L2 */
}

void icache_inv_range(void *addr, size_t size)
{
	ccm_cache_ops((size_t)addr, (size_t)addr + size, CCM_IC_INVAL);
}

void dcache_op_all(unsigned long op_type)
{
	if (DCACHE_OP_INV == op_type) {
		write_csr(CSR_CCM_SCOMMAND, CCM_DC_INVAL_ALL);
	} else if (DCACHE_OP_CLEAN_INV == op_type) {
		write_csr(CSR_CCM_SCOMMAND, CCM_DC_WBINVAL_ALL);
	} else if (DCACHE_OP_CLEAN == op_type) {
		write_csr(CSR_CCM_SCOMMAND, CCM_DC_WB_ALL);
	}
	/* maybe need to operate L2 */
}

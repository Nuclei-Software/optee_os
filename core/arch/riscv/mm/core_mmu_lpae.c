// SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause)
/*
 * Copyright (c) 2015-2016, 2022 Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2014, 2022, ARM Limited and Contributors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <platform_config.h>

#include <riscv.h>
#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <inttypes.h>
#include <keep.h>
#include <kernel/cache_helpers.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/tlb_helpers.h>
#include <mm/pgt_cache.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>
#include <kernel/spinlock.h>
#include <bitstring.h>

#ifndef DEBUG_XLAT_TABLE
#define DEBUG_XLAT_TABLE 0
#endif

#if DEBUG_XLAT_TABLE
#define debug_print(...) DMSG_RAW(__VA_ARGS__)
#else
#define debug_print(...) ((void)0)
#endif


/*
 * Miscellaneous MMU related constants
 */

#define INVALID_DESC		0x0
#define VALID_DESC			0x1
#define BLOCK_DESC			0x1
#define L3_BLOCK_DESC		0x3
#define TABLE_DESC			0x0
#define DESC_ENTRY_TYPE_MASK	0x7

#define DESC_IS_VALID(desc) ((desc) & 0x1)
#define DESC_IS_TABLE(desc)	\
	(DESC_IS_VALID(desc)  && \
	(((desc >> 0x1) & 0x7) == 0))

#define PTE_PPN(x) ((x) >> 10)

#define OUTPUT_ADDRESS_MASK	(0x0000FFFFFFFFFC00ULL)

#define UNSET_DESC		((uint64_t)-1)

#define FOUR_KB_SHIFT		12
#define PAGE_SIZE_SHIFT		FOUR_KB_SHIFT
#define PAGE_SIZE		(1 << PAGE_SIZE_SHIFT)
#define PAGE_SIZE_MASK		(PAGE_SIZE - 1)
#define IS_PAGE_ALIGNED(addr)	(((addr) & PAGE_SIZE_MASK) == 0)

#define XLAT_ENTRY_SIZE_SHIFT	3 /* Each MMU table entry is 8 bytes (1 << 3) */
#define XLAT_ENTRY_SIZE		(1 << XLAT_ENTRY_SIZE_SHIFT)

#define XLAT_TABLE_SIZE_SHIFT	PAGE_SIZE_SHIFT
#define XLAT_TABLE_SIZE		(1 << XLAT_TABLE_SIZE_SHIFT)

#define XLAT_TABLE_LEVEL_MAX	U(3)

/* Values for number of entries in each MMU translation table */
#define XLAT_TABLE_ENTRIES_SHIFT (XLAT_TABLE_SIZE_SHIFT - XLAT_ENTRY_SIZE_SHIFT)
#define XLAT_TABLE_ENTRIES	(1 << XLAT_TABLE_ENTRIES_SHIFT)
#define XLAT_TABLE_ENTRIES_MASK	(XLAT_TABLE_ENTRIES - 1)

/* Values to convert a memory address to an index into a translation table */
#define L3_XLAT_ADDRESS_SHIFT	PAGE_SIZE_SHIFT
#define L2_XLAT_ADDRESS_SHIFT	(L3_XLAT_ADDRESS_SHIFT + \
				 XLAT_TABLE_ENTRIES_SHIFT)
#define L1_XLAT_ADDRESS_SHIFT	(L2_XLAT_ADDRESS_SHIFT + \
				 XLAT_TABLE_ENTRIES_SHIFT)
#define L0_XLAT_ADDRESS_SHIFT	(L1_XLAT_ADDRESS_SHIFT + \
				 XLAT_TABLE_ENTRIES_SHIFT)
#define XLAT_ADDR_SHIFT(level)	(PAGE_SIZE_SHIFT + \
				 ((XLAT_TABLE_LEVEL_MAX - (level)) * \
				 XLAT_TABLE_ENTRIES_SHIFT))

#define XLAT_BLOCK_SIZE(level)	(UL(1) << XLAT_ADDR_SHIFT(level))

/* Base table */
#define BASE_XLAT_ADDRESS_SHIFT	XLAT_ADDR_SHIFT(CORE_MMU_BASE_TABLE_LEVEL)
#define BASE_XLAT_BLOCK_SIZE	XLAT_BLOCK_SIZE(CORE_MMU_BASE_TABLE_LEVEL)
#define BASE_XLAT_ENTTIES_SIZE

#define NUM_BASE_LEVEL_ENTRIES	\
	BIT(CFG_LPAE_ADDR_SPACE_BITS - BASE_XLAT_ADDRESS_SHIFT)
#define NUM_BASE_LEVEL_ENTRIES_MASK (NUM_BASE_LEVEL_ENTRIES - 1)
/*
 * MMU L1 table, one for each core
 *
 * With CFG_CORE_UNMAP_CORE_AT_EL0, each core has one table to be used
 * while in kernel mode and one to be used while in user mode.
 */
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
#define NUM_BASE_TABLES	2
#else
#define NUM_BASE_TABLES	1
#endif

#ifndef MAX_XLAT_TABLES
#ifdef CFG_VIRTUALIZATION
#	define XLAT_TABLE_VIRTUALIZATION_EXTRA 3
#else
#	define XLAT_TABLE_VIRTUALIZATION_EXTRA 0
#endif
#ifdef CFG_CORE_ASLR
#	define XLAT_TABLE_ASLR_EXTRA 3
#else
#	define XLAT_TABLE_ASLR_EXTRA 0
#endif
#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
#	define XLAT_TABLE_TEE_EXTRA 8
#	define XLAT_TABLE_USER_EXTRA (NUM_BASE_TABLES * CFG_TEE_CORE_NB_CORE)
#else
#	define XLAT_TABLE_TEE_EXTRA 5
#	define XLAT_TABLE_USER_EXTRA 0
#endif
#define MAX_XLAT_TABLES		(XLAT_TABLE_TEE_EXTRA + \
				 XLAT_TABLE_VIRTUALIZATION_EXTRA + \
				 XLAT_TABLE_ASLR_EXTRA + \
				 XLAT_TABLE_USER_EXTRA)
#endif /*!MAX_XLAT_TABLES*/

typedef uint64_t base_xlat_tbls_t[CFG_TEE_CORE_NB_CORE][NUM_BASE_LEVEL_ENTRIES];
typedef uint64_t xlat_tbl_t[XLAT_TABLE_ENTRIES];

static base_xlat_tbls_t base_xlation_table[NUM_BASE_TABLES]
	__aligned(NUM_BASE_LEVEL_ENTRIES * XLAT_ENTRY_SIZE)
	__section(".nozi.mmu.base_table");

static xlat_tbl_t xlat_tables[MAX_XLAT_TABLES]
	__aligned(XLAT_TABLE_SIZE) __section(".nozi.mmu.l2");

#define XLAT_TABLES_SIZE	(sizeof(xlat_tbl_t) * MAX_XLAT_TABLES)

/* MMU L2 table for TAs, one for each thread */
static xlat_tbl_t xlat_tables_ul1[CFG_NUM_THREADS]
	__aligned(XLAT_TABLE_SIZE) __section(".nozi.mmu.l2");

/*
 * TAs page table entry inside a level 1 page table.
 *
 * TAs mapping is expected to start from level 2.
 *
 * If base level is 1 then this is the index of a level 1 entry,
 * that will point directly into TA mapping table.
 *
 * If base level is 0 then entry 0 in base table is always used, and then
 * we fallback to "base level == 1" like scenario.
 */
static int user_va_idx __nex_data = -1;

struct mmu_partition {
	base_xlat_tbls_t *base_tables;
	xlat_tbl_t *xlat_tables;
	xlat_tbl_t *l2_ta_tables;
	unsigned int xlat_tables_used;
	unsigned int asid;
};

static struct mmu_partition default_partition __nex_data = {
	.base_tables = base_xlation_table,
	.xlat_tables = xlat_tables,
	.l2_ta_tables = xlat_tables_ul1,
	.xlat_tables_used = 0,
	.asid = 0
};

static struct mmu_partition *get_prtn(void)
{
	return &default_partition;
}

static uint32_t desc_to_mattr(unsigned level, uint64_t desc)
{
    unsigned long mattr = TEE_MATTR_SECURE;
	
	if (!(desc & 1))
		return 0;

	if (level == XLAT_TABLE_LEVEL_MAX) {
		/*this level should be block memory area, else return invalid*/
		if (DESC_IS_TABLE(desc))
			return 0;
		
		mattr |= TEE_MATTR_VALID_BLOCK;
		if (desc & PTE_U) {
			if (desc & PTE_R)
				mattr |= TEE_MATTR_UR;
			if (desc & PTE_W)
				mattr |= TEE_MATTR_UW;
			if (desc & PTE_X)
				mattr |= TEE_MATTR_UX;
		} else {
			if (desc & PTE_R)
				mattr |= TEE_MATTR_PR;
			if (desc & PTE_W)
				mattr |= TEE_MATTR_PW;
			if (desc & PTE_X)
				mattr |= TEE_MATTR_PX;
		}

		if (desc & PTE_G)
			mattr |= TEE_MATTR_GLOBAL;
	} else {
		if (DESC_IS_TABLE(desc))
			mattr |= TEE_MATTR_TABLE;
	}

	return mattr;
}

static uint64_t mattr_to_desc(unsigned level __unused, uint32_t attr)
{
	uint64_t desc = 0;

	if (attr & TEE_MATTR_TABLE)
		return PTE_V;

	if (attr & TEE_MATTR_VALID_BLOCK)
		desc |= PTE_V;

	if (attr & TEE_MATTR_UR)
		desc |= (PTE_R | PTE_U);
	if (attr & TEE_MATTR_UW)
		desc |= (PTE_W | PTE_U);
	if (attr & TEE_MATTR_UX)
		desc |= (PTE_X | PTE_U);

	if (attr & TEE_MATTR_PR)
		desc |= PTE_R;
	if (attr & TEE_MATTR_PW)
		desc |= PTE_W;
	if (attr & TEE_MATTR_PX)
		desc |= PTE_X;

	if (attr & TEE_MATTR_GLOBAL)
		desc |= PTE_G;

	return desc;
}

static uint64_t *core_mmu_xlat_table_alloc(struct mmu_partition *prtn)
{
	uint64_t *new_table = NULL;

	if (prtn->xlat_tables_used >= MAX_XLAT_TABLES) {
		EMSG("%u xlat tables exhausted", MAX_XLAT_TABLES);

		return NULL;
	}

	new_table = prtn->xlat_tables[prtn->xlat_tables_used++];

	DMSG("xlat tables used %u / %u",
	     prtn->xlat_tables_used, MAX_XLAT_TABLES);

	return new_table;
}

/*
 * Given an entry that points to a table returns the virtual address
 * of the pointed table. NULL otherwise.
 */
static void *core_mmu_xlat_table_entry_pa2va(struct mmu_partition *prtn __unused,
					     unsigned int level,
					     uint64_t entry)
{
	paddr_t pa = 0;
	void *va = NULL;

	if (! DESC_IS_TABLE(entry) ||
	    level >= XLAT_TABLE_LEVEL_MAX)
		return NULL;

	pa = entry >> 10 << 12;
	va = phys_to_virt(pa, MEM_AREA_TEE_RAM_RW_DATA, XLAT_TABLE_SIZE);

	return va;
}

/*
 * For a table entry that points to a table - allocate and copy to
 * a new pointed table. This is done for the requested entry,
 * without going deeper into the pointed table entries.
 *
 * A success is returned for non-table entries, as nothing to do there.
 */
__maybe_unused
static bool core_mmu_entry_copy(struct core_mmu_table_info *tbl_info,
				unsigned int idx)
{
	uint64_t *orig_table = NULL;
	uint64_t *new_table = NULL;
	uint64_t *entry = NULL;
	struct mmu_partition *prtn = NULL;

	prtn = &default_partition;
	assert(prtn);

	if (idx >= tbl_info->num_entries)
		return false;

	entry = (uint64_t *)tbl_info->table + idx;

	/* Nothing to do for non-table entries */
	if (! DESC_IS_TABLE(*entry) ||
	    tbl_info->level >= XLAT_TABLE_LEVEL_MAX)
		return true;

	new_table = core_mmu_xlat_table_alloc(prtn);
	if (!new_table)
		return false;

	orig_table = core_mmu_xlat_table_entry_pa2va(prtn, tbl_info->level,
						     *entry);
	if (!orig_table)
		return false;

	/* Copy original table content to new table */
	memcpy(new_table, orig_table, XLAT_TABLE_ENTRIES * XLAT_ENTRY_SIZE);

	/* Point to the new table */
	*entry = virt_to_phys(new_table) >> 12 << 10 | PTE_V;

	return true;
}

static void core_init_mmu_prtn_tee(struct mmu_partition *prtn,
				   struct tee_mmap_region *mm)
{
	size_t n;

	assert(prtn && mm);

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++) {
		debug_print(" %010" PRIxVA " %010" PRIxPA " %10zx %x",
			    mm[n].va, mm[n].pa, mm[n].size, mm[n].attr);

		if (!IS_PAGE_ALIGNED(mm[n].pa) || !IS_PAGE_ALIGNED(mm[n].size))
			panic("unaligned region");
	}

	/* Clear table before use */
	memset(prtn->base_tables, 0, sizeof(base_xlation_table));

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++)
		if (!core_mmu_is_dynamic_vaspace(mm + n))
			core_mmu_map_region(prtn, mm + n);

	/*
	 * Primary mapping table is ready at index `get_core_pos()`
	 * whose value may not be ZERO. Take this index as copy source.
	 */
	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		if (n == get_core_pos())
			continue;

		memcpy(prtn->base_tables[0][n],
		       prtn->base_tables[0][get_core_pos()],
		       XLAT_ENTRY_SIZE * NUM_BASE_LEVEL_ENTRIES);
	}
}

/*
 * In order to support 32-bit TAs we will have to find
 * a user VA base in the region [1GB, 4GB[.
 * Due to OP-TEE design limitation, TAs page table should be an entry
 * inside a level 1 page table.
 *
 * Available options are only these:
 * - base level 0 entry 0 - [0GB, 512GB[
 *   - level 1 entry 0 - [0GB, 1GB[
 *   - level 1 entry 1 - [1GB, 2GB[           <----
 *   - level 1 entry 2 - [2GB, 3GB[           <----
 *   - level 1 entry 3 - [3GB, 4GB[           <----
 *   - level 1 entry 4 - [4GB, 5GB[
 *   - ...
 * - ...
 *
 * - base level 1 entry 0 - [0GB, 1GB[
 * - base level 1 entry 1 - [1GB, 2GB[        <----
 * - base level 1 entry 2 - [2GB, 3GB[        <----
 * - base level 1 entry 3 - [3GB, 4GB[        <----
 * - base level 1 entry 4 - [4GB, 5GB[
 * - ...
 */
static void set_user_va_idx(struct mmu_partition *prtn)
{
	uint64_t *tbl = NULL;
	unsigned int n = 0;

	assert(prtn);

	tbl = prtn->base_tables[0][get_core_pos()];

	/*
	 * If base level is 0, then we must use its entry 0.
	 */
	

	/*
	 * Search level 1 table (i.e. 1GB mapping per entry) for
	 * an empty entry in the range [1GB, 4GB[.
	 */
	for (n = 1; n < 4; n++) {
		if ((tbl[n] & 1) == INVALID_DESC) {
			user_va_idx = n;
			break;
		}
	}

	assert(user_va_idx != -1);
}

/*
 * Setup an entry inside a core level 1 page table for TAs memory mapping
 *
 * If base table level is 1 - user_va_idx is already the index,
 *                            so nothing to do.
 * If base table level is 0 - we might need to allocate entry 0 of base table,
 *                            as TAs page table is an entry inside a level 1
 *                            page table.
 */
static void core_init_mmu_prtn_ta_core(struct mmu_partition *prtn
				       __maybe_unused,
				       unsigned int base_idx __maybe_unused,
				       unsigned int core __maybe_unused)
{
	//do nothing
}

static void core_init_mmu_prtn_ta(struct mmu_partition *prtn)
{
	unsigned int base_idx = 0;
	unsigned int core = 0;

	assert(user_va_idx != -1);

	for (base_idx = 0; base_idx < NUM_BASE_TABLES; base_idx++)
		for (core = 0; core < CFG_TEE_CORE_NB_CORE; core++)
			core_init_mmu_prtn_ta_core(prtn, base_idx, core);
}

void core_init_mmu(struct tee_mmap_region *mm)
{
	uint64_t max_va = 0;
	size_t n;

	COMPILE_TIME_ASSERT(CORE_MMU_BASE_TABLE_SHIFT ==
			    XLAT_ADDR_SHIFT(CORE_MMU_BASE_TABLE_LEVEL));
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	COMPILE_TIME_ASSERT(CORE_MMU_BASE_TABLE_OFFSET ==
			   sizeof(base_xlation_table) / 2);
#endif
	COMPILE_TIME_ASSERT(XLAT_TABLES_SIZE == sizeof(xlat_tables));

	/* Initialize default pagetables */
	core_init_mmu_prtn_tee(&default_partition, mm);

	for (n = 0; !core_mmap_is_end_of_table(mm + n); n++) {
		vaddr_t va_end = mm[n].va + mm[n].size - 1;

		if (va_end > max_va)
			max_va = va_end;
	}

	set_user_va_idx(&default_partition);

	core_init_mmu_prtn_ta(&default_partition);

	COMPILE_TIME_ASSERT(CFG_LPAE_ADDR_SPACE_BITS > L1_XLAT_ADDRESS_SHIFT);
	assert(max_va < BIT64(CFG_LPAE_ADDR_SPACE_BITS));
}

void core_init_mmu_regs(struct core_mmu_config *cfg)
{
	cfg->ttbr_base = virt_to_phys(base_xlation_table[0][0]);
	cfg->ttbr_core_offset = sizeof(base_xlation_table[0][0]);
}

void core_mmu_set_info_table(struct core_mmu_table_info *tbl_info,
		unsigned level, vaddr_t va_base, void *table)
{
	tbl_info->level = level;
	tbl_info->table = table;
	tbl_info->va_base = va_base;
	tbl_info->shift = XLAT_ADDR_SHIFT(level);

	assert(level >= CORE_MMU_BASE_TABLE_LEVEL);
	assert(level <= XLAT_TABLE_LEVEL_MAX);

	if (level == CORE_MMU_BASE_TABLE_LEVEL)
		tbl_info->num_entries = NUM_BASE_LEVEL_ENTRIES;
	else
		tbl_info->num_entries = XLAT_TABLE_ENTRIES;
}

void core_mmu_get_user_pgdir(struct core_mmu_table_info *pgd_info)
{
	vaddr_t va_range_base;
	void *tbl = get_prtn()->l2_ta_tables[thread_get_id()];

	core_mmu_get_user_va_range(&va_range_base, NULL);
	core_mmu_set_info_table(pgd_info, 2, va_range_base, tbl);
}

void core_mmu_create_user_map(struct user_mode_ctx *uctx,
			      struct core_mmu_user_map *map)
{
	struct core_mmu_table_info dir_info;

	COMPILE_TIME_ASSERT(sizeof(uint64_t) * XLAT_TABLE_ENTRIES == PGT_SIZE);

	core_mmu_get_user_pgdir(&dir_info);
	memset(dir_info.table, 0, PGT_SIZE);
	core_mmu_populate_user_map(&dir_info, uctx);
	map->user_map = virt_to_phys(dir_info.table) >> 12 << 10 | PTE_V;
	map->asid = uctx->vm_info.asid;
}

bool core_mmu_find_table(struct mmu_partition *prtn, vaddr_t va,
			 unsigned max_level,
			 struct core_mmu_table_info *tbl_info)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	unsigned int num_entries = NUM_BASE_LEVEL_ENTRIES;
	unsigned int level = CORE_MMU_BASE_TABLE_LEVEL;
	vaddr_t va_base = 0;
	bool ret = false;
	uint64_t *tbl;

	if (!prtn)
		prtn = get_prtn();
	tbl = prtn->base_tables[0][get_core_pos()];

	while (true) {
		unsigned int level_size_shift = XLAT_ADDR_SHIFT(level);
		unsigned int n = (va - va_base) >> level_size_shift;

		if (n >= num_entries)
			goto out;

		if (level == max_level || level == XLAT_TABLE_LEVEL_MAX ||
			! DESC_IS_TABLE(tbl[n])) {
			/*
			 * We've either reached max_level, a block
			 * mapping entry or an "invalid" mapping entry.
			 */

			/*
			 * Base level is the CPU specific translation table.
			 * It doesn't make sense to return anything based
			 * on that unless foreign interrupts already are
			 * masked.
			 */
			/*if (level == CORE_MMU_BASE_TABLE_LEVEL &&
			    !(exceptions & THREAD_EXCP_FOREIGN_INTR))
				goto out;*/

			tbl_info->table = tbl;
			tbl_info->va_base = va_base;
			tbl_info->level = level;
			tbl_info->shift = level_size_shift;
			tbl_info->num_entries = num_entries;
			ret = true;
			goto out;
		}

		tbl = core_mmu_xlat_table_entry_pa2va(prtn, level, tbl[n]);

		if (!tbl)
			goto out;

		va_base += (vaddr_t)n << level_size_shift;
		level++;
		num_entries = XLAT_TABLE_ENTRIES;
	}
out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

bool core_mmu_entry_to_finer_grained(struct core_mmu_table_info *tbl_info,
				     unsigned int idx, bool secure __unused)
{
	uint64_t *new_table;
	uint64_t *entry;
	int i;
	paddr_t pa;
	uint64_t attr;
	paddr_t block_size_on_next_lvl = XLAT_BLOCK_SIZE(tbl_info->level + 1);
	struct mmu_partition *prtn;

	prtn = &default_partition;
	assert(prtn);

	if (tbl_info->level >= XLAT_TABLE_LEVEL_MAX ||
	    idx >= tbl_info->num_entries)
		return false;

	entry = (uint64_t *)tbl_info->table + idx;

	if (DESC_IS_TABLE(*entry))
		return true;

	new_table = core_mmu_xlat_table_alloc(prtn);
	if (!new_table)
		return false;

	if (*entry) {
		pa = *entry & OUTPUT_ADDRESS_MASK;
		attr = *entry & ~OUTPUT_ADDRESS_MASK;
		for (i = 0; i < XLAT_TABLE_ENTRIES; i++) {
			new_table[i] = (pa >> 12 << 10) | attr ;
			pa += block_size_on_next_lvl;
		}
	} else {
		memset(new_table, 0, XLAT_TABLE_ENTRIES * XLAT_ENTRY_SIZE);
	}
	/* set desc to table type,R/W/X are all zero*/
	*entry = (virt_to_phys(new_table) >> 12 << 10) | PTE_V;

	return true;
}

void core_mmu_set_entry_primitive(void *table, size_t level, size_t idx,
				  paddr_t pa, uint32_t attr)
{
	uint64_t *tbl = table;
	uint64_t desc = mattr_to_desc(level, attr);

	tbl[idx] = desc | (pa >> 12 << 10);
	if (!DESC_IS_TABLE(desc))
		tbl[idx] |= PTE_A | PTE_D;
}

void core_mmu_get_entry_primitive(const void *table, size_t level,
				  size_t idx, paddr_t *pa, uint32_t *attr)
{
	const uint64_t *tbl = table;

	if (pa)
		*pa = tbl[idx] >> 10 << 12;

	if (attr)
		*attr = desc_to_mattr(level, tbl[idx]);
}

bool core_mmu_user_va_range_is_defined(void)
{
	return user_va_idx != -1;
}

void core_mmu_get_user_va_range(vaddr_t *base, size_t *size)
{
	assert(user_va_idx != -1);

	if (base)
		*base = (vaddr_t)user_va_idx << L1_XLAT_ADDRESS_SHIFT;
	if (size)
		*size = BIT64(L1_XLAT_ADDRESS_SHIFT);
}

static uint64_t *core_mmu_get_user_mapping_entry(struct mmu_partition *prtn,
						 unsigned int base_idx)
{
	assert(user_va_idx != -1);

	return &prtn->base_tables[base_idx][get_core_pos()][user_va_idx];
}

bool core_mmu_user_mapping_is_active(void)
{
	bool ret = false;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	uint64_t *entry = NULL;

	entry = core_mmu_get_user_mapping_entry(get_prtn(), 0);
	ret = (*entry != 0);

	thread_unmask_exceptions(exceptions);

	return ret;
}

void core_mmu_get_user_map(struct core_mmu_user_map *map)
{
	struct mmu_partition *prtn = get_prtn();
	uint64_t *entry = NULL;

	entry = core_mmu_get_user_mapping_entry(prtn, 0);

	map->user_map = *entry;
	if (map->user_map) {
		map->asid = (read_satp() >> TTBR_ASID_SHIFT) &
			    TTBR_ASID_MASK;
	} else {
		map->asid = 0;
	}
}

void core_mmu_set_user_map(struct core_mmu_user_map *map)
{
	uint64_t ttbr = 0;
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	struct mmu_partition *prtn = get_prtn();
	uint64_t *entries[NUM_BASE_TABLES] = { };
	unsigned int i = 0;

	ttbr = read_satp();
	/* Clear ASID */
	ttbr &= ~((uint64_t)TTBR_ASID_MASK << TTBR_ASID_SHIFT);
	write_satp(ttbr);
	mb();

	for (i = 0; i < NUM_BASE_TABLES; i++)
		entries[i] = core_mmu_get_user_mapping_entry(prtn, i);

	/* Set the new map */
	if (map && map->user_map) {
		for (i = 0; i < NUM_BASE_TABLES; i++)
			*entries[i] = map->user_map;
		mb();
		ttbr |= ((uint64_t)map->asid << TTBR_ASID_SHIFT);
		write_satp(ttbr);
		mb();
	} else {
		for (i = 0; i < NUM_BASE_TABLES; i++)
			*entries[i] = INVALID_DESC;
		mb();
	}

	flush_tlb();
	asm volatile("fence.i");

	thread_unmask_exceptions(exceptions);
}

enum core_mmu_fault core_mmu_get_fault_type(uint32_t fault_descr __unused)
{
	return 0;
}

#define MMU_NUM_ASID_PAIRS		64

static bitstr_t bit_decl(g_asid, MMU_NUM_ASID_PAIRS) __nex_bss;
static unsigned int g_asid_spinlock __nex_bss = SPINLOCK_UNLOCK;

void tlbi_mva_range_asid(vaddr_t va, size_t len, size_t granule, uint32_t asid)
{
	assert(granule == CORE_MMU_PGDIR_SIZE || granule == SMALL_PAGE_SIZE);
	assert(!(va & (granule - 1)) && !(len & (granule - 1)));

	mb();
	while (len) {
		tlbi_mva_asid(va, asid);
		len -= granule;
		va += granule;
	}
	mb();
}

TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len)
{
	switch (op) {
		case DCACHE_CLEAN:
			dcache_op_all(DCACHE_OP_CLEAN);
			break;
		case DCACHE_AREA_CLEAN:
			dcache_clean_range(va, len);
			break;
		case DCACHE_INVALIDATE:
			dcache_op_all(DCACHE_OP_INV);
			break;
		case DCACHE_AREA_INVALIDATE:
			dcache_inv_range(va, len);
			break;
		case ICACHE_INVALIDATE:
			icache_inv_all();
			break;
		case ICACHE_AREA_INVALIDATE:
			icache_inv_range(va, len);
			break;
		case DCACHE_CLEAN_INV:
			dcache_op_all(DCACHE_OP_CLEAN_INV);
			break;
		case DCACHE_AREA_CLEAN_INV:
			dcache_cleaninv_range(va, len);
			break;
		default:
			return TEE_ERROR_NOT_IMPLEMENTED;
		}
		return TEE_SUCCESS;
}

unsigned int asid_alloc(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);
	unsigned int r;
	int i;

	bit_ffc(g_asid, MMU_NUM_ASID_PAIRS, &i);
	if (i == -1) {
		r = 0;
	} else {
		bit_set(g_asid, i);
		r = (i + 1) * 2;
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
	return r;
}

void asid_free(unsigned int asid)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&g_asid_spinlock);

	/* Only even ASIDs are supposed to be allocated */
	assert(!(asid & 1));

	if (asid) {
		int i = (asid - 1) / 2;

		assert(i < MMU_NUM_ASID_PAIRS && bit_test(g_asid, i));
		bit_clear(g_asid, i);
	}

	cpu_spin_unlock_xrestore(&g_asid_spinlock, exceptions);
}

bool arch_va2pa_helper(void *va, paddr_t *pa)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	bool ret = false;
	uint32_t ttb;
	uint32_t level;
	uint32_t idx;
	uint32_t entry;
	int i;

	ttb = (read_satp() & ((1UL << 44) - 1)) << 12;
	if (ttb == 0) {
		ret = true;
		*pa = (paddr_t)va;
		goto out;
	}
	for (i = 0; i < 3; i++) {
		level = i + 1;
		idx = ((vaddr_t)va >> XLAT_ADDR_SHIFT(level)) & (XLAT_TABLE_ENTRIES_MASK);
		entry = ((uint64_t*)(size_t)ttb)[idx];
		if (!(entry & PTE_V)) {
			debug_print("level:%x,idx:%x, invalid entry:%x\n",level, idx, entry);
			ret = false;
			break;
		}

		if (!DESC_IS_TABLE(entry)) {
			/*entry is block entry, direct get ppn ,add va offset return pa*/
			*pa = (PTE_PPN(entry) << PAGE_SIZE_SHIFT) | ((vaddr_t)va & (XLAT_BLOCK_SIZE(level) - 1));
			ret = true;
			break;
		} else {
			/*entry is table, update next level ttb to get next tab*/
			ttb = PTE_PPN(entry) << PAGE_SIZE_SHIFT;
		}	
	}

out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

bool cpu_mmu_enabled(void)
{
	return read_satp() ? true : false;
}

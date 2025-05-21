/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2021, Arm Limited
 */

#include <platform_config.h>

#include <riscv.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread_private.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

	/*
	 * Setup sp to point to the top of the tmp stack for the current CPU:
	 * sp is assigned stack_tmp + (hart_id +1) * stack_tmp_stride
	 */
.macro set_sp hartid_reg
	mv	t0, \hartid_reg
	li	t1, CFG_TEE_CORE_NB_CORE
	bge	t0, t1, unhandled_cpu
	addi	t0, t0, 1
	lw	t1, stack_tmp_stride
	la	t2, stack_tmp
	mv	sp, t2
	mul	t2, t1, t0
	add	sp, sp, t2
.endm

/*
 * a0:hardid of running optee os
 * a1:optee os size, useless
 * a2:dts address
 */

FUNC _start , :
	mv	s1, a0 /* save hardid to s1 */
#if defined(CFG_DT_ADDR)
	ldr s2, =CFG_DT_ADDR
#else
	mv	s2, a2 /* save dts address to s2 */
#endif
	la	gp, __global_pointer$
	la	a0, reset_vect_table
	csrw	stvec, a0
	fence
	/*
	 * Clear .bss, this code obviously depends on the linker keeping
	 * start/end of .bss at least 8 byte aligned.
	 */
	la	a0, __bss_start
	la	a1, __bss_end
clear_bss:
	sd	x0, (a0)
	add	a0, a0, 8
	blt	a0, a1, clear_bss

	/* Setup sp, s1 is current hartid */
	set_sp	s1
	jal	thread_init_thread_core_local

	/*
	 * Invalidate dcache for all memory used during initialization to
	 * avoid nasty surprices when the cache is turned on. We must not
	 * invalidate memory not used by OP-TEE since we may invalidate
	 * entries used by for instance ARM Trusted Firmware.
	 */
	la	a0, __text_start
	la	a1, cached_mem_end
	sub	a1, a1, a0
	jal	dcache_cleaninv_range

	/* Enable Console */
	jal	console_init

	li	a0, 0
	la	a1, boot_mmu_config
	jal	core_init_mmu_map

	mv	a0, s1
	jal	enable_mmu

	jal	boot_init_primary_early

	mv	a0, s2/* DT address */
	jal	boot_init_primary_late
	/*
	 * In case we've touched memory that secondary CPUs will use before
	 * they have turned on their D-cache, clean and invalidate the
	 * D-cache before exiting to normal world.
	 */
	la	a0, __text_start
	la	a1, cached_mem_end
	sub	a1, a1, a0
	jal	dcache_cleaninv_range
	/*
	 * Clear current thread id now to allow the thread to be reused on
	 * next entry. Matches the thread_init_boot_thread in
	 * boot.c.
	 */
	jal	thread_clr_boot_thread

	/*
	 * Pass the vector address returned from main_init
	 * Compensate for the load offset since cpu_on_handler() is
	 * called with MMU off.
	 * CORE_MMU_CONFIG_LOAD_OFFSET = 16
	 */
	la	s3, boot_mmu_config
	ld	a0, 16(s3)
	la	a1, thread_vector_table
	sub	a1, a1, a0
	li	a6, TEESMC_OPTEED_RETURN_ENTRY_DONE
	li	a7, 0x4F505445
	ecall
	/* ecall should not return */
END_FUNC _start
DECLARE_KEEP_INIT _start

	.section .identity_map.data
	.balign	8
LOCAL_DATA cached_mem_end , :
	.skip	8
END_DATA cached_mem_end

/*
 * void enable_mmu(unsigned long core_pos);
 *
 * This function depends on being mapped with in the identity map where
 * physical address and virtual address is the same. After MMU has been
 * enabled the instruction pointer will be updated to execute as the new
 * offset instead. Stack pointers and the return address are updated.
 */
LOCAL_FUNC enable_mmu , : , .identity_map
	/*
	 * a0 = core_pos
	 * a2 = ttbr_base
	 * a3 = ttbr_core_offset
	 * a4 = load_offset
	 */
	la	a1, boot_mmu_config
	ld	a2, 0(a1)
	ld	a3, 8(a1)
	ld	a4, 16(a1)
	/*
	 * ttbr = ttbr_base + ttbr_core_offset * core_pos
	 * a5 = ttbr
	 */
	mul	a5, a0, a3
	add	a5, a5, a2

	/* Compute satp for page tables, but don't load it yet */
	srl	a6, a5, 12
	li	a7, SATP_MODE_SV39
	sll	a7, a7, 60
	or	a6, a6, a7

	/* Update stvec */
	csrr	a7, stvec
	add	a7, a7, a4
	csrw 	stvec, a7

	/* Adjust stack pointers and return address */
	add	sp, sp, a4
	add	ra, ra, a4
	fence
	fence.i
	/* Enable the MMU */
	csrw	satp, a6
	sfence.vma
	ret
END_FUNC enable_mmu

	.section .identity_map.data
	.balign	8
DATA boot_mmu_config , : /* struct core_mmu_config */
	.skip	CORE_MMU_CONFIG_SIZE
END_DATA boot_mmu_config

FUNC cpu_on_handler , :
	mv	s1, a0
	mv	s2, a1
	mv	s3, ra
	la	gp, __global_pointer$
	la	a0, reset_vect_table
	csrw	stvec, a0
	fence

	/* Setup sp, s1 is current hartid */
	set_sp	s1
	mv	a0, s1
	jal	enable_mmu

	mv	a0, s1
	mv	a1, s2
	mv	ra, s3
	j	boot_cpu_on_handler
	ret
END_FUNC cpu_on_handler
DECLARE_KEEP_PAGER cpu_on_handler

LOCAL_FUNC unhandled_cpu , :
	wfi
	j	unhandled_cpu
	ret
END_FUNC unhandled_cpu

LOCAL_DATA stack_tmp_rel , :
	.word	stack_tmp - stack_tmp_rel
END_DATA stack_tmp_rel

	.section .identity_map, "ax", %progbits
	.align	11
LOCAL_FUNC reset_vect_table , :, .identity_map, , nobti
	wfi
	j	.
	ret
END_FUNC reset_vect_table

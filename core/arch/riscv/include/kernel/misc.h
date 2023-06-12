/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 * Copyright 2023 Nuclei System Technology.
 */

#ifndef KERNEL_MISC_H
#define KERNEL_MISC_H

#include <assert.h>
#include <kernel/thread.h>
#include <riscv.h>
#include <types_ext.h>

static inline size_t __noprof get_core_pos(void)
{
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	return read_hartid();
}

#endif /*KERNEL_MISC_H*/

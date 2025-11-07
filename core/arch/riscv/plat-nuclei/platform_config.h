/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 *
 * Brief   Spike platform configuration.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#ifdef CFG_RISCV_MTIME_RATE
#define RISCV_MTIME_RATE CFG_RISCV_MTIME_RATE
#else
#define RISCV_MTIME_RATE 32768
#endif

#define NUCLEI_MAILBOX_BASE       (0x97000000UL)
#define NUCLEI_MAILBOX_SIZE       (0x4000UL)

#define PLIC_BASE                 (0x4000000UL)

#endif

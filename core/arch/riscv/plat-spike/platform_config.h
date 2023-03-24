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
#define RISCV_MTIME_RATE 1000000
#endif

#endif

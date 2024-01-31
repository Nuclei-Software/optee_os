// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 Nuclei System Technology.
 */
#include <io.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include "stdio.h"
#include <kernel/interrupt.h>
#include <sbi.h>

#define PLIC_CLAIM_SIZE         0x1000
/*hart0 S mode*/
#define PLIC_CLAIM_HART0_BASE 0x1c201000
#define PLIC_CLAIM_HART0_SIZE PLIC_CLAIM_SIZE
/*hart1 S mode*/
#define PLIC_CLAIM_HART1_BASE 0x1c203000
#define PLIC_CLAIM_HART1_SIZE PLIC_CLAIM_SIZE
/*hart2 S mode*/
#define PLIC_CLAIM_HART2_BASE 0x1c205000
#define PLIC_CLAIM_HART2_SIZE PLIC_CLAIM_SIZE
/*hart3 S mode*/
#define PLIC_CLAIM_HART3_BASE 0x1c207000
#define PLIC_CLAIM_HART3_SIZE PLIC_CLAIM_SIZE

register_phys_mem(MEM_AREA_IO_SEC, PLIC_CLAIM_HART0_BASE, PLIC_CLAIM_HART0_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, PLIC_CLAIM_HART1_BASE, PLIC_CLAIM_HART1_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, PLIC_CLAIM_HART2_BASE, PLIC_CLAIM_HART2_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, PLIC_CLAIM_HART3_BASE, PLIC_CLAIM_HART3_SIZE);

volatile vaddr_t plic_claim_base = 0;
void itr_core_handler(void)
{
    int id;
    int hartid;

#ifdef CFG_SHART_FEATURE
    hartid = read_hartid();
#else
    hartid = sbi_read_hartid();
#endif

    sbi_console_putchar('0' + hartid);
    sbi_console_putchar('@');
    sbi_console_putchar('\n');
    plic_claim_base = core_mmu_get_va(PLIC_CLAIM_HART0_BASE +
            hartid * 0x2000, MEM_AREA_IO_SEC, PLIC_CLAIM_SIZE);

    /*claim plic interrupt*/
    id = io_read32(plic_claim_base + 4);
    if (id == 38 || id == 39) {
        static volatile vaddr_t timer_base = 0;

        if (timer_base ==0)
            timer_base = core_mmu_get_va(0x10012000, MEM_AREA_IO_SEC,
                    0x1000);
        *(volatile unsigned int*)timer_base = 300000000;
        *(volatile unsigned int*)(timer_base +4) = (unsigned int)(-1);
    }
    /*complete*/
    io_write32(plic_claim_base + 4, id);
}

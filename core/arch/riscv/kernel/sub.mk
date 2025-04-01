srcs-$(CFG_WITH_USER_TA) += ldelf_loader.c
srcs-y += otp_stubs.c
srcs-y += delay.c
srcs-y += idle.c
srcs-y += sbi.c
srcs-y += console.c
# srcs-$(CFG_SECURE_TIME_SOURCE_CNTPCT) += tee_time_arm_cntpct.c
srcs-$(CFG_RISCV_TIME_SOURCE_RDTIME) += tee_time_rdtime.c

srcs-y += spinlock.S

srcs-y += tlb_helpers_rv.S
srcs-y += cache_helpers.c


srcs-y += thread_rv.S
srcs-y += thread.c

srcs-y += thread_optee_smc.c
srcs-y += thread_optee_smc_a64.S

srcs-y += abort.c
ifeq ($(CFG_WITH_VFP),y)
srcs-y += vfp.c
srcs-y += vfp_rv64.S
endif
srcs-y += trace_ext.c

srcs-y += boot.c
srcs-y += entry.S

srcs-y += link_dummies_paged.c
srcs-y += link_dummies_init.c

asm-defines-y += asm-defines.c
# Reflect the following dependencies:
# asm-defines.c includes <kernel/thread.h>
#   <kernel/thread.h> includes <asm.h>
#     <asm.h> includes <generated/arm32_sysreg.h>
#                  and <generated/arm32_gicv3_sysreg.h> (optional)

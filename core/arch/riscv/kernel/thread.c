// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 * Copyright (c) 2016-2022, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020-2021, Arm Limited
 */

#include <platform_config.h>

#include <assert.h>
#include <config.h>
#include <io.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <riscv.h>
#include <trace.h>
#include <util.h>

#define __enable_user_access()                          \
    __asm__ __volatile__ ("csrs sstatus, %0" : : "r" (CSR_XSTATUS_SUM) : "memory")
#define __disable_user_access()                         \
    __asm__ __volatile__ ("csrc sstatus, %0" : : "r" (CSR_XSTATUS_SUM) : "memory")

uint32_t __nostackcheck thread_get_exceptions(void)
{
	return read_csr(CSR_XIE) & THREAD_EXCP_ALL;
}

void __nostackcheck thread_set_exceptions(uint32_t exceptions)
{
	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	barrier();
	write_csr(CSR_XIE, exceptions);
	barrier();
}

uint32_t __nostackcheck thread_mask_exceptions(uint32_t exceptions)
{
	uint32_t state = thread_get_exceptions();

	thread_set_exceptions(state | (exceptions & THREAD_EXCP_ALL));
	return state;
}

void __nostackcheck thread_unmask_exceptions(uint32_t state)
{
	thread_set_exceptions(state & THREAD_EXCP_ALL);
}

static void thread_lazy_save_ns_vfp(void)
{
	/* implement */
}

static void thread_lazy_restore_ns_vfp(void)
{
	/* implement */
}

uint32_t thread_kernel_enable_vfp(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	/* implement */
	return exceptions;
}

void thread_kernel_disable_vfp(uint32_t state __unused)
{
	uint32_t exceptions = thread_get_exceptions();
	/* implement */
	thread_set_exceptions(exceptions);
}

void thread_kernel_save_vfp(void)
{
	/* implement */
}

void thread_kernel_restore_vfp(void)
{
	/* implement */
}

void thread_user_enable_vfp(struct thread_user_vfp_state *uvfp __unused)
{
	/* implement */
}

void thread_user_save_vfp(void)
{
	/* implement */
}

void thread_user_clear_vfp(struct user_mode_ctx *uctx __unused)
{
	/* implement */
}

static void setup_unwind_user_mode(struct thread_svc_regs *regs)
{
	regs->ra = (uintptr_t)thread_unwind_user_mode;
	regs->status = read_csr(CSR_XSTATUS);
	regs->sp = thread_get_saved_thread_sp();
}

static void thread_unhandled_trap(struct thread_trap_regs *regs,
				  unsigned long cause __unused)
{
    DMSG("Unhandled trap xepc:0x%016lx xcause:0x%016lx xtval:0x%016lx",
		read_csr(CSR_XEPC), read_csr(CSR_XCAUSE), read_csr(CSR_XTVAL));
	panic();
}

void  thread_scall_handler(struct thread_svc_regs *regs)
{
	struct ts_session *sess = NULL;
	uint32_t state = 0;

	/* Enable native interrupts */
	state = thread_get_exceptions();
	thread_unmask_exceptions(state & ~THREAD_EXCP_NATIVE_INTR);

	thread_user_save_vfp();

	sess = ts_get_current_session();

	/* Restore foreign interrupts which are disabled on exception entry */
	thread_restore_foreign_intr();

	assert(sess && sess->handle_scall);

	if (!sess->handle_svc(regs)) {
		setup_unwind_user_mode(regs);
        thread_exit_user_mode(regs->a0, regs->a1, regs->a2,
                      regs->a3, regs->sp, regs->ra,
                      regs->status);
	}
}

static void thread_user_ecall_handler(struct thread_trap_regs *trap_regs)
{
	struct thread_svc_regs scall_regs;
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	/* copy trap_regs to scall_regs */
	scall_regs.a0 = trap_regs->a0;
	scall_regs.a1 = trap_regs->a1;
	scall_regs.a2 = trap_regs->a2;
	scall_regs.a3 = trap_regs->a3;
	scall_regs.a4 = trap_regs->a4;
	scall_regs.a5 = trap_regs->a5;
	scall_regs.a6 = trap_regs->a6;
	scall_regs.a7 = trap_regs->a7;
	scall_regs.ra = trap_regs->ra;
	scall_regs.status = trap_regs->status;
	scall_regs.t0 = trap_regs->t0;
	thread_scall_handler(&scall_regs);
	/* copy scall_regs to trap_regs */
	trap_regs->a0 = scall_regs.a0;
	trap_regs->a1 = scall_regs.a1;
	trap_regs->a2 = scall_regs.a2;
	trap_regs->a3 = scall_regs.a3;
	trap_regs->a4 = scall_regs.a4;
	trap_regs->a5 = scall_regs.a5;
	trap_regs->a6 = scall_regs.a6;
	trap_regs->a7 = scall_regs.a7;

	threads[ct].kern_sp = (unsigned long)(trap_regs + 1);

	trap_regs->epc += 4;
}

static void copy_trap_to_abort(struct thread_trap_regs *trap_regs,
                   struct thread_abort_regs *abort_regs)
{
    *abort_regs = (struct thread_abort_regs) {
        .status = trap_regs->status,
        .ra = trap_regs->ra,
        .sp = trap_regs->sp,
        .gp = trap_regs->gp,
        .tp = trap_regs->tp,
        .t0 = trap_regs->t0,
        .t1 = trap_regs->t1,
        .t2 = trap_regs->t2,
        .s0 = trap_regs->s0,
        .s1 = trap_regs->s1,
        .a0 = trap_regs->a0,
        .a1 = trap_regs->a1,
        .a2 = trap_regs->a2,
        .a3 = trap_regs->a3,
        .a4 = trap_regs->a4,
        .a5 = trap_regs->a5,
        .a6 = trap_regs->a6,
        .a7 = trap_regs->a7,
        .s2 = trap_regs->s2,
        .s3 = trap_regs->s3,
        .s4 = trap_regs->s4,
        .s5 = trap_regs->s5,
        .s6 = trap_regs->s6,
        .s7 = trap_regs->s7,
        .s8 = trap_regs->s8,
        .s9 = trap_regs->s9,
        .s10 = trap_regs->s10,
        .s11 = trap_regs->s11,
        .t3 = trap_regs->t3,
        .t4 = trap_regs->t4,
        .t5 = trap_regs->t5,
        .t6 = trap_regs->t6,
    };
}

static void thread_abort_handler(struct thread_trap_regs *trap_regs,
                 unsigned long cause)
{
    struct thread_abort_regs abort_regs = { };

    assert(cause == read_csr(CSR_XCAUSE));
    copy_trap_to_abort(trap_regs, &abort_regs);
    abort_regs.cause = read_csr(CSR_XCAUSE);
    abort_regs.epc = read_csr(CSR_XEPC);
    abort_regs.tval = read_csr(CSR_XTVAL);
    abort_regs.satp = read_csr(CSR_SATP);
    abort_handler(cause, &abort_regs);
}

static void thread_exception_handler(unsigned long cause,
				     struct thread_trap_regs *regs)
{
	switch (cause) {
	case CAUSE_USER_ECALL:
		thread_user_ecall_handler(regs);
		break;
	default:
		thread_abort_handler(regs, cause);
		break;
	}
}

static void thread_irq_handler(void)
{
	itr_core_handler();
}

static void thread_interrupt_handler(unsigned long cause,
				     struct thread_trap_regs *regs)
{
	switch ((unsigned int)cause) {
	case IRQ_XTIMER:
		clear_csr(CSR_SIE, CSR_XIE_TIE);
		break;
	case IRQ_XSOFT:
		thread_unhandled_trap(regs, cause);
		break;
	case IRQ_XEXT:
		thread_irq_handler();
		break;
	default:
		thread_unhandled_trap(regs, cause);
	}
}

void thread_trap_handler(long cause, unsigned long epc __maybe_unused,
			 struct thread_trap_regs *regs,
			 bool user __maybe_unused)
{
	/*
	 * The Interrupt bit (XLEN-1) in the cause register is set
	 * if the trap was caused by an interrupt.
	 */
	if (cause < 0)
		thread_interrupt_handler(cause, regs);
	/*
	 * Otherwise, cause is never written by the implementation,
	 * though it may be explicitly written by software.
	 */
	else
		thread_exception_handler((cause & LONG_MAX), regs);
}

static void init_regs(struct thread_ctx *thread, uint32_t a0, uint32_t a1,
		      uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
		      uint32_t a6, uint32_t a7, void *pc)
{
	thread->regs.pc = (uintptr_t)pc;

	/* Set up xstatus */
	thread->regs.status = read_csr(CSR_XSTATUS);

	thread->regs.status = set_field_u64(thread->regs.status, SSTATUS_SPP,
					    PRV_S);
//	thread->regs.status |= CSR_XSTATUS_SUM | SSTATUS_MXR;
	thread->regs.status |= CSR_XSTATUS_SUM | SSTATUS_FS;

	/* Reinitialize stack pointer */
	thread->regs.sp = thread->stack_va_end;

	/*
	 * Copy arguments into context. This will make the
	 * arguments appear in a0-a7 when thread is started.
	 */
	thread->regs.a0 = a0;
	thread->regs.a1 = a1;
	thread->regs.a2 = a2;
	thread->regs.a3 = a3;
	thread->regs.a4 = a4;
	thread->regs.a5 = a5;
	thread->regs.a6 = a6;
	thread->regs.a7 = a7;

	thread->regs.s0 = 0;
}

static void __thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2,
				   uint32_t a3, uint32_t a4, uint32_t a5,
				   uint32_t a6, uint32_t a7,
				   void *pc)
{
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;
	size_t n = 0;

	assert(l->curr_thread == THREAD_ID_INVALID);

	thread_lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state == THREAD_STATE_FREE) {
			threads[n].state = THREAD_STATE_ACTIVE;
			found_thread = true;
			break;
		}
	}

	thread_unlock_global();

	if (!found_thread)
		return;

	l->curr_thread = n;

	threads[n].flags = 0;
	init_regs(threads + n, a0, a1, a2, a3, a4, a5, a6, a7, pc);

	thread_lazy_save_ns_vfp();

	l->flags &= ~THREAD_CLF_TMP;

	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5)
{
	__thread_alloc_and_run(a0, a1, a2, a3, a4, a5, 0, 0,
			       thread_std_smc_entry);
}

static void copy_a0_to_a3(struct thread_ctx_regs *regs, uint32_t a0,
			  uint32_t a1, uint32_t a2, uint32_t a3)
{
	regs->a0 = a0;
	regs->a1 = a1;
	regs->a2 = a2;
	regs->a3 = a3;
}

static bool is_from_user(unsigned long status)
{
	return (status & MSTATUS_SPP);
}

#ifdef CFG_SYSCALL_FTRACE
static void __noprof ftrace_suspend(void)
{
	struct ts_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s && s->fbuf)
		s->fbuf->syscall_trace_suspended = true;
}

static void __noprof ftrace_resume(void)
{
	struct ts_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s && s->fbuf)
		s->fbuf->syscall_trace_suspended = false;
}
#else
static void __maybe_unused __noprof ftrace_suspend(void)
{
}

static void __noprof ftrace_resume(void)
{
}
#endif

static bool is_user_mode(struct thread_ctx_regs *regs)
{
	return is_from_user((uint32_t)regs->status);
}

vaddr_t thread_get_saved_thread_sp(void)
{
    struct thread_core_local *l = thread_get_core_local();
    int ct = l->curr_thread;

    assert(ct != THREAD_ID_INVALID);
    return threads[ct].kern_sp;
}

void thread_resume_from_rpc(uint32_t thread_id, uint32_t a0, uint32_t a1,
			    uint32_t a2, uint32_t a3)
{
	size_t n = thread_id;
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == THREAD_ID_INVALID);

	thread_lock_global();

	if (n < CFG_NUM_THREADS && threads[n].state == THREAD_STATE_SUSPENDED) {
		threads[n].state = THREAD_STATE_ACTIVE;
		found_thread = true;
	}

	thread_unlock_global();

	if (!found_thread)
		return;

	l->curr_thread = n;

	if (threads[n].have_user_map) {
		core_mmu_set_user_map(&threads[n].user_map);
		if (threads[n].flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR)
			tee_ta_ftrace_update_times_resume();
	}

	if (is_user_mode(&threads[n].regs))
		tee_ta_update_session_utime_resume();

	/*
	 * Return from RPC to request service of a foreign interrupt must not
	 * get parameters from non-secure world.
	 */
	if (threads[n].flags & THREAD_FLAGS_COPY_ARGS_ON_RETURN) {
		copy_a0_to_a3(&threads[n].regs, a0, a1, a2, a3);
		threads[n].flags &= ~THREAD_FLAGS_COPY_ARGS_ON_RETURN;
	}

	thread_lazy_save_ns_vfp();

	if (threads[n].have_user_map)
		ftrace_resume();

	l->flags &= ~THREAD_CLF_TMP;
	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

void thread_state_free(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	thread_lazy_restore_ns_vfp();
	tee_pager_release_phys((void *)(threads[ct].stack_va_end -
				STACK_THREAD_SIZE), STACK_THREAD_SIZE);

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = THREAD_ID_INVALID;

	if (IS_ENABLED(CFG_VIRTUALIZATION))
		virt_unset_guest();
	thread_unlock_global();
}

static void release_unused_kernel_stack(struct thread_ctx *thr __unused,
					uint64_t cpsr __unused)
{

}

int thread_state_suspend(uint32_t flags, uint64_t status, vaddr_t pc)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	if (core_mmu_user_mapping_is_active())
		ftrace_suspend();

	thread_check_canaries();

	release_unused_kernel_stack(threads + ct, status);

	if (is_from_user(status)) {
		thread_user_save_vfp();
		tee_ta_update_session_utime_suspend();
		tee_ta_gprof_sample_pc(pc);
	}
	thread_lazy_restore_ns_vfp();

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].flags |= flags;
	threads[ct].regs.status = status;
	threads[ct].regs.pc = pc;
	threads[ct].state = THREAD_STATE_SUSPENDED;

	threads[ct].have_user_map = core_mmu_user_mapping_is_active();
	if (threads[ct].have_user_map) {
		if (threads[ct].flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR)
			tee_ta_ftrace_update_times_suspend();
		core_mmu_get_user_map(&threads[ct].user_map);
		core_mmu_set_user_map(NULL);
	}

	l->curr_thread = THREAD_ID_INVALID;

	if (IS_ENABLED(CFG_VIRTUALIZATION))
		virt_unset_guest();

	thread_unlock_global();

	return ct;
}

bool thread_init_stack(uint32_t thread_id, vaddr_t sp)
{
	if (thread_id >= CFG_NUM_THREADS)
		return false;
	threads[thread_id].stack_va_end = sp;
	return true;
}

static void init_user_kcode(void)
{
}

void thread_init_primary(void)
{
	/* Initialize canaries around the stacks */
	thread_init_canaries();

	init_user_kcode();
}

static vaddr_t get_trap_vect(void)
{
	return (vaddr_t)thread_trap_vect;
}

void thread_init_tvec(void)
{
	unsigned long tvec = (unsigned long)get_trap_vect();

	COMPILE_TIME_ASSERT(sizeof(struct thread_trap_regs) % 16 == 0);
	write_csr(CSR_XTVEC, tvec);
	assert(read_csr(CSR_XTVEC) == tvec);
}

void thread_init_per_cpu(void)
{
	thread_init_tvec();

	set_csr(CSR_XSTATUS, CSR_XSTATUS_SUM);
}

static void set_ctx_regs(struct thread_ctx_regs *regs, unsigned long a0,
			 unsigned long a1, unsigned long a2, unsigned long a3,
			 unsigned long user_sp, unsigned long entry_func,
			 uint64_t status,
			 struct thread_pauth_keys *keys __unused)
{
	*regs = (struct thread_ctx_regs){ };
	regs->a0 = a0;
	regs->a1 = a1;
	regs->a2 = a2;
	regs->a3 = a3;
	regs->sp = user_sp;
	regs->pc = entry_func;
	regs->status = status;
	regs->s0 = 0;
}

uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
				unsigned long a2, unsigned long a3,
				unsigned long user_sp,
				unsigned long entry_func,
				bool is_32bit __unused,
				uint32_t *exit_status0,
				uint32_t *exit_status1)
{
	uint64_t status = 0;
	uint32_t exceptions = 0;
	uint32_t rc = 0;
	struct thread_ctx_regs *regs = NULL;

	tee_ta_update_session_utime_resume();

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	regs = thread_get_ctx_regs();
	status = read_sstatus();
	set_ctx_regs(regs, a0, a1, a2, a3, user_sp, entry_func, status, NULL);
	//__enable_user_access();
	regs->status |= BIT(18);
	rc = __thread_enter_user_mode(regs, exit_status0, exit_status1);
	regs->status &= ~BIT(18);
//	__disable_user_access();
	thread_unmask_exceptions(exceptions);

	return rc;
}

unsigned long __weak thread_cpu_off_handler(unsigned long a0 __unused,
					    unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_cpu_off_handler);

unsigned long __weak thread_cpu_suspend_handler(unsigned long a0 __unused,
						unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_cpu_suspend_handler);

unsigned long __weak thread_cpu_resume_handler(unsigned long a0 __unused,
					       unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_cpu_resume_handler);

unsigned long __weak thread_system_off_handler(unsigned long a0 __unused,
					       unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_system_off_handler);

unsigned long __weak thread_system_reset_handler(unsigned long a0 __unused,
						 unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_system_reset_handler);

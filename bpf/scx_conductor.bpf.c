/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_conductor - the hand-written, *parameterised* reference scheduler.
 *
 * Two ways of getting a scheduler onto a device under the conductor:
 *
 *  1. This template, specialised per workload: the daemon writes the const
 *     volatile knobs below into .rodata *before* load. The kernel verifier then
 *     sees them as constants, so the loaded program really is a different, smaller
 *     program per profile. The object is built and reviewed once; its digest never
 *     changes.
 *
 *  2. On-device generation (conductord/generator.py): an agent is shown this file
 *     and conductor_abi.bpf.h, and writes a *new* scheduler for the current workload
 *     and hardware. The result goes through a static gate, compilation, the kernel
 *     verifier (load without attach), a canary and an operator approval before it is
 *     ever signed and loaded. This file is the reference the agent starts from.
 *
 * Design (deliberately conservative, derived from scx_simple):
 *   - one shared vtime-ordered DSQ  => starvation-free by construction
 *   - class-scaled vtime charge     => FG/MEDIA get more share, BG gets less,
 *                                      but nobody is starved
 *   - class-scaled sleeper credit   => wakeup latency boost for FG/MEDIA
 *   - class-scaled slice            => short slices where latency matters,
 *                                      long slices where throughput/power matter
 *   - per-class cpuperf hint        => performance / power posture
 *   - per-class enqueue->run latency histogram => SLO signal for the governor
 *
 * Needs Linux >= 6.12 with CONFIG_SCHED_CLASS_EXT. Headers (scx/common.bpf.h)
 * must come from the same kernel tree you run.
 */
#include "conductor_abi.bpf.h"

/* ---------------- specialisation knobs (rodata) ---------------- */
/* index: CLS_NORMAL, CLS_FG, CLS_MEDIA, CLS_BG */
const volatile u64 slice_ns[NR_CLS]    = { 4000000, 3000000, 3000000, 8000000 };
const volatile u64 credit_ns[NR_CLS]   = { 2000000, 6000000, 6000000, 0 };
const volatile u32 charge_pct[NR_CLS]  = { 100, 70, 60, 180 };
const volatile u32 perf_target[NR_CLS] = { 0, 0, 0, 0 };	/* 0 = don't touch */
const volatile bool inject_stall = false;	/* TEST ONLY: provoke the watchdog */

static u64 vtime_now;

/* ---------------- sched_ext ops ---------------- */
s32 BPF_STRUCT_OPS(conductor_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		u32 cls = conductor_class_of(p);
		u64 slice = slice_ns[cls];

		conductor_mark_enq(p, cls, slice);
		conductor_stat_inc(ST_DIRECT_LOCAL);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
	}
	return cpu;
}

void BPF_STRUCT_OPS(conductor_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 cls = conductor_class_of(p);
	u64 slice = slice_ns[cls];
	u64 vtime = p->scx.dsq_vtime;
	u64 floor = vtime_now - credit_ns[cls];

	/* Bound how much credit a long sleeper may bank (latency boost). */
	if (time_before(vtime, floor)) {
		vtime = floor;
		conductor_stat_inc(ST_CREDIT_APPLIED);
	}

	conductor_mark_enq(p, cls, slice);
	conductor_stat_inc(ST_ENQ_SHARED);
	conductor_stat_inc(ST_ENQ_CLS0 + cls);
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}

void BPF_STRUCT_OPS(conductor_dispatch, s32 cpu, struct task_struct *prev)
{
	if (inject_stall)
		return;
	conductor_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(conductor_running, struct task_struct *p)
{
	u32 cls = conductor_note_running(p);
	u32 perf;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	perf = perf_target[cls];
	if (perf) {
		scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), perf);
		conductor_stat_inc(ST_PERF_SET);
	}
}

void BPF_STRUCT_OPS(conductor_stopping, struct task_struct *p, bool runnable)
{
	struct cnd_task_ctx *tctx;
	u32 cls = CLS_NORMAL;
	u64 granted = SCX_SLICE_DFL;
	u64 used;
	u32 weight = p->scx.weight ? p->scx.weight : 100;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (tctx) {
		cls = tctx->cls & CLS_MASK;
		granted = tctx->slice;
	}

	used = p->scx.slice < granted ? granted - p->scx.slice : 0;
	p->scx.dsq_vtime += used * charge_pct[cls] / weight;
}

void BPF_STRUCT_OPS(conductor_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(conductor_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(conductor_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(conductor_ops,
	       .select_cpu	= (void *)conductor_select_cpu,
	       .enqueue		= (void *)conductor_enqueue,
	       .dispatch	= (void *)conductor_dispatch,
	       .running		= (void *)conductor_running,
	       .stopping	= (void *)conductor_stopping,
	       .enable		= (void *)conductor_enable,
	       .init		= (void *)conductor_init,
	       .exit		= (void *)conductor_exit,
	       .timeout_ms	= 5000,
	       .name		= "conductor");

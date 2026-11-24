/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_conductor - a *parameterised* sched_ext scheduler template.
 *
 * "On the fly scheduler generation" in this project means: the conductor
 * daemon specialises this template per workload by writing the const volatile
 * knobs below into .rodata *before* load. The kernel verifier then sees them as
 * constants, so the loaded program is genuinely a different, smaller program
 * per profile. Source-level generation (new BPF C written by an agent) is a
 * separate, gated path described in docs/SAFETY.md and never runs on-device.
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
#include <scx/common.bpf.h>
#include "conductor.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ	0

/* ---------------- specialisation knobs (rodata) ---------------- */
/* index: CLS_NORMAL, CLS_FG, CLS_MEDIA, CLS_BG */
const volatile u64 slice_ns[NR_CLS]    = { 4000000, 3000000, 3000000, 8000000 };
const volatile u64 credit_ns[NR_CLS]   = { 2000000, 6000000, 6000000, 0 };
const volatile u32 charge_pct[NR_CLS]  = { 100, 70, 60, 180 };
const volatile u32 perf_target[NR_CLS] = { 0, 0, 0, 0 };	/* 0 = don't touch */
const volatile bool inject_stall = false;	/* TEST ONLY: provoke the watchdog */

/* ---------------- maps ---------------- */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TGID_CLASS_MAX);
	__type(key, u32);
	__type(value, u8);
} tgid_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_STATS);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_CLS * LAT_BUCKETS);
	__type(key, u32);
	__type(value, u64);
} lat_hist SEC(".maps");

struct task_ctx {
	u64 enq_ts;	/* when it became runnable (ns), 0 = not pending */
	u64 slice;	/* slice we granted, for charging */
	u32 cls;	/* class at enqueue time */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static u64 vtime_now;

/* ---------------- helpers ---------------- */
static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);

	if (cnt)
		(*cnt)++;
}

static __always_inline u32 lookup_class(struct task_struct *p)
{
	u32 tgid = p->tgid;
	u8 *c = bpf_map_lookup_elem(&tgid_class, &tgid);

	return c ? (*c & CLS_MASK) : CLS_NORMAL;
}

static __always_inline void mark_enq(struct task_struct *p, u32 cls, u64 slice)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (tctx) {
		tctx->enq_ts = bpf_ktime_get_ns();
		tctx->slice = slice;
		tctx->cls = cls;
	}
}

/* bucket = min(floor(log2(latency_us + 1)), LAT_BUCKETS - 1) */
static __always_inline void record_latency(u32 cls, u64 delta_ns)
{
	u64 v = delta_ns / 1000 + 1;
	u32 b = 0;
	u32 idx;
	u64 *cnt;
	int i;

	for (i = 0; i < LAT_BUCKETS - 1; i++) {
		if (v > 1) {
			v >>= 1;
			b++;
		}
	}
	idx = (cls & CLS_MASK) * LAT_BUCKETS + b;
	cnt = bpf_map_lookup_elem(&lat_hist, &idx);
	if (cnt)
		(*cnt)++;
}

/* ---------------- sched_ext ops ---------------- */
s32 BPF_STRUCT_OPS(conductor_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		u32 cls = lookup_class(p);
		u64 slice = slice_ns[cls];

		mark_enq(p, cls, slice);
		stat_inc(ST_DIRECT_LOCAL);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
	}
	return cpu;
}

void BPF_STRUCT_OPS(conductor_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 cls = lookup_class(p);
	u64 slice = slice_ns[cls];
	u64 vtime = p->scx.dsq_vtime;
	u64 floor = vtime_now - credit_ns[cls];

	/* Bound how much credit a long sleeper may bank (latency boost). */
	if (time_before(vtime, floor)) {
		vtime = floor;
		stat_inc(ST_CREDIT_APPLIED);
	}

	mark_enq(p, cls, slice);
	stat_inc(ST_ENQ_SHARED);
	stat_inc(ST_ENQ_CLS0 + cls);
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}

void BPF_STRUCT_OPS(conductor_dispatch, s32 cpu, struct task_struct *prev)
{
	if (inject_stall)
		return;
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(conductor_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	u32 cls = CLS_NORMAL;
	u32 perf;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (tctx) {
		cls = tctx->cls & CLS_MASK;
		if (tctx->enq_ts) {
			u64 now = bpf_ktime_get_ns();

			if (now >= tctx->enq_ts)
				record_latency(cls, now - tctx->enq_ts);
			tctx->enq_ts = 0;
		}
	}

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	perf = perf_target[cls];
	if (perf) {
		scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), perf);
		stat_inc(ST_PERF_SET);
	}
}

void BPF_STRUCT_OPS(conductor_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
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

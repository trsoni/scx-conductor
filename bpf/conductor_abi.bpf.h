/* SPDX-License-Identifier: GPL-2.0 */
/*
 * conductor_abi.bpf.h - the contract between conductor_load and ANY scheduler
 * that runs under the conductor, whether it is the hand-written template
 * (scx_conductor.bpf.c) or a source file written on the device by an agent.
 *
 * What this header provides (so a scheduler author does not have to):
 *   - the GPL licence section and the user-exit-info block ("uei")
 *   - the maps the governor and loader talk to:
 *       tgid_class     tgid -> class       (written by the governor via the loader)
 *       stats          per-CPU counters    (read by the governor)
 *       lat_hist       per-class enqueue->run latency histogram (the SLO signal)
 *       task_ctx_stor  per-task scratch used by the helpers below
 *   - small helpers that keep the telemetry honest:
 *       conductor_class_of(p)            class of a task (CLS_*)
 *       conductor_mark_enq(p, cls, sl)   call whenever a task is made runnable
 *       conductor_note_running(p)        call from .running(); records latency
 *       conductor_stat_inc(ST_*)         bump a counter
 *       conductor_move_to_local(dsq)     portable wrapper over the kfunc whose
 *                                        arity changed between kernel versions
 *
 * A generated scheduler MUST:
 *   - #include "conductor_abi.bpf.h" and nothing else of its own for headers
 *   - end with SCX_OPS_DEFINE(gen_ops, ..., .name = "conductor_gen")
 *   - call conductor_mark_enq() when it queues a task and conductor_note_running()
 *     from .running(), or the governor sees no latency data and the canary fails
 *
 * Needs Linux with CONFIG_SCHED_CLASS_EXT. The scx headers must come from a tree
 * matching the running kernel.
 */
#ifndef __CONDUCTOR_ABI_BPF_H
#define __CONDUCTOR_ABI_BPF_H

#include <scx/common.bpf.h>
#include "conductor.h"

/* Written by tools/probe-scx-abi.sh / genbuild.py: records header-version quirks. */
#if __has_include("conductor_probe.h")
#include "conductor_probe.h"
#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ	0

/* ---------------- maps shared with the loader ---------------- */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TGID_CLASS_MAX);
	__type(key, u32);
	__type(value, u8);
} tgid_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CND_NR_STATS);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NR_CLS * LAT_BUCKETS);
	__type(key, u32);
	__type(value, u64);
} lat_hist SEC(".maps");

struct cnd_task_ctx {
	u64 enq_ts;	/* when it became runnable (ns), 0 = not pending */
	u64 slice;	/* slice we granted, for charging */
	u32 cls;	/* class at enqueue time */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cnd_task_ctx);
} task_ctx_stor SEC(".maps");

/* ---------------- helpers ---------------- */
static __always_inline void conductor_stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);

	if (cnt)
		(*cnt)++;
}

static __always_inline u32 conductor_class_of(struct task_struct *p)
{
	u32 tgid = p->tgid;
	u8 *c = bpf_map_lookup_elem(&tgid_class, &tgid);

	return c ? (*c & CLS_MASK) : CLS_NORMAL;
}

static __always_inline void conductor_mark_enq(struct task_struct *p, u32 cls, u64 slice)
{
	struct cnd_task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (tctx) {
		tctx->enq_ts = bpf_ktime_get_ns();
		tctx->slice = slice;
		tctx->cls = cls & CLS_MASK;
	}
}

/* bucket = min(floor(log2(latency_us + 1)), LAT_BUCKETS - 1) */
static __always_inline void conductor_record_latency(u32 cls, u64 delta_ns)
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

/* Call from .running(). Records enqueue->run latency and returns the class. */
static __always_inline u32 conductor_note_running(struct task_struct *p)
{
	struct cnd_task_ctx *tctx;
	u32 cls = CLS_NORMAL;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (tctx) {
		cls = tctx->cls & CLS_MASK;
		if (tctx->enq_ts) {
			u64 now = bpf_ktime_get_ns();

			if (now >= tctx->enq_ts)
				conductor_record_latency(cls, now - tctx->enq_ts);
			tctx->enq_ts = 0;
		}
	}
	return cls;
}

/*
 * scx_bpf_dsq_move_to_local() gained an @enq_flags argument in newer kernels,
 * and the scx compat header turns it into a 2-argument macro. Which one your
 * headers have is probed at build time (CND_MOVE_TO_LOCAL_2ARG).
 */
#ifdef CND_MOVE_TO_LOCAL_2ARG
#define conductor_move_to_local(dsq)	scx_bpf_dsq_move_to_local((dsq), 0)
#else
#define conductor_move_to_local(dsq)	scx_bpf_dsq_move_to_local((dsq))
#endif

#endif /* __CONDUCTOR_ABI_BPF_H */

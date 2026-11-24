/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared between the BPF scheduler template and the userspace loader.
 * Only #defines / enums here, so it is safe to include from both sides.
 */
#ifndef __SCX_CONDUCTOR_H
#define __SCX_CONDUCTOR_H

/* Per-task scheduling classes. The governor maps tgid -> class. */
enum conductor_class {
	CLS_NORMAL = 0,	/* default / unknown tasks */
	CLS_FG     = 1,	/* foreground: UI, browser, game main threads */
	CLS_MEDIA  = 2,	/* periodic pipelines: camera ISP, video, audio */
	CLS_BG     = 3,	/* background / batch / agent tool workers */
	NR_CLS     = 4,	/* must stay a power of two (masking in BPF) */
};

#define CLS_MASK		(NR_CLS - 1)
#define LAT_BUCKETS		16	/* log2(usec) buckets: <2us ... >=32ms */
#define CPUPERF_ONE		1024	/* same scale as SCX_CPUPERF_ONE */
#define TGID_CLASS_MAX		8192

/* Counters in the per-CPU "stats" array. */
enum conductor_stat {
	ST_DIRECT_LOCAL = 0,	/* idle CPU found in select_cpu, dispatched directly */
	ST_ENQ_SHARED,		/* went through the shared vtime DSQ */
	ST_ENQ_CLS0,		/* + class index: enqueues per class */
	ST_ENQ_CLS1,
	ST_ENQ_CLS2,
	ST_ENQ_CLS3,
	ST_CREDIT_APPLIED,	/* sleeper credit actually clamped a vtime */
	ST_PERF_SET,		/* cpuperf hints issued */
	NR_STATS,
};

#endif /* __SCX_CONDUCTOR_H */

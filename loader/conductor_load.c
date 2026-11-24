/* SPDX-License-Identifier: GPL-2.0 */
/*
 * conductor_load - loads ONE scheduler, holds the struct_ops link, and exposes a
 * tiny line protocol so the governor needs no BPF bindings.
 *
 * Built twice from this one source:
 *   default      : the reference template (bpf/scx_conductor.bpf.c). Specialised
 *                  per workload through the rodata knobs below.
 *   -DGEN_BUILD  : a scheduler written on the device (scx_gen skeleton, ops
 *                  "gen_ops"). No knobs: the numbers are in the source. The loader
 *                  forces the safety-relevant ops fields itself (watchdog timeout,
 *                  flags) so generated source cannot choose them. The ops name
 *                  cannot be forced (not exposed by skeletons); see below.
 *
 *   stdin  (governor -> loader)        stdout (loader -> governor, JSON lines)
 *   set <tgid> <cls>                   {"event":"attached","name":"conductor"}
 *   clr <tgid>                         {"event":"verified","name":"conductor"}   (--verify-only)
 *   clrall                             {"event":"stats","stats":[..],"lat":[[..]..]}
 *   stats                              {"event":"error","msg":"..."}
 *   quit                               {"event":"exited","ecode":N,"kernel_ejected":B}
 *
 * --verify-only loads the scheduler (the kernel verifier runs, struct_ops is
 * validated) but never attaches it: nothing is scheduled by it, no other
 * scheduler is displaced. Exit 0 = the kernel accepted it.
 *
 * Unloading = this process exiting (SIGTERM, "quit", or stdin EOF). Closing the
 * struct_ops link makes the kernel fall back to the fair class. If the kernel
 * ejects the scheduler first (watchdog, error), we notice via UEI and exit 3.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include "conductor.h"

#ifdef GEN_BUILD
#include "scx_gen.bpf.skel.h"
#define SKEL_T		struct scx_gen
#define SKEL_NAME	scx_gen
#define OPS_NAME	gen_ops
#define SCHED_NAME	"conductor_gen"
#define SKEL_DESTROY(s)	scx_gen__destroy(s)
#else
#include "scx_conductor.bpf.skel.h"
#define SKEL_T		struct scx_conductor
#define SKEL_NAME	scx_conductor
#define OPS_NAME	conductor_ops
#define SCHED_NAME	"conductor"
#define SKEL_DESTROY(s)	scx_conductor__destroy(s)
#endif

/* One level of indirection so the macro arguments are expanded before the scx
 * macros paste them into identifiers. */
#define OPEN_(ops, name)		SCX_OPS_OPEN(ops, name)
#define LOAD_(skel, ops, name, uei)	SCX_OPS_LOAD(skel, ops, name, uei)
#define ATTACH_(skel, ops, name)	SCX_OPS_ATTACH(skel, ops, name)

#define GEN_TIMEOUT_DEFAULT_MS	5000

static volatile sig_atomic_t exit_req;

static void on_signal(int sig)
{
	(void)sig;
	exit_req = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static void parse_csv_u64(const char *s, __u64 out[NR_CLS])
{
	char *dup = strdup(s), *save = NULL, *tok;
	int i = 0;

	for (tok = strtok_r(dup, ",", &save); tok && i < NR_CLS;
	     tok = strtok_r(NULL, ",", &save))
		out[i++] = strtoull(tok, NULL, 10);
	free(dup);
	if (i != NR_CLS) {
		fprintf(stderr, "expected %d comma separated values: '%s'\n", NR_CLS, s);
		exit(2);
	}
}

static void emit_error(const char *msg)
{
	printf("{\"event\":\"error\",\"msg\":\"%s\"}\n", msg);
	fflush(stdout);
}

/* Sum a per-CPU array slot across all CPUs. */
static __u64 percpu_sum(int fd, __u32 key, int ncpu, __u64 *buf)
{
	__u64 sum = 0;
	int i;

	if (bpf_map_lookup_elem(fd, &key, buf))
		return 0;
	for (i = 0; i < ncpu; i++)
		sum += buf[i];
	return sum;
}

static void emit_stats(SKEL_T *skel)
{
	int ncpu = libbpf_num_possible_cpus();
	int sfd = bpf_map__fd(skel->maps.stats);
	int lfd = bpf_map__fd(skel->maps.lat_hist);
	__u64 *buf;
	int c, b, i;

	if (ncpu <= 0)
		return;
	buf = calloc(ncpu, sizeof(*buf));
	if (!buf)
		return;

	printf("{\"event\":\"stats\",\"stats\":[");
	for (i = 0; i < CND_NR_STATS; i++)
		printf("%s%llu", i ? "," : "",
		       (unsigned long long)percpu_sum(sfd, i, ncpu, buf));
	printf("],\"lat\":[");
	for (c = 0; c < NR_CLS; c++) {
		printf("%s[", c ? "," : "");
		for (b = 0; b < LAT_BUCKETS; b++)
			printf("%s%llu", b ? "," : "",
			       (unsigned long long)percpu_sum(lfd, c * LAT_BUCKETS + b,
							      ncpu, buf));
		printf("]");
	}
	printf("]}\n");
	fflush(stdout);
	free(buf);
}

static void handle_line(SKEL_T *skel, char *line)
{
	int fd = bpf_map__fd(skel->maps.tgid_class);
	unsigned int tgid, cls;
	__u32 key, next;

	if (sscanf(line, "set %u %u", &tgid, &cls) == 2) {
		__u8 v = cls & CLS_MASK;

		key = tgid;
		if (bpf_map_update_elem(fd, &key, &v, BPF_ANY))
			emit_error("map update failed");
	} else if (sscanf(line, "clr %u", &tgid) == 1) {
		key = tgid;
		bpf_map_delete_elem(fd, &key);	/* ENOENT is fine */
	} else if (!strncmp(line, "clrall", 6)) {
		int rc = bpf_map_get_next_key(fd, NULL, &next);

		while (!rc) {
			key = next;
			rc = bpf_map_get_next_key(fd, &key, &next);
			bpf_map_delete_elem(fd, &key);
		}
	} else if (!strncmp(line, "stats", 5)) {
		emit_stats(skel);
	} else if (!strncmp(line, "quit", 4)) {
		exit_req = 1;
	} else {
		emit_error("unknown command");
	}
}

int main(int argc, char **argv)
{
	SKEL_T *skel;
	struct bpf_link *link;
	__u64 slice[NR_CLS] = { 0 }, credit[NR_CLS] = { 0 }, charge[NR_CLS] = { 0 }, perf[NR_CLS] = { 0 };
	int have_slice = 0, have_credit = 0, have_charge = 0, have_perf = 0;
	int partial = 0, inject_stall = 0, timeout_ms = 0, verify_only = 0, opt;
#ifndef GEN_BUILD
	__u32 i;
#endif
	char inbuf[4096];
	size_t inlen = 0;
	long long ecode = 0;
	int kernel_ejected = 0;

	static const struct option longopts[] = {
		{ "slice-ns",   required_argument, 0, 's' },
		{ "credit-ns",  required_argument, 0, 'c' },
		{ "charge-pct", required_argument, 0, 'g' },
		{ "perf",       required_argument, 0, 'f' },
		{ "timeout-ms", required_argument, 0, 't' },
		{ "partial",    no_argument,       0, 'p' },
		{ "inject-stall", no_argument,     0, 'X' },
		{ "verify-only", no_argument,      0, 'V' },
		{ 0, 0, 0, 0 }
	};

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (opt) {
		case 's': parse_csv_u64(optarg, slice);  have_slice = 1;  break;
		case 'c': parse_csv_u64(optarg, credit); have_credit = 1; break;
		case 'g': parse_csv_u64(optarg, charge); have_charge = 1; break;
		case 'f': parse_csv_u64(optarg, perf);   have_perf = 1;   break;
		case 't': timeout_ms = atoi(optarg); break;
		case 'p': partial = 1; break;
		case 'X': inject_stall = 1; break;
		case 'V': verify_only = 1; break;
		default:
			fprintf(stderr, "usage: %s [--slice-ns a,b,c,d] [--credit-ns ..] "
				"[--charge-pct ..] [--perf ..] [--timeout-ms N] [--partial] "
				"[--verify-only]\n",
				argv[0]);
			return 2;
		}
	}

#ifdef GEN_BUILD
	/* Generated source has no knobs: numbers live in the source. Refuse knob
	 * flags rather than silently ignoring them. */
	if (have_slice || have_credit || have_charge || have_perf || inject_stall) {
		fprintf(stderr, "knob flags are not supported for a generated scheduler\n");
		return 2;
	}
#endif

	skel = OPEN_(OPS_NAME, SKEL_NAME);

#ifdef GEN_BUILD
	/* The safety-relevant fields are the loader's, not the source's. */
	if (timeout_ms <= 0)
		timeout_ms = GEN_TIMEOUT_DEFAULT_MS;
	skel->struct_ops.OPS_NAME->flags = 0;
	/* The ops name is a char array the skeleton does not expose, so it cannot be
	 * forced here: the static gate pins it in the source and the lifecycle checks
	 * /sys/kernel/sched_ext/root/ops after attach. */
#else
	/* Specialise: rodata is frozen at load, so the verifier sees constants. */
	for (i = 0; i < NR_CLS; i++) {
		if (have_slice)  skel->rodata->slice_ns[i] = slice[i];
		if (have_credit) skel->rodata->credit_ns[i] = credit[i];
		if (have_charge) skel->rodata->charge_pct[i] = (__u32)charge[i];
		if (have_perf)   skel->rodata->perf_target[i] = (__u32)perf[i];
	}
	skel->rodata->inject_stall = inject_stall;
#endif

	if (timeout_ms > 0)
		skel->struct_ops.OPS_NAME->timeout_ms = timeout_ms;
	if (partial)
		skel->struct_ops.OPS_NAME->flags |= SCX_OPS_SWITCH_PARTIAL;

	/* Loading runs the kernel verifier and validates the struct_ops map. */
	LOAD_(skel, OPS_NAME, SKEL_NAME, uei);

	if (verify_only) {
		printf("{\"event\":\"verified\",\"name\":\"%s\"}\n", SCHED_NAME);
		fflush(stdout);
		SKEL_DESTROY(skel);
		return 0;
	}

	link = ATTACH_(skel, OPS_NAME, SKEL_NAME);

	printf("{\"event\":\"attached\",\"name\":\"%s\",\"partial\":%d}\n", SCHED_NAME, partial);
	fflush(stdout);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
		int r = poll(&pfd, 1, 200);

		if (r > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
			ssize_t n = read(STDIN_FILENO, inbuf + inlen, sizeof(inbuf) - 1 - inlen);
			char *nl;

			if (n <= 0)
				break;		/* governor went away: unload ourselves */
			inlen += n;
			inbuf[inlen] = '\0';
			while ((nl = strchr(inbuf, '\n'))) {
				*nl = '\0';
				handle_line(skel, inbuf);
				inlen -= (nl + 1) - inbuf;
				memmove(inbuf, nl + 1, inlen + 1);
			}
			if (inlen >= sizeof(inbuf) - 1)
				inlen = 0;	/* overlong garbage line: drop it */
		}
	}

	kernel_ejected = UEI_EXITED(skel, uei) ? 1 : 0;
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	printf("{\"event\":\"exited\",\"ecode\":%lld,\"kernel_ejected\":%d}\n", ecode, kernel_ejected);
	fflush(stdout);
	SKEL_DESTROY(skel);
	return kernel_ejected ? 3 : 0;
}

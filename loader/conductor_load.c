/* SPDX-License-Identifier: GPL-2.0 */
/*
 * conductor_load - loads ONE specialised instance of the scx_conductor
 * template, holds the struct_ops link, and exposes a tiny line protocol so the
 * governor needs no BPF bindings.
 *
 *   stdin  (governor -> loader)        stdout (loader -> governor, JSON lines)
 *   set <tgid> <cls>                   {"event":"attached","name":"conductor"}
 *   clr <tgid>                         {"event":"stats","stats":[..],"lat":[[..]..]}
 *   clrall                             {"event":"error","msg":"..."}
 *   stats                              {"event":"exited","ecode":N,"kernel_ejected":B}
 *   quit
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
#include "scx_conductor.bpf.skel.h"
#include "conductor.h"

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

static void emit_stats(struct scx_conductor *skel)
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
	for (i = 0; i < NR_STATS; i++)
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

static void handle_line(struct scx_conductor *skel, char *line)
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
	struct scx_conductor *skel;
	struct bpf_link *link;
	__u64 slice[NR_CLS] = { 0 }, credit[NR_CLS] = { 0 }, charge[NR_CLS] = { 0 }, perf[NR_CLS] = { 0 };
	int have_slice = 0, have_credit = 0, have_charge = 0, have_perf = 0;
	int partial = 0, inject_stall = 0, timeout_ms = 0, opt, i;
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
		default:
			fprintf(stderr, "usage: %s [--slice-ns a,b,c,d] [--credit-ns ..] "
				"[--charge-pct ..] [--perf ..] [--timeout-ms N] [--partial]\n",
				argv[0]);
			return 2;
		}
	}

	skel = SCX_OPS_OPEN(conductor_ops, scx_conductor);

	/* Specialise: rodata is frozen at load, so the verifier sees constants. */
	for (i = 0; i < NR_CLS; i++) {
		if (have_slice)  skel->rodata->slice_ns[i] = slice[i];
		if (have_credit) skel->rodata->credit_ns[i] = credit[i];
		if (have_charge) skel->rodata->charge_pct[i] = (__u32)charge[i];
		if (have_perf)   skel->rodata->perf_target[i] = (__u32)perf[i];
	}
	skel->rodata->inject_stall = inject_stall;

	if (timeout_ms > 0)
		skel->struct_ops.conductor_ops->timeout_ms = timeout_ms;
	if (partial)
		skel->struct_ops.conductor_ops->flags |= SCX_OPS_SWITCH_PARTIAL;

	SCX_OPS_LOAD(skel, conductor_ops, scx_conductor, uei);
	link = SCX_OPS_ATTACH(skel, conductor_ops, scx_conductor);

	printf("{\"event\":\"attached\",\"name\":\"conductor\",\"partial\":%d}\n", partial);
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
	scx_conductor__destroy(skel);
	return kernel_ejected ? 3 : 0;
}

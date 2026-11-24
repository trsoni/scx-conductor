# scx-conductor

Workload-adaptive CPU scheduling for Linux, using [sched_ext](https://docs.kernel.org/scheduler/sched-ext.html).
A small governor watches what the machine is doing (game, UI, browser, video, camera,
graphics, agentic/CPU-heavy work, batch), **specialises a reviewed BPF scheduler template for that
workload** (or, opt-in, has a model write a new scheduler on the device for an operator to approve), verifies it,
canaries it, hot-loads it, watches for regressions, and unloads it again when the workload goes away. The same code targets **x86_64 and arm64** and is meant to be tested under **QEMU**.

The idea is borrowed from OpenAI and Cisco's [Shirudo](https://openai.com/index/introducing-shirudo/)
(announced 2026-11-23): Shirudo loads small, signed, tested eBPF "shields" into a running Linux system to block
exploits while a patch is prepared. Here the live-loaded eBPF object is a *scheduler* and the trigger is a
*workload*, not a vulnerability. See [`docs/diagrams/shirudo-mapping.svg`](docs/diagrams/shirudo-mapping.svg).

![architecture](docs/diagrams/architecture.svg)

## Read this first: what has and has not been verified

The authoring sandbox had clang, bpftool and libbpf (hand-built, with a libelf shim) and **no QEMU and no
sched_ext kernel**. So everything up to the kernel is exercised, and nothing has been loaded into a kernel.

| Part | Status |
|---|---|
| Governor logic (classifier, policy, forge, verifier, lifecycle, audit, control socket) and the whole generation pipeline's Python | **Run:** 211 unit tests pass (Python 3.12, x86_64); the daemon dry-run with `FakeHost` ran clean and its audit chain verifies |
| Ed25519 signing / verification via `openssl` CLI | **Run** (part of the tests) |
| `bpf/scx_conductor.bpf.c` and `loader/conductor_load.c` | **Compiled and linked** on x86_64 against real scx and libbpf headers (clean with `-Wall`); the arm64 BPF object compiles; the arm64 loader was not linked |
| On-device generation, end to end up to the kernel verifier | **Run** with the template backend: static gate, clang, object checks, bpftool skeleton, loader link, `gen_load --verify-only` executed; it stops at the verifier because the sandbox kernel has no sched_ext |
| Loading any scheduler into a kernel; the kernel verifier's verdict; canary; watchdog ejection | **Not run.** `docs/LAPTOP.md` is the procedure to do it on a laptop |
| A real model backend (Anthropic API, `claude -p`) | **Never called.** Tested with scripted fake backends |
| QEMU x86_64 / arm64 boot and in-guest tests | **Not run.** Scripts exist; `docs/REPRODUCE.md` is the procedure. In-guest scripts are syntax-checked only |
| Diagrams | **Rendered and visually checked** |
| Any performance or power result | **None exist.** Profile values are untuned priors (`profiles/profiles.json`) |

Treat the first run on a sched_ext kernel as the real test. [`docs/TESTING.md`](docs/TESTING.md) lists every stage, what
it asserts, and what a failure there most likely means.

## Two ways schedulers appear "on the fly"

1. **Specialise (default, no compiler on the device).** The governor writes the `const volatile` knobs of one reviewed
   template (`bpf/scx_conductor.bpf.c`) into `.rodata` before load, so each profile is a genuinely different loaded
   program, produced in milliseconds. Manifests are signed and verified.
2. **Generate (opt-in, laptop / mobile / VM).** Like Shirudo's agents, a model **writes the scheduler's C source on the
   device** from a numbers-only prompt. The source goes through a static gate, clang, the kernel BPF verifier and a
   canary; it then waits as `pending` until an operator approves it (`conductord gen-approve`), and only then can the
   governor load it, under a signed manifest that pins every digest. Anything that fails falls back to path 1.
   Start here: [`docs/LAPTOP.md`](docs/LAPTOP.md). Design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) section 3b.
   Threat discussion, including what it does **not** establish: [`docs/SAFETY.md`](docs/SAFETY.md).

![generation pipeline](docs/diagrams/generation-pipeline.svg)

## Layout

```
bpf/            scx_conductor.bpf.c (reference scheduler), conductor_abi.bpf.h (maps + helpers every scheduler shares), conductor.h
loader/         conductor_load.c: loads one instance (also built as the generated-scheduler loader), line protocol on stdin/stdout
conductord/     governor (Python, stdlib only): signals, classifier, policy, forge, lifecycle, audit, daemon;
                generation: generator, genbackends, genstatic, genbuild, genstore
profiles/       profiles.json: workload x platform x power-state priors (UNTUNED)
tests/          unit tests (run anywhere), tests/guest/ = in-kernel tests (run inside QEMU)
tools/qemu/     build-kernel.sh, make-rootfs.sh, run-qemu.sh, guest-init.sh, kernel.config
tools/          fetch-scx-include.sh, probe-scx-abi.sh (scx header ABI probe)
tools/workloads latency probe, synthetic apps for classifier tests
docs/           LAPTOP, ARCHITECTURE, REPRODUCE, SAFETY, PLATFORMS, TESTING + diagrams (SVG + generator)
memory/         project memory files for future sessions (context, decisions, tuning log, test log)
packaging/      systemd unit
```

## Quick start

Anywhere (no kernel needed): run the logic tests and a dry-run daemon.

```bash
python3 -m unittest discover -s tests            # 211 tests (2 opt-in need a toolchain)
python3 -m conductord run --platform vm --dev-self-sign --dry-run \
    --state /tmp/cstate --sock /tmp/cstate/ctl.sock --bpf-obj <any-file> --duration 10
python3 -m conductord ctl hold gaming --sock /tmp/cstate/ctl.sock
```

On a laptop with a sched_ext kernel (including on-device generation): [`docs/LAPTOP.md`](docs/LAPTOP.md).
x86_64 and arm64 under QEMU: [`docs/REPRODUCE.md`](docs/REPRODUCE.md).

```bash
python3 -m conductord doctor                      # can this machine build, verify and load generated schedulers?
python3 -m conductord gen --workload gaming --gen-backend template --print-prompt   # what a backend would receive
```

## Licensing note

The BPF program and loader are `GPL-2.0` (required to use sched_ext kfuncs). **No licence has been chosen for the
rest of the repository**; add one before publishing.

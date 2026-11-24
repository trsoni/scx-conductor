# Safety model

Loading a scheduler into a running kernel is powerful and can make a machine unusable. This design leans on
mechanisms that already exist in the kernel and adds checks before and after the load.

## What the kernel gives us (sched_ext)

From the kernel.org sched_ext documentation: terminating the scheduler program, SysRq-S, or detecting an internal
error including stalled runnable tasks aborts the BPF scheduler and reverts all tasks to the fair class. The BPF
verifier checks the program. With `SCX_OPS_SWITCH_PARTIAL` only `SCHED_EXT` tasks are scheduled by sched_ext, so a
canary cannot affect the rest of the system.

## What this project adds

| Control | Where | Failure it addresses |
|---|---|---|
| Signed manifest, fail-closed verifier (signature, BPF digest, platform, arch, TTL, bounds) | `forge.py` | tampered or stale parameters, wrong-device manifest, swapped BPF object |
| Hard parameter bounds (slice 0.5-50 ms, charge 10-1000 %, perf <= 1024, timeout 0.1-30 s), re-checked by the verifier even for signed manifests | `policy.py` | a buggy forge or profile producing a pathological scheduler |
| Canary in partial mode with a latency probe | `canary.py` | a scheduler that loads but misbehaves on this hardware |
| Watchdog `timeout_ms` per platform (automotive 1 s) | profiles | stalls: the kernel ejects, the governor quarantines |
| PSI + FG/MEDIA latency-tail guard, rollback, 300 s quarantine | `lifecycle.py` | a scheduler that is valid but makes the workload worse |
| One shared vtime DSQ | BPF template | starvation by construction |
| Loader process owns the link; governor crash or `SIGTERM` closes it | `host.py`, `daemon.py` | governor death leaving a custom scheduler without supervision |
| Governor `finally:` unload; exception in the loop unloads | `daemon.py` | software faults in the policy layer |
| Hash-chained audit log, optional TPM PCR extend | `audit.py` | "what was loaded, when, and why" after the fact |
| `approved_only` platforms never sign or generate on the device | profiles | on-device key exposure for iot / automotive |
| Static gate on model-written C: ASCII, size cap, include / directive / helper / kfunc / ops-member allowlists, no asm, extern, `SEC`, `__attribute__`, `##`, pointer-cast tricks | `genstatic.py` | the model reaching for kernel facilities a scheduler does not need, or hiding a construct from review |
| Compiled-object check: allowed ELF sections only, static data <= 1 MiB, exactly the four ABI maps | `genstatic.py` | extra programs, probes or maps smuggled in through the compiler |
| Kernel verifier via `gen_load --verify-only` (load, never attach) | `host.py`, loader | memory-unsafe or non-terminating code, found before anything is registered |
| Generated-scheduler canary adds a starvation check (each CPU hog >= 10 % of a CPU) and a telemetry check (latency histogram must fill) | `canary.py` | a scheduler that starves a task for seconds before the watchdog fires, or one that hides its own latency |
| Operator approval: `gen-approve` signs an `approval.json` over the digests; the signed manifest pins that file's digest | `genstore.py`, `forge.py` | any model output running without a human having read it |
| Manifest pins object, loader, source and approval digests, architecture, kernel release and the ops name `conductor_gen`; sysfs must report that name after load | `forge.py`, `lifecycle.py` | swapped or edited artifact, artifact built for another kernel, wrong program loaded |
| Prompt carries numbers and three repository files only | `generator.py` | process names, paths or user data leaving the device; attacker-controlled text steering the model |
| Compile limits (`prlimit`) and optional unprivileged compile user (`--gen-sandbox-user`) | `genbuild.py` | clang resource exhaustion or a compiler bug on untrusted text |
| Generation is opt-in (`--gen-backend`), on-demand generation is a second opt-in, and `--gen-approval auto` is lab-only and warns | `__main__.py` | silent off-device prompts or unreviewed loads |
| Automotive allow-list (ui, video, camera, graphics) | profiles | agentic / batch inference tuning on a vehicle network |

## Explicitly not claimed

- **No safety certification.** Nothing here is qualified for ISO 26262, IEC 61508 or similar. Do not run it on
  safety-relevant partitions. The automotive profile exists to describe a conservative posture for infotainment-class
  workloads.
- **No performance or power claims.** There are no measurements yet.
- **On-device signing is not a security boundary.** With `--dev-self-sign`, anything with root can mint a manifest.
- **The BPF object is trusted by digest, not analysed.** The signing process (review + CI) is where trust lives.
- **PCR 16** is a debug PCR and not a production attestation policy.
- **The classifier can be fooled** by a process that renames itself (the `comm` rules) or opens device nodes.
  Mitigations are the debounce, the bounded parameter space (a wrong class cannot starve anything), and the hint
  channel for trusted platform services. A hostile local user can at worst move their own processes between classes
  the template already bounds; `tgid_class` is written only by the root-owned loader.

## Generating schedulers on the device with an AI agent

Shirudo's published design has agents (e.g. Codex) generate and validate shields, with a person approving
deployment. The same loop is implemented here for schedulers (`docs/diagrams/generation-pipeline.svg`):

1. a backend (Anthropic API, a local command such as `claude -p`, or the deterministic `template` used by tests) writes
   one C file from a numbers-only prompt;
2. the static gate, clang, the object check and the **kernel verifier** examine it, and errors go back to the model
   for up to three attempts;
3. an early canary runs it in partial mode when no other sched_ext scheduler is attached;
4. it is stored as `pending`. **Nothing pending is ever loaded.** The operator reads `review.md` and the diff against
   the reference scheduler, then runs `gen-approve`, which signs the digests;
5. the governor builds a per-power-state signed manifest for the approved artifact, the Verifier checks everything again
   at load time, and the lifecycle runs the stricter canary, loads, confirms the kernel reports `conductor_gen`,
   guards, and on any problem quarantines it and falls back to the reference template.

Platforms with `approved_only` (iot, automotive) never generate on the device and never load generated artifacts.
Running this pipeline on a forge host and shipping the signed result to such a device is a natural extension that is
**not implemented** (`forge-approved` emits template manifests only); see `memory/open-questions.md`.

### What this does and does not establish

- **The kernel verifier is the security boundary** for memory safety and termination. The static gate is a
  defence-in-depth filter on text and is **not** a sandbox: it has been tested against hostile inputs written by the
  author (inline asm spellings, trigraphs, digraphs, line continuations, macro-built includes), not fuzzed.
- **Operator review is the second boundary.** A scheduler that is verifier-clean can still be unfair, slow, or wrong
  about which CPU to pick; the canary and runtime guard catch gross cases only. A reviewer who approves without
  reading defeats the design, which is why `--gen-approval auto` exists only as a loud lab switch.
- A scheduler observes scheduling activity of every task on the machine. It already runs as root with that
  visibility; nothing here limits what a generated scheduler can infer, and the sched_ext kfunc allowlist is what keeps
  it from doing more than schedule.
- clang parses text that came from a model. The gate removes the usual compile-time routes (arbitrary `#include`,
  `#pragma`, token pasting), `prlimit` bounds resources, and `--gen-sandbox-user` drops privileges; a compiler bug is
  still a residual risk.
- Prompt injection has little to inject into: the prompt contains no text controlled by a local process or user. The
  returned code is treated as untrusted regardless.
- The on-device key signs approvals and manifests, so root on the device can approve anything. This is a development
  arrangement; for anything exposed, approve on a separate machine and ship the signed artifact.

### Not yet verified

- `--verify-only` relies on libbpf's struct_ops link semantics (load validates, attach registers). That is assumed,
  not observed: the authoring sandbox kernel has no sched_ext. The first run on a real kernel decides it.
- No real model backend has been called; the repair loop is tested with a scripted fake.
- No generated scheduler has been loaded into a kernel or measured.

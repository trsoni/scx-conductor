# Architecture

![architecture](diagrams/architecture.svg)

## 1. Data flow

1. **Collector** (`conductord/signals.py`) reads `/proc` (per-process CPU, comm, fd targets), `/proc/pressure/cpu`
   (PSI), fork rate, power-supply and thermal sysfs, GPU busy percent, and an optional hint file. Roots are
   injectable, so tests use a fake procfs.
2. **Classifier** (`classifier.py`) is rule-based and explainable: process names, fd tags (`/dev/dri`, `/dev/video*`,
   `/dev/media*`, `/dev/snd`, `/dev/dma_heap`), GPU load, fork rate, PSI. It returns a workload, a score, the evidence,
   and a per-process class map (`FG`, `MEDIA`, `BG`; everything else is `NORMAL`). A **hint** (from a platform
   service or `conductord ctl hint`) overrides inference.
3. **Debouncer** adds hysteresis: a candidate must win N ticks and the current workload must have held a minimum
   dwell, except a strong (score >= 0.9) launch out of idle/UI, which switches immediately.
4. **Policy** (`policy.py`) maps `(workload, platform, power state)` to bounded `Params`: slice, sleeper credit,
   vtime charge and cpuperf hint per class, plus the watchdog timeout. Power states: `ac`, `battery`,
   `low_battery` (<= 20 %), `thermal` (over the platform limit). `idle` means "no custom scheduler".
5. **Forge** (`forge.py`) wraps the params in a manifest (template digest, platform, arch, kernel_min, TTL) and signs it
   with Ed25519 via the `openssl` CLI. Manifests are cached per key for half their TTL; see `memory/decisions.md`
   for why that matters.
6. **Verifier** is fail-closed: signature, BPF object digest, platform, arch, expiry, clock skew, parameter bounds.
7. **Lifecycle** (`lifecycle.py`) runs canary -> load -> sysfs check -> class sync -> guard, with rollback and
   quarantine. See the state machine below.
8. **conductor_load** (`loader/conductor_load.c`) owns one loaded scheduler. It sets `.rodata` knobs, loads, attaches the
   struct_ops link and serves a line protocol: `set <tgid> <cls>`, `clr <tgid>`, `clrall`, `stats`, `quit`.
   Exiting is unloading.
9. **AuditLog** (`audit.py`): append-only, hash-chained JSONL; the head hash is extended into a TPM PCR when
   `/dev/tpmrm0` and `tpm2_pcrextend` exist.

![sequence](diagrams/sequence-switch.svg)

## 2. The BPF scheduler (`bpf/scx_conductor.bpf.c`)

Deliberately conservative, derived from the shape of `scx_simple`:

- **One shared vtime-ordered DSQ.** Every runnable task sits in one queue ordered by virtual time, so no class can
  be starved, whatever the knobs say.
- **Class-scaled vtime charge** (`charge_pct`): FG/MEDIA are charged less per ns run and so get more CPU share; BG is
  charged more.
- **Class-scaled sleeper credit** (`credit_ns`): how far behind `vtime_now` a long sleeper may start, i.e. the
  wake-up latency boost.
- **Class-scaled slice** (`slice_ns`): short where latency matters, long where throughput or power matters.
- **cpuperf hint** (`perf_target`): `scx_bpf_cpuperf_set()` per class; `0` means leave frequency alone.
- **Latency histogram** per class (enqueue to run, log2 microsecond buckets): the SLO signal the governor reads.
- **`inject_stall`** exists only so the QEMU suite can prove the kernel watchdog ejects a stalling scheduler.

Idle CPUs are used directly in `select_cpu` via `scx_bpf_select_cpu_dfl`, as in `scx_simple`.

## 3. Lifecycle

![lifecycle](diagrams/lifecycle-states.svg)

- **Canary** loads the scheduler with `SCX_OPS_SWITCH_PARTIAL`: only tasks that opt into `SCHED_EXT` use it, everything
  else stays on the fair class. A probe process (`tools/workloads/lat_probe.py --ext`) with CPU hogs measures p99
  wake-up latency; above `canary_p99_us` the manifest is quarantined and never fully loaded.
- **Guard** (every tick): loader liveness, PSI regression (`psi_some10` over baseline + 25 or the 40 floor for 10
  ticks), and every 5th tick the FG/MEDIA latency tail (>= 5 % of samples in bucket >= 13, i.e. around >= 8 ms,
  three checks in a row). Any breach unloads and quarantines for 300 s.
- **Kernel watchdog**: `timeout_ms` is passed to sched_ext. A stalled runnable task makes the kernel abort the BPF
  scheduler and revert tasks to the fair class on its own; the loader sees it (UEI exit), exits 3, and the lifecycle
  quarantines the manifest.
- **Switching** always unloads the old scheduler before verifying and loading the next one.

## 3b. On-device generation

![generation pipeline](diagrams/generation-pipeline.svg)

Beyond specialising the reference template, an agent can **write a whole new scheduler** (C source) for a workload on
the device. The pipeline is Shirudo's loop: the model writes, deterministic tools check, the kernel verifier proves
memory safety, a person approves, only a signed record loads. Walkthrough: `docs/LAPTOP.md`; threat discussion:
`docs/SAFETY.md`.

| Piece | File | Role |
|---|---|---|
| ABI header | `bpf/conductor_abi.bpf.h` | the maps (`tgid_class`, `stats`, `lat_hist`, task storage), `UEI_DEFINE`, licence and helpers every scheduler shares, so the governor's telemetry and class sync work for any generated scheduler. Wraps `scx_bpf_dsq_move_to_local` (1 or 2 arguments depending on scx version, chosen by `tools/probe-scx-abi.sh`) |
| Prompt + repair loop | `generator.py` | numbers-only context, system prompt with the hard rules, up to N attempts with the gate / compiler / verifier error as feedback; `GenManager` runs one background request at a time with cooldowns |
| Backends | `genbackends.py` | `anthropic` (stdlib HTTPS; key from env or a 0600 file), `command` (stdin -> stdout), `template` (deterministic, tests), `callable` (tests) |
| Static gate | `genstatic.py` | text rules and allowlists on the source, ELF section / map checks on the object |
| Build | `genbuild.py` | clang `-target bpf`, `bpftool gen skeleton`, `cc` the generic loader with `-DGEN_BUILD`; `vmlinux.h` generated from the running kernel's BTF and cached per release |
| Loader | `loader/conductor_load.c` | the same file, built with `GEN_BUILD`: no knob flags, `--verify-only` (load without attach), partial flag, fixed watchdog |
| Store | `genstore.py` | `<state>/generated/<id>/` holds `source.bpf.c`, `sched.bpf.o`, `gen_load`, `meta.json`, `review.md`, `build.log`, `approval.json`; `GenForge` mints a per-power-state signed manifest for an approved artifact |
| Selection | `daemon.py` | `Governor` prefers an approved, kernel-matching, verifiable generated manifest and otherwise uses the template; `--gen-on-demand` asks the backend when a workload has none |

Rules worth knowing:

- An artifact id is `sha256(source)[:12]` and is valid only for one `(workload, platform, arch, kernel release)`.
  Statuses: `building`, `failed`, `pending`, `approved`, `rejected`.
- The manifest has `template: scx_gen`, `template_sha256` = the object digest, plus `loader_sha256`, `source_sha256`,
  `approval_sha256`, `ops_name: conductor_gen` and `kernel_release`. The Verifier re-hashes the files and checks the
  approval signature on every load; the lifecycle then requires sysfs to report `conductor_gen`.
- A host factory picks the loader per manifest: the template loader for reference manifests, the artifact's own
  `gen_load` for generated ones. A lifecycle lock stops the generator's early canary and the governor attaching at the
  same time (only one sched_ext scheduler can be attached at once, so the early canary reports "skipped" when the slot is
  taken).
- Generated schedulers get a stricter canary: each CPU hog must receive at least 10 % of a CPU and the latency
  histogram must receive at least 20 samples.
- Failure at any step falls back to the reference template for that workload; a kernel ejection or SLO rollback
  quarantines the generated manifest for `slo.quarantine_s`.

## 4. Why these choices

See `memory/decisions.md`. In one line each: one DSQ for starvation-freedom; rodata specialisation as the default
path so the device needs no compiler and the reviewed object digest never changes, with source generation as an opt-in
second path that needs a toolchain and a human; Python governor because policy changes often and the hot path
(scheduling) is in the kernel; a separate loader process so a governor crash closes the link and falls back to the stock
scheduler.

## 5. What is not implemented

- Topology awareness (big.LITTLE / hybrid x86 / NUMA placement). `perf_target` is the only power lever.
- Per-thread classification: classes are per process (tgid).
- Feeding runtime telemetry (latency histograms, guard events) back into generation prompts. The prompt holds baseline
  parameters and device facts only.
- Generated artifacts on `approved_only` platforms: `forge-approved` emits template manifests only.
- More than one scheduler in flight: sched_ext attaches one at a time, so a "scheduler per app" design would need a
  multiplexing scheduler or cgroup-scoped scheduling, neither of which exists here.
- Platform hint producers (Android top-app, automotive HMI, desktop shell): the interface is `hint.json` /
  `conductord ctl hint`; no producer ships here.

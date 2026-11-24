# Platforms and workloads

One governor, five profile sets (`profiles/profiles.json`, schema 1). Every number below is an **untuned prior**:
none has been measured on hardware. Tune per device and record results in `memory/workload-profiles.md`.

## Platform profiles

| Platform | Manifests | Canary | Watchdog | Notes |
|---|---|---|---|---|
| `laptop` | generated on device (dev key) or approved | yes, 3 s | 5 s | AC / battery / low-battery / thermal states (thermal limit 90 C) |
| `mobile` | generated on device or approved | yes, 2 s | 3 s | tighter battery caps; thermal limit 80 C |
| `iot` | **approved only** | no | 8 s | long slices (x2 to x4), low perf caps, thermal limit 85 C |
| `automotive` | **approved only** | yes, 3 s | 1 s | allow-list: `ui`, `video`, `camera`, `graphics`; thermal limit 95 C |
| `vm` | generated on device | yes, 2 s | 2 s | QEMU / CI target |

Detection order (`policy.detect_platform`): `--platform`, `CONDUCTOR_PLATFORM`, `/etc/conductor/platform`, Android
`build.prop` (mobile), hypervisor flag (vm), DMI chassis type or a battery (laptop), else `iot` on ARM and `laptop` on
x86. **Set it explicitly on products**; automotive is never guessed.

Power state selects `perf_cap` (upper bound for the cpuperf hint) and `slice_scale` (longer slices off AC, so fewer
context switches per unit of work).

## Workload classes

| Workload | Typical trigger | FG | MEDIA | BG |
|---|---|---|---|---|
| `ui` | interactive default (shell, compositor active) | shell, compositor | audio server | agents, builds |
| `browser` | browser processes >= 10 % CPU | browser | audio | agents, builds |
| `gaming` | game launcher / engine names, or DRM fds + high GPU busy | game, shell | audio | builds, agents |
| `video` | player / ffmpeg / codec services | shell | player, codec, dmabuf users | builds |
| `camera` | `/dev/video*` or `/dev/media*` fds, camera server names | shell | camera / ISP pipeline | builds |
| `graphics` | DCC / benchmark names, high GPU busy | app | audio | builds |
| `agentic` | agent / local-LLM names, high fork rate | the agent | audio | (no demotion: throughput) |
| `batch` | compilers, high PSI at high utilisation | all treated alike | | |
| `idle` | < 3 % utilisation and nothing recognised | stock scheduler | | |

Classes are per process (tgid). The scheduler trades only *share* (vtime charge), *wake-up latency* (sleeper
credit), *slice length* and a *frequency hint*; none of them can starve a class.

## Per-platform notes

**Laptop / desktop.** The best-understood case. Provide game/launcher knowledge by adding names to the lists at the top
of `classifier.py`, or send hints from a desktop-environment helper (`conductord ctl hint gaming --pids ...`).

**Mobile.** Requires a kernel built with sched_ext; whether a given vendor or GKI kernel enables it was not checked.
The natural hint producer is the platform's "top-app" signal feeding `hint.json`; none ships here. `cpuperf` only matters
if the cpufreq driver and governor consume it (typically schedutil); there is no effect on QEMU.

**IoT.** Use approved-only manifests, no on-device generation, no canary (nothing to probe on headless devices), and
long slices. This is the profile family where the benefit is mostly fewer wake-ups and context switches, which is a
hypothesis to measure.

**Automotive.** Infotainment-class workloads only (see `docs/SAFETY.md`: no safety qualification). Shortest watchdog
(1 s) so a stalled scheduler is ejected quickly; agentic and batch tuning are not allowed (they resolve to the stock
scheduler). Use dedicated, separately-signed manifests per ECU image and architecture.

## Heterogeneous CPUs

Not handled yet: big.LITTLE, hybrid x86 and NUMA are not considered in placement. `scx_bpf_cpuperf_set` is the only
power lever. A topology-aware version would classify CPUs by capacity at load time and steer `MEDIA` and `BG` to
efficiency cores; it is listed in `memory/open-questions.md`.

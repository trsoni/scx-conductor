# Testing

## Layers

| Layer | Needs | Command | Status when authored |
|---|---|---|---|
| Unit (classifier, debouncer, policy, forge/verifier, lifecycle, governor, audit, signals) | python3 + openssl | `python3 -m unittest discover -s tests` | **62 pass** (x86_64, Python 3.12) |
| Dry-run daemon | python3 + openssl | see README quick start | **ran clean**; audit chain verified |
| Build (BPF + loader) | clang, libbpf, bpftool, scx headers | `make` | **not run** |
| In-kernel stages | root + sched_ext kernel | `bash tests/guest/run_all.sh` | **not run** |
| QEMU x86_64, arm64 | QEMU, kernel, rootfs | `tools/qemu/run-qemu.sh <arch>` | **not run** |

## In-guest stages (`tests/guest/run_all.sh`)

| Stage | Asserts | If it fails, look at |
|---|---|---|
| `env` | `/sys/kernel/sched_ext`, BTF, PSI exist | kernel config (`tools/qemu/kernel.config`) |
| `build` | `make` produces `conductor_load` and `scx_conductor.bpf.o` | **most likely first failure**: kfunc/enum names vs the scx headers of your kernel, `bpftool gen skeleton`, libbpf version |
| `unit` | same unit tests inside the guest (architecture independence) | Python / openssl in the rootfs |
| `loader` | attaches; sysfs shows `enabled` and ops `conductor`; stats and latency histogram populated; clean exit; sysfs back to `disabled` | BPF verifier log in the loader's stderr |
| `watchdog` | `--inject-stall` + a `SCHED_EXT` victim: kernel ejects within ~10 s, loader exits 3, sysfs `disabled` | `timeout_ms` handling, partial mode |
| `ab-latency` | probe marked FG under hogs stays within 50 ms p99; FG-class counters move; prints baseline vs conductor | QEMU timing is noisy: **do not read performance from this stage** |
| `governor` | pinned hold gaming -> camera -> rollback against the real kernel; a synthetic `steam` process causes a gaming scheduler to load; its exit replaces/unloads it; audit chain verifies and contains `canary-result`, `load`, `unload`; no `load-failed`, `ejected`, `governor-error` | `governor.log` in the stage output; `audit.jsonl` |

Results: stdout per stage, `build/guest-result.json` (arch, kernel, pass/fail/skip lists), and for QEMU
`build/qemu-<arch>.log`. Skip slow stages with `skip-ab`, `skip-e2e`.

## What a green run proves, and what it does not

Proves: the template compiles and passes the verifier on both architectures; load, unload, watchdog ejection and
rollback paths work on a real sched_ext kernel; the governor's decisions reach the kernel.

Does not prove: that any profile is faster or more power-efficient (QEMU has no meaningful frequency or power model
and TCG distorts timing), that classification is right for real applications, or anything about vendor kernels.

## Measuring benefit (the actual open work)

On real hardware, per profile: run the workload with the stock scheduler and with the conductor, compare
frame-time percentiles (games), input-to-photon latency (UI), dropped frames (video / camera), tail latency of
tool calls (agentic), and package energy (RAPL / battery gauges / on-board power rails). Record in
`memory/workload-profiles.md` with the kernel version, hardware and commit.

## Known test gaps

- fd-tag classification is tested with a fake procfs; no test opens a real `/dev/video*` (QEMU has none).
- No fuzzing of the loader's stdin protocol beyond "unknown command".
- Thermal and battery paths are covered by unit tests only.
- TPM extend path is untested (needs swtpm).

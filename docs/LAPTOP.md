# Trying on-device generation on a laptop

> **Status.** The pipeline up to the kernel verifier was run on x86_64 against real scx and libbpf headers in the
> authoring sandbox (see `memory/test-log.md`). That sandbox kernel has no sched_ext, so **nothing here has been
> loaded into a running kernel by the author**. This page is the procedure for doing that first load. Record what
> happens in `memory/test-log.md`.

What you will do: have a backend write a scheduler for one workload, watch it get gated, built and checked by your
kernel's BPF verifier, approve it yourself, and let the governor load and unload it live.
Diagram: [`diagrams/generation-pipeline.svg`](diagrams/generation-pipeline.svg).

## 0. Is this laptop eligible?

```bash
uname -r                                          # sched_ext is in mainline since 6.12
ls /sys/kernel/sched_ext                          # must exist (CONFIG_SCHED_CLASS_EXT=y)
ls /sys/kernel/btf/vmlinux                        # must exist (CONFIG_DEBUG_INFO_BTF=y)
cat /proc/pressure/cpu                            # PSI, used by the guard
cat /sys/kernel/sched_ext/state                   # "disabled" = no sched_ext scheduler is running
```

If `/sys/kernel/sched_ext` is missing, your kernel was built without sched_ext: use a kernel that has it, or the
QEMU route in `docs/REPRODUCE.md`. Only one sched_ext scheduler can be attached at a time: **stop `scx_*` services
(scx_loader, scx_lavd, ...) before testing.**

## 1. Install the toolchain

Typical package names (not verified by the author):

```bash
# Debian / Ubuntu
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev libzstd-dev bpftool python3 openssl make gcc git
# Fedora
sudo dnf install clang llvm libbpf-devel bpftool elfutils-libelf-devel zlib-devel libzstd-devel python3 openssl make gcc git
# Arch
sudo pacman -S clang llvm libbpf bpf libelf zlib zstd python openssl make gcc git
```

On Ubuntu `bpftool` may come from `linux-tools-$(uname -r)` instead.

Get the sched_ext headers and point the tool at them. Use a checkout whose version is close to your kernel:

```bash
git clone --depth 1 https://github.com/sched-ext/scx ~/scx
tools/fetch-scx-include.sh ~/scx              # copies scheds/include into third_party/scx-include
#   or:  export SCX_INC=~/scx/scheds/include   (or pass --scx-inc to conductord)
```

Header/kernel drift is the main risk. The build probes the one difference known to matter
(`scx_bpf_dsq_move_to_local` takes 1 or 2 arguments depending on version); anything else surfaces as a compile error or a
kernel verifier message, both of which `gen` reports verbatim. If libbpf is too old for the headers, build a
newer libbpf (the scx README describes it).

## 2. Check readiness

```bash
sudo python3 -m conductord doctor
```

Every row must be `ok` except the optional ones (`--`). It checks clang's BPF target, bpftool, the C compiler and
libbpf, the scx headers, kernel BTF, sched_ext in the running kernel, openssl, root, and whether an API key or the
`claude` CLI is present. Fix FAIL rows first.

## 3. Build the reference scheduler and create a signing key

```bash
make                                                   # build/conductor_load + build/scx_conductor.bpf.o
sudo mkdir -p /var/lib/conductor
sudo python3 -m conductord keygen --priv /var/lib/conductor/dev-signing.key --pub /var/lib/conductor/trusted.pub
```

The key lives on this laptop: it protects against bugs and corruption, not against a compromised root.

## 4. See what a backend would receive

```bash
python3 -m conductord gen --workload gaming --platform laptop --gen-backend template --print-prompt | less
```

That is the *entire* prompt: numbers about this device (CPU count, kernel release, power state, limits, baseline
parameters) and the text of three repository files. No process names, paths, user names or logs.

## 5. Generate without a model first (template backend)

The `template` backend writes the reference scheduler with the numbers baked into the source. It is deterministic, so
a failure here is a toolchain or kernel problem, not a model problem.

```bash
sudo python3 -m conductord gen --workload gaming --platform laptop --gen-backend template
```

It runs: static gate -> clang -> ELF checks -> bpftool skeleton -> loader build -> **kernel verifier** (loads the
scheduler without attaching it) -> early canary (partial mode, only if no other sched_ext scheduler is running).
On success it prints an artifact id and the status `pending`. A pending artifact **cannot** be loaded.

If it fails, the JSON names the stage and the tool's real output (`<state>/generated/<id>/build.log` keeps more).
The stage tells you where to look:

| Stage | Meaning |
|---|---|
| `static-gate` | the source broke a rule (message names the rule) |
| `build:compile` | clang error: usually header/kernel drift or a missing include path |
| `build:object` | clang succeeded but the object has a section or map the allowlist does not permit |
| `build:skeleton` / `build:link` | bpftool or libbpf problem (loader build) |
| `kernel-verifier` | your kernel refused the program (or lacks a kfunc/struct_ops member); the message is the kernel's |
| `canary` | loaded but starved a hog, missed the latency budget, or the telemetry contract was not wired; the artifact is stored as `rejected` and is not retried |

## 6. Review and approve

```bash
python3 -m conductord gen-list --state /var/lib/conductor
python3 -m conductord gen-show   <id> --state /var/lib/conductor            # results + diff against the reference
python3 -m conductord gen-show   <id> --state /var/lib/conductor --source   # the full C file
sudo python3 -m conductord gen-approve <id> --state /var/lib/conductor      # you must type the id
```

Approval signs the digests of the object, the loader and the source. Change one byte afterwards and the Verifier refuses it.
Use `gen-reject <id> --reason ...` to bury one.

## 7. Let the governor load it

```bash
sudo python3 -m conductord run --platform laptop --dev-self-sign
# in another terminal:
sudo python3 -m conductord ctl hold gaming          # pin the workload
python3 -m conductord ctl status
cat /sys/kernel/sched_ext/state /sys/kernel/sched_ext/root/ops    # expect: enabled / conductor_gen
sudo python3 -m conductord ctl hold camera          # no approved artifact: the reference scheduler (ops: conductor)
sudo python3 -m conductord ctl release
python3 -m conductord audit-verify /var/lib/conductor/audit.jsonl
```

The governor prefers an approved generated scheduler for `(workload, platform, arch, kernel release)` and falls back to
the reference template when there is none, when it was quarantined, or when it fails verification.

## 8. Use a real model

```bash
# Anthropic API (the prompt from step 4 leaves the laptop):
export ANTHROPIC_API_KEY=...            # or a file /etc/conductor/anthropic.key with mode 0600
export CONDUCTOR_GEN_MODEL=...          # optional; default claude-sonnet-5-5
sudo -E python3 -m conductord gen --workload video --platform laptop --gen-backend anthropic

# Or any local command that reads the prompt on stdin and prints a C file, e.g. the Claude Code CLI:
sudo python3 -m conductord gen --workload video --platform laptop --gen-backend command --gen-cmd 'claude -p'
```

Errors from the gate, the build and the kernel verifier go back to the model as text, up to `--gen-max-attempts`
(default 3). **The model and command backends have never been run by the author**; the repair loop is tested with a
scripted fake backend.

Let the governor ask by itself when a workload has no scheduler yet (opt-in; this sends the prompt off the device):

```bash
sudo -E python3 -m conductord run --platform laptop --dev-self-sign --gen-backend anthropic --gen-on-demand
python3 -m conductord ctl gen video          # or ask explicitly (needs a backend, not the flag)
```

It generates in the background, one at a time, backs off after failures (15 min) and rejections (6 h), and **still
needs your `gen-approve`** before anything loads. `--gen-approval auto` skips the human; it is for a lab VM and logs a
warning on every start.

## 9. If the machine misbehaves

In order of preference:

1. `sudo python3 -m conductord ctl rollback` unloads and pins the stock scheduler.
2. `sudo pkill -f 'conductor_load|gen_load'`: the scheduler lives only while its loader runs.
3. `Alt+SysRq+S` (needs `kernel.sysrq` to allow it) aborts the BPF scheduler from the keyboard.
4. Reboot. Nothing is persistent: no module, no boot entry.

The kernel also ejects a scheduler by itself when a runnable task stalls longer than the watchdog (5 s on `laptop`).
Canary hogs and the probe run under `SCHED_EXT` in partial mode, so a bad candidate cannot touch your desktop during the
canary. Run first on a battery-charged laptop with your work saved anyway.

## 10. Record the result

Whatever happens, append a dated entry to `memory/test-log.md`: kernel, hardware, scx header version, which stage
passed, the exact error if not, and for a loaded scheduler the output of `ctl status`. A failure there is the most
valuable result this project can produce right now.

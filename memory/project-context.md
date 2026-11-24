# Project context

**Name:** scx-conductor. **Owner request (2026-11-23):** take the concept from OpenAI + Cisco's Shirudo announcement
(signed eBPF "shields" loaded and removed on running Linux systems) and apply it to scheduling: create sched_ext
schedulers on the fly and load/unload them based on user interaction (gaming, UI, browser, agentic CPU work, camera,
graphics, video) across laptop, mobile, IoT and automotive, for best performance and power; work on x86 and arm64;
test on QEMU; deliver architecture diagrams, reproduction md files and memory md files.

## Interpretation taken
- Phase 1: "on the fly" = specialising one reviewed BPF template through `.rodata` knobs at load time. Rationale in
  `decisions.md` D1. That stays the default path.
- Phase 2 (owner challenged phase 1: "Shirudo writes bpf programs on the fly"; then "let's do on device generation since
  we can try it on the laptop"): an LLM backend writes the scheduler C on the device; static gate, clang, kernel
  verifier, canary, operator approval and signed digests decide whether it may run. `decisions.md` D10-D15.
- "Like Shirudo" = signed manifests, verifier gate, canary before enforce, operator approval, hot load/unload, audit
  trail, TPM extend.

## Status at 2026-11-23
- Governor, policy, forge/verifier, lifecycle, audit, control socket, **generation pipeline**: written, **211 unit tests
  pass** (2 of them need a real toolchain and passed when enabled), dry-run daemon ran.
- BPF template and C loader: **compiled and linked on x86_64** against real scx/libbpf headers (arm64: BPF object
  only). The generation CLI ran up to the kernel verifier and stopped there (sandbox kernel has no sched_ext).
- **Never run:** any load into a kernel, the kernel verifier's verdict (including whether `--verify-only` validates
  without attaching), canary, watchdog, QEMU, a real model backend, `tests/guest/gen_e2e.py`.
- No performance or power data exists.
- Owner asked for the artifacts on github.com/trsoni: **not done**. No GitHub link/valid token in the session and no
  repo name was given. Assumed name `trsoni/scx-conductor`; the owner has to link GitHub and create the repo (or run
  the push commands themselves).

## How to run
- Logic tests: `python3 -m unittest discover -s tests`
- Dry-run daemon: `python3 -m conductord run --platform vm --dev-self-sign --dry-run --state /tmp/cs --sock /tmp/cs/ctl.sock --bpf-obj <file>`
- Real kernel: `docs/REPRODUCE.md`; on-device generation on a laptop: `docs/LAPTOP.md`; readiness: `python3 -m conductord doctor`
- Regenerate diagrams: `python3 docs/diagrams/make_svgs.py`

## Environment facts learned
- The authoring sandbox had no network for package installs and no QEMU or sched_ext kernel. clang 18, gcc and
  `rsvg-convert` were present; libbpf, bpftool and a libelf shim were built by hand from source into a scratch dir
  (not part of the repo). The scx headers came from a checkout of github.com/sched-ext/scx.
- The sandbox kernel's BTF has no sched_ext types, so builds there used the vmlinux.h bundled in the scx repo.
- The mermaid CLI could not run (no Chrome), so diagrams are generated SVG, not Mermaid.

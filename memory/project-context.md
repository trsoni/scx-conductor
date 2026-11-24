# Project context

**Name:** scx-conductor. **Owner request (2026-11-23):** take the concept from OpenAI + Cisco's Shirudo announcement
(signed eBPF "shields" loaded and removed on running Linux systems) and apply it to scheduling: create sched_ext
schedulers on the fly and load/unload them based on user interaction (gaming, UI, browser, agentic CPU work, camera,
graphics, video) across laptop, mobile, IoT and automotive, for best performance and power; work on x86 and arm64;
test on QEMU; deliver architecture diagrams, reproduction md files and memory md files.

## Interpretation taken
- "On the fly" = specialising one reviewed BPF template through `.rodata` knobs at load time, not runtime codegen.
  Rationale in `decisions.md` D1.
- "Like Shirudo" = signed manifests, verifier gate, canary before enforce, hot load/unload, audit trail, TPM extend.

## Status at 2026-11-23
- Governor, policy, forge/verifier, lifecycle, audit, control socket: written, **62 unit tests pass**, dry-run daemon ran.
- BPF template and C loader: written, **never compiled against real headers**.
- QEMU harness (kernel build, rootfs, run, in-guest stages): written, **never executed**.
- No performance or power data exists.

## How to run
- Logic tests: `python3 -m unittest discover -s tests`
- Dry-run daemon: `python3 -m conductord run --platform vm --dev-self-sign --dry-run --state /tmp/cs --sock /tmp/cs/ctl.sock --bpf-obj <file>`
- Real kernel: `docs/REPRODUCE.md`
- Regenerate diagrams: `python3 docs/diagrams/make_svgs.py`

## Environment facts learned
- The authoring sandbox had no network for package installs, no clang/libbpf/QEMU, and `rsvg-convert` for SVG preview.
- The mermaid CLI could not run (no Chrome), so diagrams are generated SVG, not Mermaid.

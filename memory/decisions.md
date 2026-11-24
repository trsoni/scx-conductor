# Decisions and lessons

**D1 - Specialise a template via rodata instead of generating BPF C at runtime.** Devices need no compiler, the
signed object digest never changes, the verifier sees constants, and the parameter space is bounded and testable.
Source generation (e.g. by an agent) is a CI-time, human-reviewed path (`docs/SAFETY.md`).

**D2 - One shared vtime DSQ.** Starvation-free by construction regardless of knob values. Per-class DSQs would give
sharper priority but let a bad profile starve a class.

**D3 - Governor in Python (stdlib only), loader in C.** Policy changes often and runs once a second; scheduling is in
the kernel. Stdlib-only keeps minimal images viable. Signing uses the `openssl` CLI to avoid a crypto dependency.

**D4 - Loader is a separate process that owns the struct_ops link.** If the governor dies the pipe closes, the loader
exits, the link closes, the kernel returns to the fair class. Unload == process exit.

**D5 - Canary uses SCX_OPS_SWITCH_PARTIAL.** Only SCHED_EXT tasks (the probe + hogs) run on the candidate, so a bad
scheduler cannot touch the rest of the system before it is trusted. Passed manifests are cached per run.

**D6 - approved_only for iot/automotive.** No key and no generation on those devices; the forge host signs per
architecture ahead of time.

**D7 - Rule-based classifier with evidence.** Explainable, testable, deterministic; every decision's evidence goes into
the audit log. An ML/LLM classifier can replace `classify()` without changing the downstream contract.

**D8 - Guest builds its own binaries into tmpfs; repo shared over 9p.** Avoids x86/arm64 binaries clobbering each other
in the shared tree and avoids baking the repo into the image.

**D9 - Kernel/header coupling.** scx headers are copied from the same kernel tree that is booted
(`tools/fetch-scx-include.sh`); kfunc names (`scx_bpf_dsq_insert`, `scx_bpf_dsq_move_to_local`) and flag enums changed
across releases. `kernel_min` is recorded as 6.13 from memory of the rename: **verify**.

## Lessons (bugs found by actually running things)

**L1 - Manifest hash churn (fixed 2026-11-23).** `created` is inside the signed body, so re-minting the manifest each tick
changed its hash and the lifecycle hot-reloaded an identical scheduler every second (and spawned openssl each tick).
Found only by running the daemon; unit tests passed because they ran inside one wall-clock second. Fix: `Forge.make`
caches per (workload, platform, state, arch) for half the TTL. Regression test:
`test_steady_state_never_reloads_even_if_wall_clock_advances` (verified to fail without the fix).

**L2 - Collector treated clock value 0.0 as "no previous sample".** Use `is not None`. Found by a fake-clock test.

**L3 - Don't write vacuous checks.** Two placeholder assertions in the guest tests (`... or True`, a meaningless index
expression) were caught on review and replaced with real ones.

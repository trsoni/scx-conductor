# Decisions and lessons

**D1 - Specialise a template via rodata as the default path.** Devices need no compiler, the signed object digest
never changes, the verifier sees constants, and the parameter space is bounded and testable. *Amended by D10:* this was
the whole design in phase 1, which missed that Shirudo's agents write programs; generation is now a second, opt-in path
and D1 remains the fallback for everything that fails or is not approved.

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

**D10 - On-device generation, Shirudo-shaped (2026-11-23).** A backend writes ONE C file; deterministic tools check it;
the kernel verifier proves memory safety; a person approves; only a signed record loads. Chosen over CI-time-only
generation because the owner wants to try it on a laptop and because the Shirudo loop is exactly this. Kept the D1 path
as the fallback so a bad or missing generated scheduler never leaves a workload without a vetted one.

**D11 - Nothing pending ever loads; the generator never approves.** `pending` -> `approved` only through
`gen-approve`, which signs `approval.json`; the manifest pins that file's digest, so removing or editing it breaks the
Verifier. `--gen-approval auto` exists for lab VMs only, warns on every start and is audited. Mutation-tested: making
the generator approve automatically fails 8 tests.

**D12 - A shared ABI header instead of letting the model define everything.** `bpf/conductor_abi.bpf.h` owns the maps,
UEI, licence and telemetry helpers. The governor's class sync, stats and canary therefore work with any generated
scheduler, and the object check can demand exactly four maps. The model is told the contract in its system prompt, and
the gate checks `conductor_mark_enq`, `conductor_note_running`, `UEI_RECORD` are present.

**D13 - Kernel verification without attach.** `gen_load --verify-only` loads the struct_ops (libbpf `BPF_F_LINK`) and
exits before attaching, so the verifier's verdict is available while another scheduler may be active. **Assumption
not yet observed:** that load validates and only attach registers. If the first kernel run shows otherwise, the early
verify step must be replaced by the canary alone.

**D14 - Artifact identity and scope.** id = `sha256(source)[:12]`; valid for one (workload, platform, arch, kernel
release); the newest *approved* artifact for that tuple is the only candidate (`GenStore.lookup`); if it is unusable the
governor uses the template rather than an older artifact. Kernel release is in the manifest because scx kfuncs and
struct layouts drift between releases (D9).

**D15 - Numbers-only prompt.** The model receives device facts as numbers and three repository files, never process
names, paths, users or logs, so a local process cannot steer the model and nothing user-derived leaves the device.
`conductord gen --print-prompt` shows exactly what a remote backend gets. Cost: the model cannot adapt to *this user's*
apps, only to the workload class and platform limits.

**D16 - Single-flight, cooled-down background generation.** `GenManager` runs one request at a time; 15 min after a
failure, 6 h after a rejection, and nothing while a pending or approved artifact exists. Prevents a flaky backend from
burning API budget or CPU in a loop. Still needs a human before anything loads.

**D17 - One lifecycle lock shared with the generator.** Only one sched_ext scheduler can be attached, so the generator's early canary
takes the lifecycle lock and reports "skipped" if the slot is taken; the lifecycle runs the canary again at load anyway.

## Lessons (bugs found by actually running things)

**L1 - Manifest hash churn (fixed 2026-11-23).** `created` is inside the signed body, so re-minting the manifest each tick
changed its hash and the lifecycle hot-reloaded an identical scheduler every second (and spawned openssl each tick).
Found only by running the daemon; unit tests passed because they ran inside one wall-clock second. Fix: `Forge.make`
caches per (workload, platform, state, arch) for half the TTL. Regression test:
`test_steady_state_never_reloads_even_if_wall_clock_advances` (verified to fail without the fix).

**L2 - Collector treated clock value 0.0 as "no previous sample".** Use `is not None`. Found by a fake-clock test.

**L3 - Don't write vacuous checks.** Two placeholder assertions in the guest tests (`... or True`, a meaningless index
expression) were caught on review and replaced with real ones.

**L4 - Real headers disagree with memory (found 2026-11-23 by compiling).** (a) Our `NR_STATS` collided with a kernel
enum: renamed `CND_NR_STATS`. (b) `scx_bpf_dsq_move_to_local` has 1 or 2 arguments depending on scx version: probed by
`tools/probe-scx-abi.sh` and wrapped. (c) bpftool skeletons do not expose char-array members such as the ops `name`, so the
loader cannot force it: the gate pins `.name` and the lifecycle checks sysfs. (d) `SCX_OPS_OPEN` and friends use token
pasting, so passing them macros needs indirection. None of these could be found without the real toolchain.

**L5 - A guest test could never have started the daemon.** `tests/guest/governor_e2e.py` launched
`python3 -I -m conductord`; `-I` ignores `PYTHONPATH` and the working directory, so the import failed. Found while writing
the generation guest stage by checking the same invocation locally. Unit tests do not start the daemon this way.

**L6 - Test doubles that reset state hide the case under test.** `FakeHost.start()` clears `dead`, so a test that set
`dead = True` before `start` silently tested nothing, and another asserted a message for the wrong check order. Both were
caught only because the tests failed on first run; check what a test double does to the state you set.

**L7 - Gate rules can be too clever.** A "reserved names" rule rejected legitimate uses of `uei` and `task_ctx_stor`;
removed. `extra_map_problems(allowed=set())` silently fell back to defaults because of a truthiness check; fixed with
`is None`, and the test now asserts the real object has exactly the four ABI maps.

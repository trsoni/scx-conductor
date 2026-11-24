# Open questions and next work (priority order)

1. **First load on a sched_ext kernel.** Follow `docs/LAPTOP.md` (laptop) or `docs/REPRODUCE.md` (QEMU). Expected
   surprises: the verifier's view of `lat_hist` bucket loops and rodata array access, `SCX_OPS_*` / kfunc drift between
   the scx headers and the kernel, `--verify-only` semantics (D13), canary timing, watchdog timing, 9p mount options,
   rootfs package names. Record the kernel, hardware and scx header commit.
2. **Does `--verify-only` really validate without attaching?** If not, rework the early verify (D13).
3. **First real model run** (`--gen-backend anthropic` or `command`): does the model satisfy the gate and the
   telemetry contract within 3 attempts? Which errors recur? That decides whether the system prompt or the gate needs
   changing. Keep the transcripts of failures (`<state>/generated/<id>/build.log`, audit `gen-attempt`).
4. **First run of `tests/guest/gen_e2e.py`** inside QEMU on both architectures (it has never run; written to the
   documented CLI and unit-tested components).
5. **arm64 loader link and run** (only the BPF object has been compiled for arm64).
6. **Confirm minimum kernel** for `scx_bpf_dsq_insert` / `scx_bpf_dsq_move_to_local` / `scx_bpf_cpuperf_set`
   (recorded as 6.13 from memory in the manifest `kernel_min`).
7. **Measure** at least one workload per platform on real hardware, stock vs conductor vs generated; fill
   `workload-profiles.md`. No claim of benefit exists until then.
8. **Generated artifacts for approved-only platforms** (iot, automotive): generate and approve on a forge host, sign,
   ship; `forge-approved` emits template manifests only today.
9. **Feed runtime telemetry back into generation** (latency histograms, guard events) so the model can improve on
   its previous scheduler; today the prompt has baseline parameters only (D15 trade-off).
10. **Topology awareness** (big.LITTLE, hybrid x86): capacity-based placement; today only cpuperf hints.
11. **Per-thread classes** via task storage instead of per-tgid map.
12. **Hint producers**: Android top-app, automotive HMI, GNOME/KDE game-mode.
13. **Production signing**: key custody, rotation, revocation, real TPM PCR policy; approval on a separate machine.
14. **Android / GKI**: does the target kernel enable sched_ext at all?
15. **Licence**: the repo is public at github.com/trsoni/scx-conductor with no licence file; BPF and loader are marked GPL-2.0,
    the rest is undecided (same as item 16).
16. Choose a licence for the non-BPF parts.
17. Fuzz `genstatic.check` and the object checks; today they are tested with hand-written hostile inputs only.

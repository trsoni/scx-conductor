# Open questions and next work (priority order)

1. **First real build.** Compile `bpf/scx_conductor.bpf.c` against the headers of the kernel you boot; fix kfunc names,
   `SCX_OPS_*` macros, `time_before`, task-storage and `UEI_*` usage as needed. Record the kernel version.
2. **First QEMU run on both architectures.** Expect issues in: rodata array access under the verifier, `lat_hist`
   bucket loop, partial-mode canary, `inject_stall` watchdog timing, 9p mount options, rootfs package names.
3. **Confirm minimum kernel** for `scx_bpf_dsq_insert` / `scx_bpf_dsq_move_to_local` / `scx_bpf_cpuperf_set` (currently
   recorded as 6.13 from memory).
4. **Measure** at least one workload per platform on real hardware; fill `workload-profiles.md`.
5. **Topology awareness** (big.LITTLE, hybrid x86): capacity-based placement for MEDIA/BG; today only cpuperf hints.
6. **Per-thread classes** (render thread vs worker threads) via task storage instead of per-tgid map.
7. **Hint producers**: Android top-app, automotive HMI, GNOME/KDE game-mode.
8. **Agent-in-the-loop generation** (CI-time, reviewed) per `docs/SAFETY.md`; define the telemetry it consumes.
9. **Production signing**: key custody, rotation, revocation list, real TPM PCR policy.
10. **Android / GKI**: does the target kernel enable sched_ext at all?
11. Replace dev `--dev-self-sign` on laptop/mobile with a managed key or approved manifests.
12. Choose a licence for the non-BPF parts.

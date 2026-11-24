# Safety model

Loading a scheduler into a running kernel is powerful and can make a machine unusable. This design leans on
mechanisms that already exist in the kernel and adds checks before and after the load.

## What the kernel gives us (sched_ext)

From the kernel.org sched_ext documentation: terminating the scheduler program, SysRq-S, or detecting an internal
error including stalled runnable tasks aborts the BPF scheduler and reverts all tasks to the fair class. The BPF
verifier checks the program. With `SCX_OPS_SWITCH_PARTIAL` only `SCHED_EXT` tasks are scheduled by sched_ext, so a
canary cannot affect the rest of the system.

## What this project adds

| Control | Where | Failure it addresses |
|---|---|---|
| Signed manifest, fail-closed verifier (signature, BPF digest, platform, arch, TTL, bounds) | `forge.py` | tampered or stale parameters, wrong-device manifest, swapped BPF object |
| Hard parameter bounds (slice 0.5-50 ms, charge 10-1000 %, perf <= 1024, timeout 0.1-30 s), re-checked by the verifier even for signed manifests | `policy.py` | a buggy forge or profile producing a pathological scheduler |
| Canary in partial mode with a latency probe | `canary.py` | a scheduler that loads but misbehaves on this hardware |
| Watchdog `timeout_ms` per platform (automotive 1 s) | profiles | stalls: the kernel ejects, the governor quarantines |
| PSI + FG/MEDIA latency-tail guard, rollback, 300 s quarantine | `lifecycle.py` | a scheduler that is valid but makes the workload worse |
| One shared vtime DSQ | BPF template | starvation by construction |
| Loader process owns the link; governor crash or `SIGTERM` closes it | `host.py`, `daemon.py` | governor death leaving a custom scheduler without supervision |
| Governor `finally:` unload; exception in the loop unloads | `daemon.py` | software faults in the policy layer |
| Hash-chained audit log, optional TPM PCR extend | `audit.py` | "what was loaded, when, and why" after the fact |
| `approved_only` platforms never sign or generate on the device | profiles | on-device key exposure for iot / automotive |
| Automotive allow-list (ui, video, camera, graphics) | profiles | agentic / batch inference tuning on a vehicle network |

## Explicitly not claimed

- **No safety certification.** Nothing here is qualified for ISO 26262, IEC 61508 or similar. Do not run it on
  safety-relevant partitions. The automotive profile exists to describe a conservative posture for infotainment-class
  workloads.
- **No performance or power claims.** There are no measurements yet.
- **On-device signing is not a security boundary.** With `--dev-self-sign`, anything with root can mint a manifest.
- **The BPF object is trusted by digest, not analysed.** The signing process (review + CI) is where trust lives.
- **PCR 16** is a debug PCR and not a production attestation policy.
- **The classifier can be fooled** by a process that renames itself (the `comm` rules) or opens device nodes.
  Mitigations are the debounce, the bounded parameter space (a wrong class cannot starve anything), and the hint
  channel for trusted platform services. A hostile local user can at worst move their own processes between classes
  the template already bounds; `tgid_class` is written only by the root-owned loader.

## About "generating schedulers on the fly" with an AI agent

Shirudo's published design has agents (e.g. Codex) generate and validate shields, with a person approving deployment.
The equivalent here, **which is not implemented**, would be:

1. an agent proposes a new template (BPF C) or new profile values from telemetry;
2. CI compiles it for x86_64 and arm64, runs `tests/guest/` in QEMU plus on-target canaries, and compares against the
   baseline;
3. a human reviews the diff and the results;
4. CI signs the new object digest and manifests; devices load them only through the verifier.

On-device LLM-written BPF that is compiled and loaded without review is deliberately out of scope: the kernel
verifier proves memory safety and termination, not that a scheduler is fair or fast, and a scheduler is on every
task's critical path.

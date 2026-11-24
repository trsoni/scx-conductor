# Test log (append new entries at the top)

## 2026-11-23 - authoring sandbox (x86_64, Linux 6.18, Python 3.12.3, openssl 3.0.13)
RAN and PASSED
- `python3 -m unittest discover -s tests`: 62 tests OK (classifier, debouncer, policy bounds for every
  workload/platform/state, forge/verifier incl. tamper/expiry/wrong key/digest swap/platform mismatch, lifecycle incl.
  canary cache/quarantine/ejection/PSI+latency rollback, governor cycles, audit chain tamper detection, fake procfs).
- Dry-run daemon (`--dry-run`) with control socket: status/hold/hint/rollback worked; audit chain verified.
  Found and fixed L1 (reload churn) here.
- `lat_probe.py` baseline smoke run.
- Diagram SVGs generated, XML-validated, rendered with rsvg-convert and visually checked.
- `bash -n` on all shell scripts; `ast.parse` on all Python scripts; loader C `gcc -fsyntax-only -Wall -Wextra`
  against **stub** headers (not real libbpf/scx).

NOT RUN (no tooling in the sandbox)
- BPF compile (clang/bpftool), real loader build, any sched_ext kernel, QEMU x86_64/arm64, TPM path, GitHub upload
  (session GitHub token invalid and account not linked; repo name not given).

## Template for next entries
date - host/guest - arch - kernel - stages run - result - issues found (and the fix commit)

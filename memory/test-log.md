# Test log (append new entries at the top)

## 2026-11-23 (later) - authoring sandbox (x86_64, Linux 6.18 without sched_ext, Python 3.12.3, clang 18.1.3)
Toolchain: libbpf, bpftool v7.9.0 built by hand from source with a hand-written libelf.h/gelf.h shim (scratch dir, not in
the repo); scx headers from a checkout of github.com/sched-ext/scx (`scheds/include`); the scx repo's bundled vmlinux.h
(this kernel's BTF has no sched_ext types). Not distro packages.

RAN and PASSED
- `python3 -m unittest discover -s tests`: **211 tests OK** with `-W error::ResourceWarning`. With the optional real-toolchain
  tests enabled (`CONDUCTOR_TEST_SCX_INC`, `CONDUCTOR_TEST_VMLINUX_DIR`, `CONDUCTOR_TEST_OBJ`, `..._CFLAGS/LDLIBS`): 211 run, 0 skipped.
- `make` (reference scheduler): `bpf/scx_conductor.bpf.c` and `loader/conductor_load.c` built from current sources, x86_64,
  no warnings. arm64: BPF object compiled (`make ARCH=arm64 ... scx_conductor.bpf.o`); object passes `genstatic.elf_problems`
  and has exactly the four ABI maps. arm64 loader **not** linked.
- `python3 -m conductord doctor` (correctly reported `sched_ext in running kernel: missing`).
- `python3 -m conductord gen --workload gaming --platform vm --gen-backend template --no-canary`: passed the static gate,
  clang, object checks, bpftool skeleton, loader link, and executed `gen_load --verify-only`; stopped at stage
  `kernel-verifier` with the loader's own message (`sched_ext_ops.dump() missing, kernel too old?`) because this kernel
  has no sched_ext. The failed artifact directory was kept with `build.log` as designed.
- Mutation checks on `test_generator.py`: dropping the repair feedback made 4 tests fail; auto-approving made 8 fail.
- `tools/fetch-scx-include.sh` against fake kernel-tree and scx-checkout layouts.
- Diagram `generation-pipeline.svg` and the updated `shirudo-mapping.svg` rendered with rsvg-convert and viewed.

Found and fixed (see `decisions.md` L4-L7): kernel enum collision, `move_to_local` arity drift, skeleton char-array
members, `python -I -m` in the existing governor guest test, test doubles that reset the state under test, an over-clever
gate rule, a truthiness bug in `extra_map_problems`, unclosed pipes in `LoaderHost.stop` (now closed).

NOT RUN
- Loading any scheduler into any kernel; the kernel verifier's verdict; early canary; lifecycle canary; watchdog ejection.
- `--verify-only` semantics (assumed: load validates, attach registers; decision D13).
- A real model backend (`anthropic`, `command`): only scripted fakes and the deterministic `template` backend.
- `tests/guest/gen_e2e.py` and the `gen` stage of `run_all.sh`: written and syntax-checked only.
- `tests/guest/governor_e2e.py` after the `-I` fix: not run.
- QEMU x86_64 / arm64, TPM path, arm64 loader link.

Done 2026-11-24: public repo `trsoni/scx-conductor` created (empty, no README/licence/.gitignore) and `main` pushed; remote HEAD
`ef131c4` equals local HEAD, 2 commits, 76 files, no tarball or keys in the tree.

## 2026-11-23 (earlier) - authoring sandbox (x86_64, Linux 6.18, Python 3.12.3, openssl 3.0.13)
(Superseded in part by the entry above: at this point there was no clang/bpftool/libbpf and 62 unit tests.)
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

"""Build pipeline for generated schedulers: clang (BPF) -> bpftool skeleton -> cc loader.

Mirrors the Makefile (`make gen SRC=...`), which was verified against real scx headers
on x86_64 (and the BPF step on arm64); this is the same sequence driven from Python so
the daemon can run it on the device.

Compilation of model-written source is the first place untrusted text meets a large C
toolchain, so: includes are restricted by the static gate beforehand, every step has a
timeout and (when `prlimit` exists) CPU / address-space / file-size limits, and the
compile can optionally run as an unprivileged user (`drop_user`). None of that replaces
the verifier or the approval step.
"""
from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import genstatic
from .forge import sha256_file

ARCH_DEFINE = {"x86_64": "x86", "amd64": "x86", "aarch64": "arm64", "arm64": "arm64"}
SCX_CANDIDATES_REL = ("third_party/scx-include",)
SCX_CANDIDATES_ABS = ("/usr/include", "/usr/local/include", "/usr/share/scx/include",
                      "/usr/src/linux/tools/sched_ext/include")


@dataclass
class BuildResult:
    ok: bool
    stage: str                       # "ok" | "setup" | "compile" | "object" | "skeleton" | "link"
    log: str = ""
    files: dict = field(default_factory=dict)      # name -> sha256
    tools: dict = field(default_factory=dict)      # tool versions, recorded in meta.json


def _tail(text: str, n: int = 4000) -> str:
    return text if len(text) <= n else "...[truncated]...\n" + text[-n:]


class Toolchain:
    def __init__(self, repo_root: str, work_root: str, *, scx_inc: Optional[str] = None,
                 vmlinux_dir: Optional[str] = None, clang: str = "clang", bpftool: str = "bpftool",
                 cc: str = "cc", extra_cflags: Optional[list] = None,
                 extra_ldlibs: Optional[list] = None, arch: Optional[str] = None,
                 release: Optional[str] = None, timeout: float = 240.0,
                 drop_user: Optional[str] = None, runner: Optional[Callable] = None):
        self.repo_root, self.work_root = repo_root, work_root
        self._scx_arg, self._vmlinux_arg = scx_inc, vmlinux_dir
        self.clang, self.bpftool, self.cc = clang, bpftool, cc
        self.extra_cflags = extra_cflags if extra_cflags is not None else \
            shlex.split(os.environ.get("CONDUCTOR_EXTRA_CFLAGS", ""))
        self.extra_ldlibs = extra_ldlibs if extra_ldlibs is not None else \
            shlex.split(os.environ.get("CONDUCTOR_EXTRA_LDLIBS", ""))
        machine = arch or platform.machine()
        self.machine = machine
        self.arch_def = ARCH_DEFINE.get(machine, machine)
        self.release = release or platform.release()
        self.timeout, self.drop_user = timeout, drop_user
        self._runner = runner or subprocess.run
        self._cache = os.path.join(work_root, "toolchain", self.release)

    # ------------------------------------------------------------ discovery
    def scx_inc(self) -> Optional[str]:
        cands = [self._scx_arg, os.environ.get("SCX_INC")]
        cands += [os.path.join(self.repo_root, c) for c in SCX_CANDIDATES_REL]
        cands += list(SCX_CANDIDATES_ABS)
        cands.append(f"/lib/modules/{self.release}/build/tools/sched_ext/include")
        for c in cands:
            if c and os.path.isfile(os.path.join(c, "scx", "common.bpf.h")):
                return c
        return None

    def _incs(self, extra: list) -> list:
        scx = self.scx_inc()
        out = []
        for d in extra:
            out += ["-I" + d]
        if scx:
            out += ["-I" + scx]
            if os.path.isdir(os.path.join(scx, "bpf-compat")):
                out += ["-I" + os.path.join(scx, "bpf-compat")]
        out += ["-I" + os.path.join(self.repo_root, "bpf")]
        out += self.extra_cflags
        return out

    # ------------------------------------------------------------ process helper
    def _exec(self, argv: list, *, cwd: Optional[str] = None, stdin: Optional[bytes] = None,
              limits: bool = True, as_user: bool = False) -> tuple:
        """Returns (rc, combined output text)."""
        argv = list(argv)
        if limits and shutil.which("prlimit"):
            argv = ["prlimit", "--cpu=180", "--as=3221225472", "--fsize=268435456", "--"] + argv
        kw = {}
        if as_user and self.drop_user and os.geteuid() == 0:
            kw["user"] = self.drop_user
        try:
            r = self._runner(argv, cwd=cwd, input=stdin, capture_output=True,
                             timeout=self.timeout, **kw)
        except FileNotFoundError as e:
            return 127, f"{argv[0]}: not found ({e})"
        except subprocess.TimeoutExpired:
            return 124, f"{argv[0]}: timed out after {self.timeout:.0f}s"
        except OSError as e:
            return 126, f"{argv[0]}: {e}"
        out = (r.stdout or b"").decode(errors="replace") + (r.stderr or b"").decode(errors="replace")
        return r.returncode, out

    def _version(self, argv: list) -> str:
        rc, out = self._exec(argv, limits=False)
        return out.strip().splitlines()[0] if rc == 0 and out.strip() else "unknown"

    # ------------------------------------------------------------ cached inputs
    def vmlinux_dir(self) -> tuple:
        """(dir, error). Either the supplied dir or a vmlinux.h generated from kernel BTF."""
        d = self._vmlinux_arg or os.environ.get("VMLINUX_DIR")
        if d:
            return (d, None) if os.path.isfile(os.path.join(d, "vmlinux.h")) else (None, f"{d}/vmlinux.h missing")
        d = self._cache
        h = os.path.join(d, "vmlinux.h")
        if os.path.isfile(h) and os.path.getsize(h) > 0:
            return d, None
        os.makedirs(d, exist_ok=True)
        rc, out = self._exec([self.bpftool, "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
                             limits=False)
        if rc != 0 or "struct task_struct" not in out:
            return None, f"cannot generate vmlinux.h: {out[-300:]}"
        tmp = h + ".tmp"
        with open(tmp, "w") as f:
            f.write(out)
        os.replace(tmp, h)
        return d, None

    def probe_header(self, vmlinux_dir: str) -> str:
        """Directory holding conductor_probe.h (scx header ABI probe), cached per kernel."""
        d = os.path.join(self._cache, "probe")
        h = os.path.join(d, "conductor_probe.h")
        if os.path.isfile(h):
            return d
        os.makedirs(d, exist_ok=True)
        base = [self.clang, "-O2", "-mcpu=v3", "-target", "bpf", f"-D__TARGET_ARCH_{self.arch_def}",
                *self._incs([vmlinux_dir]), "-fsyntax-only", "-x", "c", "-"]

        def compiles(body: str) -> bool:
            src = f"#include <scx/common.bpf.h>\nvoid probe(void){{ {body} }}\n"
            rc, _ = self._exec(base, stdin=src.encode(), limits=False)
            return rc == 0

        lines = ["/* generated by genbuild.Toolchain.probe_header - do not edit */"]
        if compiles("scx_bpf_dsq_move_to_local(0, 0);"):
            lines.append("#define CND_MOVE_TO_LOCAL_2ARG 1")
        elif compiles("scx_bpf_dsq_move_to_local(0);"):
            lines.append("/* scx_bpf_dsq_move_to_local: 1 argument */")
        else:
            lines.append("/* scx_bpf_dsq_move_to_local: probe failed, headers may be incompatible */")
        with open(h, "w") as f:
            f.write("\n".join(lines) + "\n")
        return d

    # ------------------------------------------------------------ the build
    def build(self, source: str, out_dir: str) -> BuildResult:
        os.makedirs(out_dir, exist_ok=True)
        src_path = os.path.join(out_dir, "source.bpf.c")
        with open(src_path, "w") as f:
            f.write(source)
        os.chmod(src_path, 0o444)

        res = BuildResult(False, "setup")
        scx = self.scx_inc()
        if not scx:
            res.log = ("scx headers not found (need scx/common.bpf.h): run tools/fetch-scx-include.sh "
                       "<linux-src>, or set SCX_INC / --scx-inc")
            return res
        vdir, err = self.vmlinux_dir()
        if err:
            res.log = err
            return res
        pdir = self.probe_header(vdir)
        res.tools = {"clang": self._version([self.clang, "--version"]),
                     "bpftool": self._version([self.bpftool, "--version"]),
                     "scx_inc": scx, "arch": self.machine, "release": self.release}

        obj = os.path.join(out_dir, "sched.bpf.o")
        rc, out = self._exec([self.clang, "-g", "-O2", "-Wall", "-Werror=implicit-function-declaration",
                              "-Werror=int-conversion", "-mcpu=v3", "-target", "bpf",
                              f"-D__TARGET_ARCH_{self.arch_def}", *self._incs([pdir, vdir]),
                              "-c", src_path, "-o", obj], cwd=out_dir, as_user=True)
        res.log = out
        if rc != 0:
            res.stage = "compile"
            res.log = _tail(out)
            return res

        probs = genstatic.elf_problems(obj) + genstatic.extra_map_problems(obj)
        if probs:
            res.stage, res.log = "object", "compiled object rejected:\n  " + "\n  ".join(probs)
            return res

        skel = os.path.join(out_dir, "scx_gen.bpf.skel.h")
        rc, out = self._exec([self.bpftool, "gen", "skeleton", obj, "name", "scx_gen"], limits=False)
        if rc != 0:
            res.stage, res.log = "skeleton", _tail(out)
            return res
        with open(skel, "w") as f:
            f.write(out)

        loader = os.path.join(out_dir, "gen_load")
        cmd = [self.cc, "-g", "-O2", "-Wall", "-DGEN_BUILD", "-I" + out_dir, *self._incs([]),
               os.path.join(self.repo_root, "loader", "conductor_load.c"), "-o", loader,
               *self.extra_ldlibs, "-lbpf", "-lelf", "-lz", "-lzstd"]
        rc, out = self._exec(cmd, cwd=out_dir)
        if rc != 0:
            res.stage, res.log = "link", _tail(out)
            return res

        res.files = {"source": sha256_file(src_path), "obj": sha256_file(obj), "loader": sha256_file(loader)}
        res.ok, res.stage, res.log = True, "ok", ""
        return res

    # ------------------------------------------------------------ diagnostics
    def check(self) -> list:
        """[(name, ok, detail)] for `conductord doctor`."""
        rows = []

        def add(name, ok, detail=""):
            rows.append((name, bool(ok), detail))

        w = shutil.which
        add("clang", w(self.clang), self._version([self.clang, "--version"]) if w(self.clang) else "not found")
        if w(self.clang):
            rc, out = self._exec([self.clang, "-print-targets"], limits=False)
            add("clang BPF target", rc == 0 and " bpf" in out, "needed for -target bpf")
        add("bpftool", w(self.bpftool), self._version([self.bpftool, "--version"]) if w(self.bpftool) else "not found")
        add("cc (loader)", w(self.cc), self.cc)
        scx = self.scx_inc()
        add("scx headers", scx, scx or "scx/common.bpf.h not found (tools/fetch-scx-include.sh)")
        add("kernel BTF", os.path.isfile("/sys/kernel/btf/vmlinux"), "/sys/kernel/btf/vmlinux")
        has_scx = os.path.isdir("/sys/kernel/sched_ext")
        add("sched_ext in running kernel", has_scx,
            "/sys/kernel/sched_ext present" if has_scx else "missing: kernel needs CONFIG_SCHED_CLASS_EXT=y")
        add("openssl", w("openssl"), "Ed25519 signing")
        add("prlimit", w("prlimit"), "optional: resource limits for compiles")
        if scx and w(self.cc):
            rc, out = self._exec([self.cc, *self._incs([]), "-fsyntax-only", "-x", "c", "-"],
                                 stdin=b"#include <bpf/libbpf.h>\n#include <scx/common.h>\n", limits=False)
            add("libbpf + scx userspace headers", rc == 0, "ok" if rc == 0 else out[-200:])
        return rows


def write_file(path: str, text: str, mode: int = 0o644) -> None:
    tmp = f"{path}.{os.getpid()}.{int(time.time() * 1000)}.tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)

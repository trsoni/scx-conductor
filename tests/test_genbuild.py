import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from conductord import genbuild
from conductord.genbuild import Toolchain
from tests.genhelpers import GOOD_SECTIONS, ROOT, make_elf

FAKE_CLANG = r"""#!/bin/bash
for a in "$@"; do [ "$a" = "--version" ] && { echo "fake clang 1.0"; exit 0; }; done
for a in "$@"; do [ "$a" = "-print-targets" ] && { echo "  bpf - BPF (host endian)"; exit 0; }; done
for a in "$@"; do
  if [ "$a" = "-fsyntax-only" ]; then
    in=$(cat)
    case "$in" in
      *"(0, 0)"*) [ "$FAKE_2ARG" = 1 ] && exit 0 || exit 1;;
      *) [ "$FAKE_1ARG" = 1 ] && exit 0 || exit 1;;
    esac
  fi
done
out=""; prev=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
echo "$@" >> "$FAKE_LOG"
if [ -n "$FAKE_CLANG_FAIL" ]; then echo "source.bpf.c:3:1: error: fake compile error" >&2; exit 1; fi
cp "$FAKE_OBJ" "$out"
"""
FAKE_BPFTOOL = r"""#!/bin/bash
[ "$1" = "--version" ] && { echo "fake bpftool v1"; exit 0; }
if [ "$1" = "btf" ]; then echo "$FAKE_VMLINUX"; exit 0; fi
if [ "$1" = "gen" ]; then
  [ -n "$FAKE_SKEL_FAIL" ] && { echo "libbpf: skeleton failure" >&2; exit 1; }
  echo "/* fake skeleton */"; exit 0
fi
exit 1
"""
FAKE_CC = r"""#!/bin/bash
for a in "$@"; do [ "$a" = "-fsyntax-only" ] && { cat >/dev/null; exit 0; }; done
out=""; prev=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
echo "$@" >> "$FAKE_LOG"
[ -n "$FAKE_CC_FAIL" ] && { echo "conductor_load.c: error: fake link error" >&2; exit 1; }
echo "LOADER-BINARY" > "$out"
"""


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def read(path):
    with open(path) as f:
        return f.read()


def script(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)
    return path


class ToolchainBase(unittest.TestCase):
    ENV = ("FAKE_OBJ", "FAKE_LOG", "FAKE_VMLINUX", "FAKE_2ARG", "FAKE_1ARG", "FAKE_CLANG_FAIL",
           "FAKE_SKEL_FAIL", "FAKE_CC_FAIL", "SCX_INC", "VMLINUX_DIR")

    def setUp(self):
        self.saved = {k: os.environ.get(k) for k in self.ENV}
        for k in self.ENV:
            os.environ.pop(k, None)
        self.d = tempfile.mkdtemp(prefix="tc-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.clang = script(os.path.join(self.d, "fake-clang"), FAKE_CLANG)
        self.bpftool = script(os.path.join(self.d, "fake-bpftool"), FAKE_BPFTOOL)
        self.cc = script(os.path.join(self.d, "fake-cc"), FAKE_CC)
        self.obj = os.path.join(self.d, "good.o")
        with open(self.obj, "wb") as f:
            f.write(make_elf(GOOD_SECTIONS))
        self.log = os.path.join(self.d, "calls.log")
        os.environ.update({"FAKE_OBJ": self.obj, "FAKE_LOG": self.log,
                           "FAKE_VMLINUX": "struct task_struct { int pid; };", "FAKE_2ARG": "1"})
        self.scx = os.path.join(self.d, "scx-inc")
        os.makedirs(os.path.join(self.scx, "scx"))
        write(os.path.join(self.scx, "scx", "common.bpf.h"), "/* fake */")
        self.work = os.path.join(self.d, "work")

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def tc(self, **kw):
        kw.setdefault("scx_inc", self.scx)
        return Toolchain(ROOT, self.work, clang=self.clang, bpftool=self.bpftool, cc=self.cc,
                         arch="x86_64", release="6.99.0-test", extra_cflags=[], extra_ldlibs=[], **kw)

    def log_lines(self):
        try:
            return read(self.log).splitlines()
        except OSError:
            return []


class TestBuild(ToolchainBase):
    def test_success(self):
        out = os.path.join(self.d, "out")
        r = self.tc().build("int x;\n", out)
        self.assertTrue(r.ok, r.log)
        self.assertEqual(set(r.files), {"source", "obj", "loader"})
        self.assertEqual(r.tools["clang"], "fake clang 1.0")
        self.assertEqual(r.tools["arch"], "x86_64")
        for f in ("source.bpf.c", "sched.bpf.o", "scx_gen.bpf.skel.h", "gen_load"):
            self.assertTrue(os.path.exists(os.path.join(out, f)), f)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(out, "source.bpf.c")).st_mode), 0o444)

    def test_compile_flags(self):
        self.tc().build("int x;\n", os.path.join(self.d, "out"))
        clang_call = [l for l in self.log_lines() if "-target bpf" in l][0]
        for flag in ("-mcpu=v3", "-D__TARGET_ARCH_x86", "-Werror=implicit-function-declaration", "-O2", "-g"):
            self.assertIn(flag, clang_call)
        cc_call = [l for l in self.log_lines() if "-DGEN_BUILD" in l][0]
        self.assertIn("conductor_load.c", cc_call)
        for lib in ("-lbpf", "-lelf", "-lz", "-lzstd"):
            self.assertIn(lib, cc_call)

    def test_arch_define_arm64(self):
        tc = Toolchain(ROOT, self.work, clang=self.clang, bpftool=self.bpftool, cc=self.cc, scx_inc=self.scx,
                       arch="aarch64", release="6.99.0-test", extra_cflags=[], extra_ldlibs=[])
        tc.build("int x;\n", os.path.join(self.d, "out"))
        self.assertIn("-D__TARGET_ARCH_arm64", [l for l in self.log_lines() if "-target bpf" in l][0])

    def test_compile_error_is_reported_with_clang_output(self):
        os.environ["FAKE_CLANG_FAIL"] = "1"
        r = self.tc().build("int x;\n", os.path.join(self.d, "out"))
        self.assertFalse(r.ok)
        self.assertEqual(r.stage, "compile")
        self.assertIn("fake compile error", r.log)

    def test_skeleton_and_link_failures(self):
        os.environ["FAKE_SKEL_FAIL"] = "1"
        r = self.tc().build("int x;\n", os.path.join(self.d, "o1"))
        self.assertEqual((r.ok, r.stage), (False, "skeleton"))
        del os.environ["FAKE_SKEL_FAIL"]
        os.environ["FAKE_CC_FAIL"] = "1"
        r = self.tc().build("int x;\n", os.path.join(self.d, "o2"))
        self.assertEqual((r.ok, r.stage), (False, "link"))
        self.assertIn("fake link error", r.log)

    def test_unexpected_program_section_rejected_after_compile(self):
        with open(self.obj, "wb") as f:
            f.write(make_elf(GOOD_SECTIONS + [("tp/sched/sched_switch", 1, 16)]))
        r = self.tc().build("int x;\n", os.path.join(self.d, "out"))
        self.assertEqual((r.ok, r.stage), (False, "object"))
        self.assertIn("tp/sched/sched_switch", r.log)

    def test_extra_map_rejected(self):
        with open(self.obj, "wb") as f:
            f.write(make_elf(GOOD_SECTIONS, [("tgid_class", ".maps"), ("my_map", ".maps")]))
        r = self.tc().build("int x;\n", os.path.join(self.d, "out"))
        self.assertEqual((r.ok, r.stage), (False, "object"))
        self.assertIn("my_map", r.log)

    def test_missing_scx_headers(self):
        with mock.patch.object(genbuild, "SCX_CANDIDATES_ABS", ()), \
                mock.patch.object(genbuild, "SCX_CANDIDATES_REL", ()):
            tc = Toolchain(ROOT, self.work, clang=self.clang, bpftool=self.bpftool, cc=self.cc,
                           release="0-none", extra_cflags=[], extra_ldlibs=[])
            r = tc.build("int x;\n", os.path.join(self.d, "out"))
        self.assertEqual((r.ok, r.stage), (False, "setup"))
        self.assertIn("scx headers not found", r.log)

    def test_scx_inc_from_env(self):
        os.environ["SCX_INC"] = self.scx
        with mock.patch.object(genbuild, "SCX_CANDIDATES_ABS", ()), mock.patch.object(genbuild, "SCX_CANDIDATES_REL", ()):
            tc = Toolchain(ROOT, self.work, clang=self.clang, bpftool=self.bpftool, cc=self.cc,
                           release="0-none", extra_cflags=[], extra_ldlibs=[])
            self.assertEqual(tc.scx_inc(), self.scx)

    def test_timeout_is_a_failure_not_a_hang(self):
        def runner(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        r = self.tc(runner=runner, vmlinux_dir=self.work).build("int x;\n", os.path.join(self.d, "out"))
        self.assertFalse(r.ok)

    def test_resource_limits_and_user_drop(self):
        calls = []

        def runner(argv, **kw):
            calls.append((argv, kw))
            return subprocess.CompletedProcess(argv, 1, b"", b"stop")
        os.makedirs(self.work, exist_ok=True)
        os.makedirs(os.path.join(self.work, "toolchain", "6.99.0-test", "probe"), exist_ok=True)
        write(os.path.join(self.work, "toolchain", "6.99.0-test", "vmlinux.h"), "struct task_struct{};")
        write(os.path.join(self.work, "toolchain", "6.99.0-test", "probe", "conductor_probe.h"), "")
        with mock.patch("os.geteuid", return_value=0):
            self.tc(runner=runner, drop_user="nobody").build("int x;\n", os.path.join(self.d, "out"))
        compile_calls = [c for c in calls if "-target" in c[0]]
        self.assertTrue(compile_calls)
        argv, kw = compile_calls[0]
        if shutil.which("prlimit"):
            self.assertEqual(argv[0], "prlimit")
            self.assertTrue(any(a.startswith("--cpu=") for a in argv))
            self.assertTrue(any(a.startswith("--as=") for a in argv))
        self.assertEqual(kw.get("user"), "nobody")


class TestCachedInputs(ToolchainBase):
    def test_vmlinux_generated_once_per_kernel(self):
        tc = self.tc()
        d1, err = tc.vmlinux_dir()
        self.assertIsNone(err)
        h = os.path.join(d1, "vmlinux.h")
        self.assertIn("struct task_struct", read(h))
        m1 = os.stat(h).st_mtime_ns
        d2, _ = self.tc().vmlinux_dir()
        self.assertEqual(os.stat(os.path.join(d2, "vmlinux.h")).st_mtime_ns, m1)
        self.assertTrue(d1.endswith("6.99.0-test"))

    def test_bad_btf_dump_is_a_setup_error(self):
        os.environ["FAKE_VMLINUX"] = "garbage"
        r = self.tc().build("int x;\n", os.path.join(self.d, "out"))
        self.assertEqual((r.ok, r.stage), (False, "setup"))
        self.assertIn("vmlinux.h", r.log)

    def test_explicit_vmlinux_dir(self):
        vd = os.path.join(self.d, "vm")
        os.makedirs(vd)
        write(os.path.join(vd, "vmlinux.h"), "x")
        self.assertEqual(self.tc(vmlinux_dir=vd).vmlinux_dir(), (vd, None))
        self.assertIsNone(self.tc(vmlinux_dir=os.path.join(self.d, "nope")).vmlinux_dir()[0])

    def probe_text(self, tc):
        d, _ = tc.vmlinux_dir()
        pd = tc.probe_header(d)
        return read(os.path.join(pd, "conductor_probe.h"))

    def test_probe_two_arg(self):
        self.assertIn("#define CND_MOVE_TO_LOCAL_2ARG 1", self.probe_text(self.tc()))

    def test_probe_one_arg(self):
        del os.environ["FAKE_2ARG"]
        os.environ["FAKE_1ARG"] = "1"
        txt = self.probe_text(self.tc())
        self.assertNotIn("#define CND_MOVE_TO_LOCAL_2ARG", txt)
        self.assertIn("1 argument", txt)

    def test_probe_failure_leaves_define_unset_and_says_so(self):
        del os.environ["FAKE_2ARG"]
        txt = self.probe_text(self.tc())
        self.assertNotIn("#define CND_MOVE_TO_LOCAL_2ARG", txt)
        self.assertIn("probe failed", txt)

    def test_probe_is_cached(self):
        tc = self.tc()
        d, _ = tc.vmlinux_dir()
        p = os.path.join(tc.probe_header(d), "conductor_probe.h")
        m1 = os.stat(p).st_mtime_ns
        os.environ["FAKE_2ARG"] = ""
        tc.probe_header(d)
        self.assertEqual(os.stat(p).st_mtime_ns, m1)


class TestCheck(ToolchainBase):
    def test_all_present(self):
        rows = {n: ok for n, ok, _ in self.tc().check()}
        for name in ("clang", "clang BPF target", "bpftool", "cc (loader)", "scx headers", "openssl"):
            self.assertTrue(rows[name], name)

    def test_missing_pieces_reported(self):
        tc = Toolchain(ROOT, self.work, clang="/nonexistent/clang", bpftool="/nonexistent/bpftool",
                       cc="/nonexistent/cc", scx_inc=os.path.join(self.d, "nope"), release="0-none",
                       extra_cflags=[], extra_ldlibs=[])
        with mock.patch.object(genbuild, "SCX_CANDIDATES_ABS", ()), mock.patch.object(genbuild, "SCX_CANDIDATES_REL", ()):
            rows = {n: ok for n, ok, _ in tc.check()}
        for name in ("clang", "bpftool", "cc (loader)", "scx headers"):
            self.assertFalse(rows[name], name)


class TestRealBuild(unittest.TestCase):
    """Builds the reference scheduler with REAL clang/bpftool/libbpf/scx headers.

    Skipped unless CONDUCTOR_TEST_SCX_INC and CONDUCTOR_TEST_VMLINUX_DIR are set (a vmlinux.h
    that contains sched_ext types, e.g. from your kernel's BTF or the scx repo's scheds/vmlinux).
    Optional: CONDUCTOR_TEST_CFLAGS / CONDUCTOR_TEST_LDLIBS for non-standard libbpf locations.
    """

    def test_template_backend_source_builds_and_loader_runs(self):
        scx, vm = os.environ.get("CONDUCTOR_TEST_SCX_INC"), os.environ.get("CONDUCTOR_TEST_VMLINUX_DIR")
        if not scx or not vm:
            self.skipTest("CONDUCTOR_TEST_SCX_INC / CONDUCTOR_TEST_VMLINUX_DIR not set")
        import shlex
        from conductord.genbackends import TemplateBackend, extract_c
        from conductord import genstatic
        from tests.genhelpers import TEMPLATE, params
        src = extract_c(TemplateBackend(TEMPLATE).complete("", "", {"params": params()}))
        self.assertEqual(genstatic.check(src), [])
        w = tempfile.mkdtemp(prefix="real-")
        self.addCleanup(shutil.rmtree, w, ignore_errors=True)
        tc = Toolchain(ROOT, w, scx_inc=scx, vmlinux_dir=vm,
                       extra_cflags=shlex.split(os.environ.get("CONDUCTOR_TEST_CFLAGS", "")),
                       extra_ldlibs=shlex.split(os.environ.get("CONDUCTOR_TEST_LDLIBS", "")))
        r = tc.build(src, os.path.join(w, "g"))
        self.assertTrue(r.ok, f"{r.stage}: {r.log}")
        self.assertEqual(genstatic.elf_problems(os.path.join(w, "g", "sched.bpf.o")), [])
        # the generated loader refuses the template's knob flags (before touching the kernel)
        p = subprocess.run([os.path.join(w, "g", "gen_load"), "--slice-ns", "1,2,3,4"], capture_output=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn(b"not supported for a generated scheduler", p.stderr)


if __name__ == "__main__":
    unittest.main()

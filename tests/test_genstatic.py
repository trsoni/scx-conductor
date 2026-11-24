import os
import tempfile
import unittest

from conductord import genstatic as g
from tests.genhelpers import GOOD_SECTIONS, TEMPLATE, good_source, make_elf


def problems_of(src):
    return " | ".join(g.check(src))


class TestGateAccepts(unittest.TestCase):
    def test_template_derived_source_passes(self):
        self.assertEqual(g.check(good_source()), [])

    def test_every_workload_template_passes(self):
        from conductord.model import Workload
        for wl in Workload:
            if wl == Workload.IDLE:
                continue
            self.assertEqual(g.check(good_source(wl)), [], wl)

    def test_forbidden_words_in_comments_and_strings_are_ignored(self):
        src = good_source().replace("static u64 vtime_now;",
                                    '/* asm volatile ("x"); extern int y; SEC("kprobe/x") */\n'
                                    '// bpf_probe_read_kernel ## paste\n'
                                    'static const char note[] = "asm extern bpf_probe_read_kernel ##";\n'
                                    'static u64 vtime_now;')
        self.assertEqual(g.check(src), [])


class TestGateRejects(unittest.TestCase):
    def mutate(self, old, new):
        s = good_source()
        self.assertIn(old, s)
        return s.replace(old, new, 1)

    def test_inline_asm(self):
        s = self.mutate("static u64 vtime_now;", 'static u64 vtime_now;\nstatic void f(void){ asm volatile("r0 = 0" ::: "r0"); }')
        self.assertIn("'asm'", problems_of(s))

    def test_dunder_asm_variants(self):
        for kw in ("__asm__", "__asm"):
            s = self.mutate("static u64 vtime_now;", f'static u64 vtime_now;\nstatic void f(void){{ {kw}("x"); }}')
            self.assertIn(kw, problems_of(s))

    def test_extern_ksym_and_sec(self):
        s = self.mutate("static u64 vtime_now;", "extern int bad_kfunc(void) __ksym;\nstatic u64 vtime_now;")
        p = problems_of(s)
        self.assertIn("'extern'", p)
        self.assertIn("__ksym", p)
        s = self.mutate("static u64 vtime_now;", 'SEC("kprobe/foo") int h(void *c){ return 0; }\nstatic u64 vtime_now;')
        self.assertIn("'SEC'", problems_of(s))

    def test_attribute_and_pragma(self):
        s = self.mutate("static u64 vtime_now;", '__attribute__((section("tp/x"))) static u64 vtime_now;')
        self.assertIn("__attribute__", problems_of(s))
        s = self.mutate("static u64 vtime_now;", "#pragma clang loop unroll(full)\nstatic u64 vtime_now;")
        self.assertIn("#pragma", problems_of(s))

    def test_token_pasting_and_digraphs_and_trigraphs(self):
        s = self.mutate("static u64 vtime_now;", "#define CAT(a,b) a##b\nstatic u64 vtime_now;")
        self.assertIn("token pasting", problems_of(s))
        s = self.mutate("static u64 vtime_now;", "static u64 vtime_now;\nint a<:2:>;")
        self.assertIn("digraph", problems_of(s))
        s = self.mutate("static u64 vtime_now;", 'static u64 vtime_now;\nconst char *t = "??/";')
        self.assertIn("trigraph", problems_of(s))

    def test_unknown_include(self):
        s = self.mutate('#include "conductor_abi.bpf.h"', '#include "conductor_abi.bpf.h"\n#include <linux/bpf.h>')
        self.assertIn("only #include of", problems_of(s))

    def test_include_via_macro_is_rejected(self):
        s = self.mutate('#include "conductor_abi.bpf.h"', '#define H "/etc/passwd"\n#include H')
        self.assertIn("only #include of", problems_of(s))

    def test_helper_not_on_allowlist(self):
        s = self.mutate("conductor_stat_inc(ST_PERF_SET);", "bpf_probe_read_kernel(&vtime_now, 8, 0); conductor_stat_inc(ST_PERF_SET);")
        self.assertIn("bpf_probe_read_kernel", problems_of(s))
        s = self.mutate("conductor_stat_inc(ST_PERF_SET);", "bpf_send_signal(9); conductor_stat_inc(ST_PERF_SET);")
        self.assertIn("bpf_send_signal", problems_of(s))
        s = self.mutate("conductor_stat_inc(ST_PERF_SET);", "scx_bpf_exit_bstr(0, 0, 0, 0); conductor_stat_inc(ST_PERF_SET);")
        self.assertIn("scx_bpf_exit_bstr", problems_of(s))

    def test_bpf_macros_and_uei(self):
        s = self.mutate("static u64 vtime_now;", "BPF_CORE_READ(x, y);\nstatic u64 vtime_now;")
        self.assertIn("BPF_CORE_READ", problems_of(s))
        s = self.mutate("static u64 vtime_now;", "static u64 vtime_now;\nUEI_DEFINE(other);")
        self.assertIn("UEI_DEFINE", problems_of(s))

    def test_function_pointer_helper_id_idiom(self):
        s = self.mutate("conductor_stat_inc(ST_PERF_SET);",
                        "((long (*)(void *, int))1)(0, 0); conductor_stat_inc(ST_PERF_SET);")
        self.assertIn("function-pointer", problems_of(s))
        s = self.mutate("conductor_stat_inc(ST_PERF_SET);",
                        "((void *)0xffff0000); conductor_stat_inc(ST_PERF_SET);")
        self.assertIn("integer literal to a pointer", problems_of(s))

    def test_raw_move_to_local_kfunc_points_at_wrapper(self):
        s = self.mutate("conductor_move_to_local(SHARED_DSQ);", "scx_bpf_dsq_move_to_local(SHARED_DSQ);")
        self.assertIn("conductor_move_to_local", problems_of(s))

    def test_ops_table_rules(self):
        s = self.mutate("SCX_OPS_DEFINE(gen_ops,", "SCX_OPS_DEFINE(my_ops,")
        self.assertIn("must be named gen_ops", problems_of(s))
        s = self.mutate('.name\t\t= "conductor_gen"', '.name\t\t= "other"')
        self.assertIn('.name must be "conductor_gen"', problems_of(s))
        s = self.mutate('.exit\t\t= (void *)conductor_exit,',
                        '.exit\t\t= (void *)conductor_exit,\n\t       .flags = 1,')
        self.assertIn(".flags must not be set", problems_of(s))
        s = self.mutate('.exit\t\t= (void *)conductor_exit,',
                        '.exit\t\t= (void *)conductor_exit,\n\t       .timeout_ms = 60000,')
        self.assertIn(".timeout_ms must not be set", problems_of(s))
        s = self.mutate('.exit\t\t= (void *)conductor_exit,',
                        '.exit\t\t= (void *)conductor_exit,\n\t       .cgroup_init = (void *)conductor_exit,')
        self.assertIn(".cgroup_init is not an allowed ops member", problems_of(s))

    def test_telemetry_contract(self):
        s = self.mutate("u32 cls = conductor_note_running(p);", "u32 cls = CLS_NORMAL;")
        self.assertIn("conductor_note_running() is never called", problems_of(s))
        s = self.mutate("UEI_RECORD(uei, ei);", "")
        self.assertIn("UEI_RECORD() is never called", problems_of(s))

    def test_missing_abi_include(self):
        s = self.mutate('#include "conductor_abi.bpf.h"', '#include <scx/common.bpf.h>')
        self.assertIn('missing #include "conductor_abi.bpf.h"', problems_of(s))

    def test_limits(self):
        self.assertIn("limit", problems_of("x" * (g.MAX_SOURCE_BYTES + 1)))
        self.assertEqual(g.check(""), ["empty source"])
        s = good_source() + "\n/* unterminated"
        self.assertIn("unterminated", problems_of(s))
        s = good_source().replace("static u64 vtime_now;", "static u64 vtime_now; /* café */ int é;")
        self.assertIn("non-ASCII", problems_of(s))

    def test_directives_other_than_allowed(self):
        s = self.mutate("static u64 vtime_now;", "#error nope\nstatic u64 vtime_now;")
        self.assertIn("'#error'", problems_of(s))

    def test_line_continuation_cannot_hide_a_token(self):
        s = self.mutate("static u64 vtime_now;", "static u64 vtime_now;\nstatic void f(void){ as\\\nm(\"x\"); }")
        self.assertIn("'asm'", problems_of(s))


class TestStripComments(unittest.TestCase):
    def test_block_comment_keeps_line_numbers(self):
        code, errs = g.strip_comments("a\n/* x\ny */\nb")
        self.assertEqual(errs, [])
        self.assertEqual(code.count("\n"), 3)

    def test_slash_slash_in_string_is_not_a_comment(self):
        code, _ = g.strip_comments('x = "// not a comment"; y')
        self.assertIn("not a comment", code)
        self.assertIn("y", code)


class TestElf(unittest.TestCase):
    def write(self, data):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".o")
        f.write(data)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_good_object(self):
        p = self.write(make_elf(GOOD_SECTIONS))
        self.assertEqual(g.elf_problems(p), [])

    def test_unexpected_program_section(self):
        p = self.write(make_elf(GOOD_SECTIONS + [("kprobe/do_sys_open", 1, 32)]))
        self.assertIn("unexpected section 'kprobe/do_sys_open'", " ".join(g.elf_problems(p)))
        p = self.write(make_elf(GOOD_SECTIONS + [("xdp", 1, 32)]))
        self.assertIn("'xdp'", " ".join(g.elf_problems(p)))

    def test_missing_struct_ops_link(self):
        secs = [s for s in GOOD_SECTIONS if s[0] != ".struct_ops.link"]
        self.assertIn("no .struct_ops.link", " ".join(g.elf_problems(self.write(make_elf(secs)))))

    def test_huge_static_data(self):
        secs = [s for s in GOOD_SECTIONS if s[0] != ".bss"] + [(".bss", 8, g.MAX_DATA_BYTES + 1)]
        self.assertIn("static data", " ".join(g.elf_problems(self.write(make_elf(secs)))))

    def test_garbage_is_rejected_not_crashed(self):
        self.assertIn("cannot parse", " ".join(g.elf_problems(self.write(b"not an elf"))))
        self.assertIn("cannot parse", " ".join(g.elf_problems("/nonexistent/x.o")))

    def test_extra_maps_detected(self):
        syms = [("tgid_class", ".maps"), ("stats", ".maps"), ("evil_map", ".maps")]
        p = self.write(make_elf(GOOD_SECTIONS, syms))
        probs = g.extra_map_problems(p)
        self.assertEqual(len(probs), 1)
        self.assertIn("evil_map", probs[0])
        p = self.write(make_elf(GOOD_SECTIONS, [("tgid_class", ".maps"), ("lat_hist", ".maps")]))
        self.assertEqual(g.extra_map_problems(p), [])

    def test_real_template_object_if_available(self):
        """Set CONDUCTOR_TEST_OBJ to a compiled scx_conductor.bpf.o to check the allowlist against reality."""
        p = os.environ.get("CONDUCTOR_TEST_OBJ")
        if not p or not os.path.exists(p):
            self.skipTest("CONDUCTOR_TEST_OBJ not set")
        self.assertEqual(g.elf_problems(p), [])
        self.assertEqual(g.extra_map_problems(p), [])
        # and the map inspection really sees the four ABI maps (not an empty list by accident)
        names = sorted(x.split("'")[1] for x in g.extra_map_problems(p, allowed=set()))
        self.assertEqual(names, ["lat_hist", "stats", "task_ctx_stor", "tgid_class"])


if __name__ == "__main__":
    unittest.main()

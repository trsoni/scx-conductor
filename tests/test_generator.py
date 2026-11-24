import json
import os
import shutil
import threading
import time
import unittest

from conductord import generator as gen
from conductord.genbackends import CallableBackend, GenError
from conductord.genstore import GenStore
from conductord.model import Workload
from tests.genhelpers import FakeToolchain, MACHINE, RELEASE, good_source, params, reply
from tests.helpers import ROOT, Env, profiles


class GenCase(unittest.TestCase):
    def setUp(self):
        self.e = Env("laptop")
        self.addCleanup(shutil.rmtree, self.e.d, ignore_errors=True)
        self.store = GenStore(os.path.join(self.e.d, "generated"))
        self.prompts = []

    def make(self, replies, tc=None, verify=None, canary=None, approval="ask", max_attempts=3):
        replies = list(replies)

        def fn(system, user, ctx):
            self.prompts.append(user)
            r = replies.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        self.tc = tc or FakeToolchain()
        return gen.Generator(backend=CallableBackend(fn), toolchain=self.tc, store=self.store, repo_root=ROOT,
                             audit=self.e.audit, verify_fn=verify or (lambda d: (True, "kernel ok")),
                             canary_fn=canary, approval=approval,
                             priv_key=self.e.priv if approval == "auto" else None,
                             max_attempts=max_attempts, profiles=profiles())

    def run_gen(self, g, wl=Workload.GAMING):
        return g.generate(wl, "laptop", "ac", params(wl))


class TestPipeline(GenCase):
    def test_success_on_first_attempt_is_pending_with_review(self):
        g = self.make([reply(good_source())])
        r = self.run_gen(g)
        self.assertEqual((r.ok, r.status, r.attempts), (True, "pending", 1))
        m = self.store.meta(r.gen_id)
        self.assertEqual((m["status"], m["gate"], m["arch"], m["kernel_release"]), ("pending", "pass", MACHINE, RELEASE))
        self.assertEqual(m["verify"], {"ok": True, "detail": "kernel ok"})
        self.assertTrue(os.path.exists(os.path.join(self.store.dir(r.gen_id), "review.md")))
        self.assertIsNone(self.store.approval(r.gen_id))                 # never self-approved
        ev = self.e.events()
        self.assertEqual([x for x in ev if x.startswith("gen-")], ["gen-start", "gen-built", "gen-verified", "gen-ready"])

    def test_gate_failure_is_fed_back_and_repaired(self):
        bad = good_source().replace("static u64 vtime_now;", 'static u64 vtime_now;\nstatic void f(void){ asm volatile("x"); }')
        g = self.make([reply(bad), reply(good_source())])
        r = self.run_gen(g)
        self.assertEqual((r.ok, r.attempts), (True, 2))
        self.assertEqual(len(self.tc.calls), 1)                          # the bad source never reached the compiler
        self.assertIn("Your previous attempt failed at: static-gate", self.prompts[1])
        self.assertIn("'asm'", self.prompts[1])
        self.assertIn("asm volatile", self.prompts[1])                   # previous source included
        self.assertNotIn("previous attempt failed", self.prompts[0])

    def test_compile_error_is_fed_back(self):
        g = self.make([reply(good_source()), reply(good_source(tweak=1))],
                      tc=FakeToolchain([("compile", "source.bpf.c:9:3: error: use of undeclared identifier 'foo'")]))
        r = self.run_gen(g)
        self.assertTrue(r.ok)
        self.assertIn("build:compile", self.prompts[1])
        self.assertIn("undeclared identifier 'foo'", self.prompts[1])
        failed = [m for m in self.store.list(include_failed=True) if m["status"] == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertTrue(os.path.exists(os.path.join(self.store.dir(failed[0]["id"]), "build.log")))

    def test_verifier_log_is_fed_back(self):
        calls = []

        def verify(d):
            calls.append(d)
            return (False, "R3 invalid mem access 'scalar'") if len(calls) == 1 else (True, "ok")
        g = self.make([reply(good_source()), reply(good_source(tweak=1))], verify=verify)
        r = self.run_gen(g)
        self.assertTrue(r.ok)
        self.assertIn("kernel-verifier", self.prompts[1])
        self.assertIn("invalid mem access", self.prompts[1])

    def test_format_error_asks_for_a_fenced_block(self):
        g = self.make(["I would suggest a scheduler that...", reply(good_source())])
        self.assertTrue(self.run_gen(g).ok)
        self.assertIn("exactly one fenced", self.prompts[1])

    def test_gives_up_after_max_attempts(self):
        bad = reply("```c\nint nope;\n```")
        g = self.make([bad, bad, bad], max_attempts=3)
        r = self.run_gen(g)
        self.assertFalse(r.ok)
        self.assertEqual((r.stage, r.attempts), ("static-gate", 3))
        self.assertEqual(len(self.prompts), 3)
        self.assertIn("gen-failed", self.e.events())
        self.assertEqual(self.store.list(), [])

    def test_backend_error_stops_without_retrying(self):
        g = self.make([GenError("API error 401"), reply(good_source())])
        r = self.run_gen(g)
        self.assertEqual((r.ok, r.stage, r.attempts), (False, "backend", 1))
        self.assertEqual(len(self.prompts), 1)

    def test_duplicate_source_is_not_rebuilt(self):
        g = self.make([reply(good_source()), reply(good_source())])
        first = self.run_gen(g)
        second = self.run_gen(g)
        self.assertEqual((second.ok, second.status, second.gen_id), (True, "duplicate", first.gen_id))
        self.assertEqual(len(self.tc.calls), 1)

    def test_canary_failure_rejects_and_cannot_be_approved(self):
        g = self.make([reply(good_source())], canary=lambda d, p: (False, "p99 90000us > 50000us"))
        r = self.run_gen(g)
        self.assertEqual((r.ok, r.status, r.stage), (False, "rejected", "canary"))
        m = self.store.meta(r.gen_id)
        self.assertEqual((m["status"], m["reject_reason"]), ("rejected", "canary failed"))
        with self.assertRaises(ValueError):
            self.store.approve(r.gen_id, self.e.priv)

    def test_canary_skipped_stays_pending_canary_passed_recorded(self):
        g = self.make([reply(good_source())], canary=lambda d, p: (None, "skipped: another sched_ext scheduler is active"))
        r = self.run_gen(g)
        self.assertEqual((r.ok, r.status), (True, "pending"))
        self.assertIsNone(self.store.meta(r.gen_id)["canary"]["ok"])
        g2 = self.make([reply(good_source(tweak=5))], canary=lambda d, p: (True, {"p99_us": 120}))
        r2 = self.run_gen(g2)
        self.assertEqual(self.store.meta(r2.gen_id)["canary"], {"ok": True, "detail": {"p99_us": 120}})

    def test_auto_approval_signs_and_is_audited(self):
        g = self.make([reply(good_source())], approval="auto")
        r = self.run_gen(g)
        self.assertEqual((r.ok, r.status), (True, "approved"))
        self.assertIsNotNone(self.store.approval(r.gen_id))
        self.assertEqual(self.store.meta(r.gen_id)["approved_by"], "auto")
        self.assertIn("gen-approved", self.e.events())

    def test_auto_approval_does_not_approve_a_canary_failure(self):
        g = self.make([reply(good_source())], approval="auto", canary=lambda d, p: (False, "starved"))
        r = self.run_gen(g)
        self.assertEqual(r.status, "rejected")
        self.assertIsNone(self.store.approval(r.gen_id))

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            gen.Generator(backend=CallableBackend(lambda *a: ""), toolchain=FakeToolchain(), store=self.store,
                          repo_root=ROOT, audit=self.e.audit, verify_fn=lambda d: (True, ""), approval="auto")
        with self.assertRaises(ValueError):
            gen.Generator(backend=CallableBackend(lambda *a: ""), toolchain=FakeToolchain(), store=self.store,
                          repo_root=ROOT, audit=self.e.audit, verify_fn=lambda d: (True, ""), approval="maybe")

    def test_audit_chain_stays_valid_across_a_run(self):
        from conductord.audit import verify_chain
        g = self.make([reply(good_source())])
        self.run_gen(g)
        ok, n, err = verify_chain(self.e.audit.path)
        self.assertTrue(ok, err)
        self.assertGreaterEqual(n, 4)


class TestPrompt(GenCase):
    def test_context_is_numbers_only(self):
        ctx = gen.collect_ctx(Workload.GAMING, "laptop", "ac", params(), release=RELEASE, arch=MACHINE, profiles=profiles())
        self.assertEqual(set(ctx), {"workload", "platform", "power_state", "arch", "kernel_release", "nr_cpus",
                                    "perf_cap", "slice_scale", "canary_p99_limit_us", "watchdog_ms", "baseline"})
        self.assertEqual(set(ctx["baseline"]), {"slice_ns", "credit_ns", "charge_pct", "cpuperf"})

    def test_prompt_contains_contract_and_reference_but_no_user_data(self):
        g = self.make([])
        system, user = g.preview(Workload.GAMING, "laptop", "ac", params())
        for needle in ("SCX_OPS_DEFINE(gen_ops", "conductor_mark_enq", "conductor_move_to_local", "Never starve"):
            self.assertIn(needle, system)
        for needle in ("conductor_abi.bpf.h", "scx_conductor.bpf.c", "Reference scheduler", "Workload: gaming",
                       "baseline", "frame-time"):
            self.assertIn(needle, user)
        # nothing derived from the machine's users or processes
        import getpass
        for secret in (getpass.getuser(), os.uname().nodename, "steam", "gnome-shell", "/home/"):
            if secret == "root":                       # too short to be a meaningful probe
                continue
            self.assertNotIn(secret, system + user, secret)

    def test_allowlists_in_prompt_match_the_gate(self):
        from conductord import genstatic
        system, _ = self.make([]).preview(Workload.GAMING, "laptop", "ac", params())
        for name in genstatic.ALLOWED_BPF_HELPERS + genstatic.ALLOWED_SCX_KFUNCS:
            self.assertIn(name, system)
        for op in genstatic.ALLOWED_OPS:
            self.assertIn("." + op, system)

    def test_every_workload_has_an_intent(self):
        for wl in Workload:
            if wl != Workload.IDLE:
                self.assertIn(wl.value, gen.INTENTS)

    def test_feedback_truncates_huge_logs(self):
        ctx = gen.collect_ctx(Workload.UI, "laptop", "ac", params(Workload.UI), release=RELEASE, arch=MACHINE)
        _, user = gen.build_prompt(ctx, ROOT, {"stage": "compile", "errors": "E" * 20000, "source": "int x;"})
        self.assertLess(len(user), 60000)
        self.assertIn("[truncated]", user)


class TestManager(GenCase):
    def mgr(self, replies, **kw):
        g = self.make(replies)
        return gen.GenManager(g, sync=True, **kw), g

    def test_requests_generate_once_then_report_exists(self):
        m, g = self.mgr([reply(good_source())])
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "started")
        self.assertEqual(m.last["status"], "pending")
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "exists")
        self.assertEqual(len(self.prompts), 1)

    def test_failure_triggers_cooldown(self):
        t = [0.0]
        m, g = self.mgr([GenError("down"), reply(good_source())], cooldown_s=900)
        m.clock = lambda: t[0]
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "started")
        self.assertFalse(m.last["ok"])
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "cooldown")
        t[0] = 901
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "started")
        self.assertTrue(m.last["ok"])

    def test_recent_rejection_is_respected_then_expires(self):
        from tests.genhelpers import make_artifact
        now = [1_700_000_000.0]
        m, g = self.mgr([reply(good_source(tweak=7))], rejected_cooldown_s=3600)
        m.wall = lambda: now[0]
        make_artifact(self.store, status="rejected", created=1_700_000_000)
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "cooldown")
        now[0] += 3601
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "started")

    def test_single_flight_and_nonblocking(self):
        release, started = threading.Event(), threading.Event()

        def slow(system, user, ctx):
            started.set()
            release.wait(10)
            return reply(good_source())
        g = gen.Generator(backend=CallableBackend(slow), toolchain=FakeToolchain(), store=self.store, repo_root=ROOT,
                          audit=self.e.audit, verify_fn=lambda d: (True, "ok"), profiles=profiles())
        m = gen.GenManager(g)
        t0 = time.monotonic()
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "started")
        self.assertLess(time.monotonic() - t0, 1.0)                      # returned without waiting for the model
        self.assertTrue(started.wait(5))
        self.assertTrue(m.status()["busy"])
        self.assertEqual(m.request(Workload.VIDEO, "laptop", "ac", params(Workload.VIDEO)), "busy")
        release.set()
        m.join(10)
        self.assertFalse(m.status()["busy"])
        self.assertEqual(m.last["status"], "pending")

    def test_worker_exception_is_contained_and_cools_down(self):
        class Boom(CallableBackend):
            def complete(self, *a, **k):
                raise RuntimeError("kaboom")
        g = gen.Generator(backend=Boom(lambda *a: ""), toolchain=FakeToolchain(), store=self.store, repo_root=ROOT,
                          audit=self.e.audit, verify_fn=lambda d: (True, "ok"), profiles=profiles())
        m = gen.GenManager(g, sync=True)
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "started")
        self.assertEqual(m.last["stage"], "exception")
        self.assertIn("kaboom", m.last["detail"])
        self.assertFalse(m.status()["busy"])
        self.assertEqual(m.request(Workload.GAMING, "laptop", "ac", params()), "cooldown")


if __name__ == "__main__":
    unittest.main()

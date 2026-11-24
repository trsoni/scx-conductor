import contextlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from conductord import canary as canary_mod
from conductord.canary import make_canary, make_dir_canary
from conductord.daemon import ControlServer, GenSupport, Governor
from conductord.forge import Verifier
from conductord.generator import GenManager, Generator
from conductord.genbackends import CallableBackend
from conductord.genstore import GenForge, GenStore
from conductord.host import FakeHost, LoaderHost, verify_only
from conductord.lifecycle import Lifecycle
from conductord.model import Workload
from tests.genhelpers import FakeToolchain, MACHINE, RELEASE, good_source, make_artifact, params, reply
from tests.helpers import ROOT, Env, P, profiles, snap


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


GAME = lambda: snap([P(100, "steam", 45), P(101, "gnome-shell", 6), P(102, "cc1plus", 70)], util=80)
UI = lambda: snap([P(101, "gnome-shell", 8)], util=15)
IDLE = lambda: snap(util=1)


class GovCase(unittest.TestCase):
    def setUp(self):
        self.addCleanup(lambda: shutil.rmtree(self.e.d, ignore_errors=True))

    def build(self, platform="laptop", approve=("gaming",), on_demand=False, backend_replies=None,
              release=RELEASE, canary=None):
        self.e = Env(platform)
        self.store = GenStore(os.path.join(self.e.d, "generated"))
        self.ids = {}
        for i, wl in enumerate(approve):
            gid = make_artifact(self.store, source=good_source(Workload(wl), tweak=i), workload=wl,
                                platform=platform, release=release, created=1_700_000_000 + i)
            self.store.approve(gid, self.e.priv)
            self.ids[wl] = gid
        self.h_tmpl, self.h_gen = FakeHost(), FakeHost()
        self.h_gen.state_ops = "conductor_gen"
        self.clk = Clock()
        verifier = Verifier(self.e.pub, self.e.obj, release=RELEASE)
        hf = lambda m: self.h_gen if m.is_generated else self.h_tmpl
        self.lc = Lifecycle(self.h_tmpl, verifier, self.e.audit, self.e.profiles, platform, canary_fn=canary,
                            clock=self.clk, host_factory=hf)
        mgr = None
        self.replies = list(backend_replies or [])
        if on_demand:
            g = Generator(backend=CallableBackend(lambda s, u, c: self.replies.pop(0)), toolchain=FakeToolchain(),
                          store=self.store, repo_root=ROOT, audit=self.e.audit,
                          verify_fn=lambda d: (True, "ok"), profiles=self.e.profiles)
            mgr = GenManager(g, sync=True)
        self.mgr = mgr
        self.gen = GenSupport(self.store, GenForge(self.store, self.e.priv), MACHINE, RELEASE, manager=mgr,
                              on_demand=on_demand)
        self.g = Governor(self.e.profiles, platform, None, self.e.forge, self.lc, self.e.audit, None,
                          min_switch_s=8, clock=self.clk, gen=self.gen)

    def run_for(self, mk, secs):
        out = None
        for _ in range(secs):
            self.clk.t += 1
            out = self.g.step(mk())
        return out

    def audit_events(self, name):
        with open(self.e.audit.path) as f:
            return [json.loads(l) for l in f if json.loads(l)["event"] == name]


class TestGovernorWithGeneration(GovCase):
    def test_approved_artifact_is_used_for_its_workload(self):
        self.build()
        r = self.run_for(GAME, 4)
        self.assertTrue(r["active"].startswith(f"gen:{self.ids['gaming']}/gaming@laptop/ac"), r)
        self.assertTrue(self.h_gen.running)
        self.assertFalse(self.h_tmpl.running)
        self.assertEqual(self.h_gen.classes, {100: 1, 101: 1, 102: 3})        # class sync goes to the generated host
        load = self.audit_events("load")[0]["data"]
        self.assertEqual(load["gen_id"], self.ids["gaming"])
        self.assertEqual(load["sched_ext"]["ops"], "conductor_gen")

    def test_other_workloads_still_use_the_reference_template(self):
        self.build()
        self.run_for(GAME, 4)
        r = self.run_for(UI, 14)
        self.assertEqual(r["active"], "ui@laptop/ac")
        self.assertTrue(self.h_tmpl.running)
        self.assertFalse(self.h_gen.running)                                    # old host was stopped on switch
        self.assertEqual(self.e.events().count("load"), 2)

    def test_no_artifact_means_template(self):
        self.build(approve=())
        self.assertEqual(self.run_for(GAME, 4)["active"], "gaming@laptop/ac")
        self.assertEqual(self.mgr, None)

    def test_pending_or_rejected_artifacts_are_never_used(self):
        self.build(approve=())
        make_artifact(self.store, status="pending")
        make_artifact(self.store, source=good_source(tweak=9), status="rejected")
        self.assertEqual(self.run_for(GAME, 4)["active"], "gaming@laptop/ac")

    def test_artifact_for_another_kernel_is_ignored(self):
        self.build(release="6.1.0-older")
        self.assertEqual(self.run_for(GAME, 4)["active"], "gaming@laptop/ac")

    def test_approved_only_platform_never_uses_generated(self):
        self.build(platform="iot")
        r = self.run_for(GAME, 4)
        self.assertIsNone(r["active"])                                          # no approved-store manifests either
        self.assertFalse(self.h_gen.running)

    def test_platform_flag_disables_generated(self):
        self.build()
        self.g.pcfg["allow_device_generation"] = False
        self.assertEqual(self.run_for(GAME, 4)["active"], "gaming@laptop/ac")

    def test_idle_gets_no_custom_scheduler_even_with_artifacts(self):
        self.build(approve=("gaming",))
        self.run_for(IDLE, 4)
        self.assertIsNone(self.lc.active)

    def test_tampered_artifact_falls_back_and_is_reported_once(self):
        self.build()
        with open(os.path.join(self.store.dir(self.ids["gaming"]), "gen_load"), "ab") as f:
            f.write(b"x")
        r = self.run_for(GAME, 4)
        self.assertEqual(r["active"], "gaming@laptop/ac")
        self.run_for(GAME, 20)
        un = self.audit_events("gen-unusable")
        self.assertEqual(len(un), 1)                                            # not once per tick
        self.assertIn("does not match artifact digests", un[0]["data"]["reason"])

    def test_kernel_ejection_quarantines_generated_and_falls_back(self):
        self.build()
        self.run_for(GAME, 4)
        self.h_gen.dead = True
        self.clk.t += 1
        self.assertEqual(self.g.step(GAME())["event"], "ejected")
        r = self.run_for(GAME, 10)
        self.assertEqual(r["active"], "gaming@laptop/ac")                       # template while gen is quarantined
        self.assertIn("ejected", self.e.events())
        self.clk.t += self.e.profiles["slo"]["quarantine_s"] + 1
        self.assertTrue(self.run_for(GAME, 10)["active"].startswith("gen:"))    # tried again after quarantine

    def test_canary_failure_of_generated_quarantines_it(self):
        calls = []

        def canary(host, m):
            calls.append(m.is_generated)
            return (False, "starved") if m.is_generated else (True, {})
        self.build(canary=canary)
        r = self.run_for(GAME, 12)
        self.assertEqual(r["active"], "gaming@laptop/ac")
        self.assertIn(True, calls)
        self.assertFalse(self.h_gen.running)
        res = self.audit_events("canary-result")
        self.assertTrue(any(not x["data"]["ok"] and x["data"]["detail"] == "starved" for x in res))
        self.assertFalse([x for x in self.audit_events("load") if x["data"].get("gen_id")])   # never reached "load"

    def test_sysfs_ops_name_mismatch_unloads_generated(self):
        self.build()
        self.h_gen.state_ops = "conductor"                                      # kernel reports the wrong scheduler
        r = self.run_for(GAME, 6)
        self.assertNotIn("gen:", r["active"] or "")
        self.assertIn("load-failed", self.e.events())

    def test_status_reports_generation_state(self):
        self.build()
        st = self.g.status()
        self.assertEqual(st["gen"]["artifacts"], {"approved": 1})
        self.assertFalse(st["gen"]["on_demand"])


class TestOnDemand(GovCase):
    def test_generates_in_background_then_uses_it_after_approval(self):
        self.build(approve=(), on_demand=True, backend_replies=[reply(good_source())])
        r = self.run_for(GAME, 3)
        self.assertEqual(r["active"], "gaming@laptop/ac")                        # template meanwhile
        listed = self.store.list()
        self.assertEqual([m["status"] for m in listed], ["pending"])
        self.assertEqual(self.replies, [])                                       # backend asked exactly once
        self.run_for(GAME, 20)
        self.assertEqual(self.audit_events("gen-start").__len__(), 1)           # no repeat requests while pending
        self.assertEqual(self.run_for(GAME, 2)["active"], "gaming@laptop/ac")    # still template: not approved
        self.store.approve(listed[0]["id"], self.e.priv)
        r = self.run_for(GAME, 10)
        self.assertTrue(r["active"].startswith("gen:"), r)

    def test_without_on_demand_flag_backend_is_never_called(self):
        self.build(approve=(), on_demand=False, backend_replies=[reply(good_source())])
        self.run_for(GAME, 5)
        self.assertEqual(self.audit_events("gen-start"), [])

    def test_ctl_gen_command(self):
        self.build(approve=(), on_demand=True, backend_replies=[reply(good_source(Workload.VIDEO))])
        srv = ControlServer.__new__(ControlServer)
        srv.gov = self.g
        self.g.last_state = "ac"
        res = srv.handle({"cmd": "gen", "workload": "video"})
        self.assertEqual(res, {"ok": True, "result": "started"})
        self.assertEqual(srv.handle({"cmd": "gen", "workload": "video"})["result"], "exists")
        self.assertFalse(srv.handle({"cmd": "gen", "workload": "idle"})["ok"])

    def test_ctl_gen_without_backend_or_on_forbidden_platform(self):
        self.build(approve=())
        self.assertFalse(self.g.request_generation("gaming")["ok"])
        self.build(platform="iot", approve=(), on_demand=True, backend_replies=[reply(good_source())])
        res = self.g.request_generation("gaming")
        self.assertFalse(res["ok"])
        self.assertIn("does not allow", res["error"])


class TestLifecycleHostSelection(unittest.TestCase):
    def test_host_factory_is_consulted_after_the_old_host_stops(self):
        e = Env("laptop")
        self.addCleanup(shutil.rmtree, e.d, ignore_errors=True)
        order, a, b = [], FakeHost(), FakeHost()
        orig_stop = a.stop
        a.stop = lambda *x, **k: (order.append("stop-a"), orig_stop())[1]
        picks = iter([a, b])

        def hf(m):
            order.append("factory")
            return next(picks)
        lc = Lifecycle(a, e.verifier, e.audit, e.profiles, "laptop", host_factory=hf)
        m1 = e.forge.make(Workload.GAMING, "laptop", "ac")
        m2 = e.forge.make(Workload.UI, "laptop", "ac")
        self.assertTrue(lc.apply(m1)[0])
        self.assertTrue(lc.apply(m2)[0])
        self.assertEqual(order, ["factory", "stop-a", "factory"])
        self.assertIs(lc.host, b)
        self.assertTrue(b.running)


# ----------------------------------------------------------------------------- host
def script(d, name, text):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(text)
    os.chmod(p, 0o755)
    return p


class TestVerifyOnly(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_accepted(self):
        p = script(self.d, "ok", '#!/bin/bash\n[ "$1" = "--verify-only" ] || exit 9\necho \'{"event":"verified","name":"conductor_gen"}\'\n')
        ok, msg = verify_only(p)
        self.assertTrue(ok)
        self.assertIn("accepted by the kernel", msg)

    def test_rejected_returns_the_verifier_log_tail(self):
        log = "\n".join(f"line {i}: R{i} invalid" for i in range(2000))
        p = script(self.d, "bad", f"#!/bin/bash\ncat <<'EOF' >&2\n{log}\nEOF\nexit 1\n")
        ok, msg = verify_only(p)
        self.assertFalse(ok)
        self.assertTrue(msg.endswith("line 1999: R1999 invalid\n") or msg.endswith("line 1999: R1999 invalid"))
        self.assertLessEqual(len(msg), 4000)

    def test_exit_zero_without_verified_event_is_not_accepted(self):
        p = script(self.d, "liar", "#!/bin/bash\necho hello\nexit 0\n")
        self.assertFalse(verify_only(p)[0])

    def test_missing_binary_and_timeout(self):
        self.assertFalse(verify_only("/nonexistent/gen_load")[0])
        p = script(self.d, "slow", "#!/bin/bash\nsleep 5\n")
        ok, msg = verify_only(p, timeout=0.3)
        self.assertFalse(ok)
        self.assertIn("Timeout", msg)


class TestLoaderHostCommandLine(unittest.TestCase):
    LOADER = r"""#!/bin/bash
echo "$@" > "$ARGV_OUT"
echo '{"event":"attached","name":"x"}'
read -r line
"""

    def run_host(self, knobs, partial):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        out = os.path.join(d, "argv")
        os.environ["ARGV_OUT"] = out
        self.addCleanup(os.environ.pop, "ARGV_OUT", None)
        h = LoaderHost(script(d, "loader", self.LOADER), knobs=knobs)
        ok, why = h.start(params(), partial=partial, inject_stall=True)
        self.assertTrue(ok, why)
        h.stop()
        with open(out) as f:
            return f.read().split()

    def test_template_host_passes_knobs(self):
        argv = self.run_host(True, False)
        for flag in ("--slice-ns", "--credit-ns", "--charge-pct", "--perf", "--timeout-ms", "--inject-stall"):
            self.assertIn(flag, argv)
        self.assertNotIn("--partial", argv)

    def test_generated_host_passes_no_knobs_and_never_inject_stall(self):
        argv = self.run_host(False, True)
        self.assertEqual(argv, ["--timeout-ms", str(params().timeout_ms), "--partial"])


# ----------------------------------------------------------------------------- canary
class FakeProbe:
    def __init__(self, **res):
        self.res = {"n": 900, "p50_us": 80, "p99_us": 900, "max_us": 3000, "policy_ok": True, "ext": True,
                    "hogs": 2, "hog_cpu_ms": [2900.0, 2800.0], "duration_ms": 3000}
        self.res.update(res)

    def __call__(self, argv, **kw):
        return subprocess.CompletedProcess(argv, 0, json.dumps(self.res).encode(), b"")


class Manifestish:
    def __init__(self, generated):
        self.params, self.is_generated = params(), generated


def lat(n):
    return [[n, 0, 0, 0] + [0] * 12, [0] * 16, [0] * 16, [0] * 16]


class TestCanaryChecks(unittest.TestCase):
    def run_canary(self, generated, probe=None, stats="default", host=None, limit=50000):
        h = host or FakeHost()
        h.stats_payload = {"stats": [0] * 8, "lat": lat(500)} if stats == "default" else stats
        with mock.patch.object(canary_mod.subprocess, "run", probe or FakeProbe()):
            return make_canary(3, limit)(h, Manifestish(generated)), h

    def test_good_generated_scheduler_passes(self):
        (ok, detail), h = self.run_canary(True)
        self.assertTrue(ok, detail)
        self.assertFalse(h.running)                                              # always stopped afterwards

    def test_template_manifest_skips_the_generated_only_checks(self):
        (ok, _), _ = self.run_canary(False, probe=FakeProbe(hog_cpu_ms=[1.0, 1.0]), stats=None)
        self.assertTrue(ok)

    def test_starved_hog_fails_generated(self):
        (ok, detail), _ = self.run_canary(True, probe=FakeProbe(hog_cpu_ms=[2900.0, 40.0]))
        self.assertFalse(ok)
        self.assertIn("starved", detail)

    def test_no_telemetry_fails_generated(self):
        (ok, detail), _ = self.run_canary(True, stats=None)
        self.assertEqual((ok, "no telemetry" in detail), (False, True))
        (ok, detail), _ = self.run_canary(True, stats={"stats": [0] * 8, "lat": lat(3)})
        self.assertEqual((ok, "latency samples" in detail), (False, True))

    def test_latency_limit_ejection_and_start_failure(self):
        (ok, detail), _ = self.run_canary(True, probe=FakeProbe(p99_us=90000))
        self.assertFalse(ok)
        self.assertIn("p99", detail)
        class Ejected(FakeHost):                                                 # attaches, then the kernel drops it
            def alive(self): return False
            def sched_ext_state(self): return {"state": "enabled", "ops": "conductor_gen"}
        (ok, detail), _ = self.run_canary(True, host=Ejected())
        self.assertEqual((ok, "ejected" in detail), (False, True))
        h = FakeHost()
        h.fail_start = True
        (ok, detail), _ = self.run_canary(True, host=h)
        self.assertEqual((ok, detail), (False, "verifier rejected (fake)"))


class TestDirCanary(unittest.TestCase):
    def test_skipped_when_another_scheduler_is_active(self):
        started = []
        run = make_dir_canary(3, 50000, lambda d: started.append(d) or FakeHost(),
                              lambda: {"state": "enabled", "ops": "other"})
        ok, detail = run("/x", params())
        self.assertIsNone(ok)
        self.assertIn("skipped", detail)
        self.assertEqual(started, [])

    def test_runs_when_slot_is_free_and_holds_the_lock(self):
        events = []

        class Lock:
            def __enter__(self): events.append("enter"); return self
            def __exit__(self, *a): events.append("exit"); return False

        def host_for(d):
            events.append("host")
            h = FakeHost()
            h.stats_payload = {"stats": [0] * 8, "lat": lat(500)}
            return h
        run = make_dir_canary(3, 50000, host_for, lambda: {"state": "disabled", "ops": None}, lock=Lock())
        with mock.patch.object(canary_mod.subprocess, "run", FakeProbe()):
            ok, detail = run("/x", params())
        self.assertTrue(ok, detail)
        self.assertEqual(events, ["enter", "host", "exit"])

    def test_no_sysfs_is_treated_as_free(self):
        h = FakeHost()
        h.stats_payload = {"stats": [0] * 8, "lat": lat(500)}
        run = make_dir_canary(3, 50000, lambda d: h, lambda: {"state": None, "ops": None})
        with mock.patch.object(canary_mod.subprocess, "run", FakeProbe()):
            self.assertTrue(run("/x", params())[0])


if __name__ == "__main__":
    unittest.main()

import json, unittest
from conductord.audit import AuditLog, verify_chain
from conductord.host import FakeHost
from conductord.lifecycle import Lifecycle, lat_breach
from conductord.model import Workload
from tests.helpers import Env


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


class TestLifecycle(unittest.TestCase):
    def setUp(self):
        self.e = Env("vm")
        self.h = FakeHost()
        self.clk = Clock()
        self.canary_calls = 0
        self.canary_ok = True

        def canary(host, m):
            self.canary_calls += 1
            ok, _ = host.start(m.params, partial=True)
            host.stop()
            return self.canary_ok, "fake"
        self.lc = Lifecycle(self.h, self.e.verifier, self.e.audit, self.e.profiles, "vm",
                            canary_fn=canary, clock=self.clk)

    def m(self, wl=Workload.GAMING, st="ac"):
        return self.e.forge.make(wl, "vm", st)

    def test_load_with_canary_then_cached(self):
        ok, _ = self.lc.apply(self.m())
        self.assertTrue(ok)
        self.assertEqual(self.canary_calls, 1)
        self.assertEqual(self.h.history, [("start", True), ("stop", None), ("start", False)])
        self.lc.unload("test")
        ok, _ = self.lc.apply(self.m())
        self.assertTrue(ok)
        self.assertEqual(self.canary_calls, 1, "canary must be cached per manifest")

    def test_unchanged_is_noop(self):
        self.lc.apply(self.m())
        n = len(self.h.history)
        self.assertEqual(self.lc.apply(self.m()), (True, "unchanged"))
        self.assertEqual(len(self.h.history), n)

    def test_switch_unloads_old_first(self):
        self.lc.apply(self.m(Workload.GAMING))
        self.lc.apply(self.m(Workload.UI))
        ev = self.e.events()
        self.assertEqual([x for x in ev if x in ("load", "unload")], ["load", "unload", "load"])
        self.assertEqual(self.lc.active.body["workload"], "ui")

    def test_canary_failure_quarantines_and_never_full_loads(self):
        self.canary_ok = False
        ok, why = self.lc.apply(self.m())
        self.assertFalse(ok)
        self.assertNotIn(("start", False), self.h.history)
        self.assertEqual(self.lc.apply(self.m()), (False, "quarantined"))
        self.clk.t += 10_000
        self.canary_ok = True
        self.assertTrue(self.lc.apply(self.m())[0])

    def test_verifier_reject_audited_and_no_load(self):
        m = self.m()
        m.body["params"]["perf"][1] = 7
        ok, why = self.lc.apply(m)
        self.assertFalse(ok)
        self.assertEqual(why, "bad signature")
        self.assertEqual(self.h.history, [])
        self.assertIn("rejected", self.e.events())

    def test_load_failure_quarantines(self):
        self.h.fail_start = True
        self.lc.canary_fn = None
        ok, _ = self.lc.apply(self.m())
        self.assertFalse(ok)
        self.assertIn("load-failed", self.e.events())
        self.assertIsNone(self.lc.active)

    def test_sysfs_mismatch_unloads(self):
        self.lc.canary_fn = None
        self.h.state_ops = "someone-else"
        ok, why = self.lc.apply(self.m())
        self.assertFalse(ok)
        self.assertFalse(self.h.running)

    def test_kernel_ejection_detected(self):
        self.lc.canary_fn = None
        self.lc.apply(self.m())
        self.h.dead = True
        self.assertEqual(self.lc.tick(0.0), "ejected")
        self.assertIsNone(self.lc.active)
        self.assertEqual(self.lc.apply(self.m()), (False, "quarantined"))

    def test_psi_regression_rolls_back(self):
        self.lc.canary_fn = None
        self.lc.apply(self.m(), psi_baseline=5.0)
        res = [self.lc.tick(80.0) for _ in range(10)]
        self.assertEqual(res[-1], "rollback")
        self.assertIsNone(self.lc.active)
        self.assertIn("rollback", self.e.events())

    def test_psi_spike_shorter_than_window_is_tolerated(self):
        self.lc.canary_fn = None
        self.lc.apply(self.m(), psi_baseline=5.0)
        for _ in range(9):
            self.assertIsNone(self.lc.tick(80.0))
        self.assertIsNone(self.lc.tick(5.0))

    def test_latency_slo_rollback(self):
        self.lc.canary_fn = None
        self.lc.apply(self.m())
        n = 0
        def lat(bad):
            cls = [[0] * 16 for _ in range(4)]
            cls[1][2] = 1000
            cls[1][14] = bad
            return {"event": "stats", "lat": cls}
        res = None
        for i in range(40):
            self.h.stats_payload = lat(100 * i)       # growing tail in FG class
            res = self.lc.tick(0.0) or res
        self.assertEqual(res, "rollback")

    def test_lat_breach_function(self):
        slo = self.e.profiles["slo"]
        ok = [[0] * 16 for _ in range(4)]
        ok[1][3] = 1000
        self.assertFalse(lat_breach(ok, slo))
        ok[1][15] = 100
        self.assertTrue(lat_breach(ok, slo))
        tiny = [[0] * 16 for _ in range(4)]
        tiny[1][15] = 10
        self.assertFalse(lat_breach(tiny, slo), "too few samples to judge")

    def test_sync_classes_diff(self):
        self.lc.canary_fn = None
        self.lc.apply(self.m())
        self.lc.sync_classes({10: 1, 11: 3, 12: 0})
        self.assertEqual(self.h.classes, {10: 1, 11: 3})
        self.lc.sync_classes({10: 2})
        self.assertEqual(self.h.classes, {10: 2})


class TestAudit(unittest.TestCase):
    def test_chain_and_tamper(self):
        e = Env("vm")
        for i in range(5):
            e.audit.record("x", i=i)
        ok, n, err = verify_chain(e.audit.path)
        self.assertTrue(ok); self.assertEqual(n, 5)
        with open(e.audit.path) as f:
            lines = f.read().splitlines()
        d = json.loads(lines[2]); d["data"]["i"] = 99
        lines[2] = json.dumps(d, sort_keys=True)
        with open(e.audit.path, "w") as f:
            f.write("\n".join(lines) + "\n")
        ok, n, err = verify_chain(e.audit.path)
        self.assertFalse(ok)

    def test_truncation_in_middle_detected(self):
        e = Env("vm")
        for i in range(4):
            e.audit.record("x", i=i)
        with open(e.audit.path) as f:
            lines = f.read().splitlines()
        with open(e.audit.path, "w") as f:
            f.write("\n".join(lines[:1] + lines[2:]) + "\n")
        self.assertFalse(verify_chain(e.audit.path)[0])

    def test_recovery_continues_chain(self):
        e = Env("vm")
        e.audit.record("a")
        a2 = AuditLog(e.audit.path, use_tpm=False)
        a2.record("b")
        self.assertTrue(verify_chain(e.audit.path)[0])


if __name__ == "__main__":
    unittest.main()

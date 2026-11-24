import os, unittest
from conductord.daemon import Governor
from conductord.forge import ApprovedStore, Forge
from conductord.host import FakeHost
from conductord.lifecycle import Lifecycle
from conductord.model import Workload
from tests.helpers import Env, P, snap


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def build(platform="vm", store_dir=None, canary=None):
    e = Env(platform)
    h, clk = FakeHost(), Clock()
    lc = Lifecycle(h, e.verifier, e.audit, e.profiles, platform, canary_fn=canary, clock=clk)
    store = ApprovedStore(store_dir) if store_dir else None
    g = Governor(e.profiles, platform, None, e.forge, lc, e.audit, store, min_switch_s=8, clock=clk)
    return e, h, clk, lc, g


GAME = lambda: snap([P(100, "steam", 45), P(101, "gnome-shell", 6), P(102, "cc1plus", 70)], util=80)
IDLE = lambda: snap(util=1)
UI = lambda: snap([P(101, "gnome-shell", 8)], util=15)


class TestGovernor(unittest.TestCase):
    def run_for(self, g, clk, mk, secs):
        out = None
        for _ in range(secs):
            clk.t += 1
            out = g.step(mk())
        return out

    def test_idle_game_ui_idle_cycle(self):
        e, h, clk, lc, g = build()
        self.run_for(g, clk, IDLE, 3)
        self.assertIsNone(lc.active)
        r = self.run_for(g, clk, GAME, 4)
        self.assertEqual(r["active"], "gaming@vm/ac")
        self.assertEqual(h.classes, {100: 1, 101: 1, 102: 3})
        r = self.run_for(g, clk, UI, 14)
        self.assertEqual(r["active"], "ui@vm/ac")
        r = self.run_for(g, clk, IDLE, 14)
        self.assertIsNone(r["active"])
        self.assertFalse(h.running)
        ev = e.events()
        self.assertEqual([x for x in ev if x in ("load", "unload")], ["load", "unload", "load", "unload"])
        self.assertEqual(ev.count("decision"), 3)   # idle->gaming, gaming->ui, ui->stock

    def test_steady_state_never_reloads_even_if_wall_clock_advances(self):
        """Regression: manifest 'created' timestamp used to change the hash every tick => reload churn."""
        import itertools, time
        e, h, clk, lc, g = build()
        tick = itertools.count(int(time.time()))   # must stay near real time: the Verifier checks TTL against it
        e.forge.clock = lambda: next(tick)             # every call returns a different second
        self.run_for(g, clk, GAME, 3)
        loads = e.events().count("load")
        self.run_for(g, clk, GAME, 30)
        self.assertEqual(loads, 1)
        self.assertEqual(e.events().count("load"), 1)
        self.assertEqual(e.events().count("unload"), 0)
        self.assertEqual(e.events().count("decision"), 1)

    def test_manifest_regenerated_after_half_ttl(self):
        e, h, clk, lc, g = build()
        t = {"now": 1_700_000_000.0}
        e.forge.clock = lambda: t["now"]
        m1 = e.forge.make(Workload.UI, "vm", "ac")
        self.assertIs(e.forge.make(Workload.UI, "vm", "ac"), m1)
        t["now"] += e.forge.ttl_s // 2 + 1
        m2 = e.forge.make(Workload.UI, "vm", "ac")
        self.assertIsNot(m2, m1)
        self.assertNotEqual(m1.hash, m2.hash)

    def test_flapping_input_causes_no_reload(self):
        e, h, clk, lc, g = build()
        self.run_for(g, clk, GAME, 3)
        loads = e.events().count("load")
        for i in range(20):
            clk.t += 1
            g.step(UI() if i % 2 else GAME())
        self.assertEqual(e.events().count("load"), loads)

    def test_battery_changes_manifest(self):
        e, h, clk, lc, g = build()
        self.run_for(g, clk, GAME, 3)
        ac = lc.active.hash
        bat = lambda: snap([P(100, "steam", 45)], util=70, ac=False, bat=50)
        self.run_for(g, clk, bat, 10)
        self.assertEqual(lc.active.body["power_state"], "battery")
        self.assertNotEqual(lc.active.hash, ac)

    def test_thermal_trip_bypasses_dwell(self):
        e, h, clk, lc, g = build()
        self.run_for(g, clk, GAME, 3)
        hot = lambda: snap([P(100, "steam", 45)], util=70, temp=95)
        clk.t += 1
        g.step(hot())
        self.assertEqual(lc.active.body["power_state"], "thermal")

    def test_hold_and_rollback_via_controls(self):
        e, h, clk, lc, g = build()
        g.pinned = "camera"
        self.run_for(g, clk, IDLE, 2)
        self.assertEqual(lc.active.body["workload"], "camera")
        lc.unload("operator rollback")
        g.pinned = "baseline"
        self.run_for(g, clk, GAME, 3)
        self.assertIsNone(lc.active)

    def test_approved_only_platform_never_signs_on_device(self):
        d = os.path.join(Env("vm").d, "approved")
        e, h, clk, lc, g = build("automotive", d)
        # nothing shipped -> baseline even for an allowed workload
        cam = lambda: snap([P(5, "libcamera-hello", 15, {"v4l"})], util=30)
        self.run_for(g, clk, cam, 4)
        self.assertIsNone(lc.active)
        # ship a signed manifest -> it loads
        m = e.forge.make(Workload.CAMERA, "automotive", "ac", arch="any")
        ApprovedStore(d).save(m)
        self.run_for(g, clk, cam, 10)
        self.assertEqual(lc.active.name, "camera@automotive/ac")

    def test_approved_only_rejects_manifest_for_other_platform(self):
        d = os.path.join(Env("vm").d, "approved")
        e, h, clk, lc, g = build("automotive", d)
        m = e.forge.make(Workload.CAMERA, "vm", "ac", arch="any")
        m.body["name"] = "camera@automotive/ac"          # forged label, wrong platform inside the signed body
        m.sig_b64 = None
        ApprovedStore(d).save(m)
        cam = lambda: snap([P(5, "libcamera-hello", 15, {"v4l"})], util=30)
        self.run_for(g, clk, cam, 6)
        self.assertIsNone(lc.active)
        self.assertIn("rejected", e.events())

    def test_loop_exception_leaves_stock_scheduler(self):
        e, h, clk, lc, g = build()
        self.run_for(g, clk, GAME, 3)
        class Boom:
            def collect(self): raise RuntimeError("boom")
        g.collector = Boom()
        g.run(interval=0.0, duration=0.05)
        self.assertFalse(h.running)
        self.assertIn("governor-error", e.events())


if __name__ == "__main__":
    unittest.main()

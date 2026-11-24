import copy, time, unittest
from conductord.forge import Forge, Manifest, Verifier, canonical, sign_bytes, verify_bytes
from conductord.model import Params, Workload
from conductord.policy import build_params, power_state, validate_params
from tests.helpers import Env, profiles, snap


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.pr = profiles()

    def test_idle_is_stock_scheduler(self):
        self.assertIsNone(build_params(self.pr, Workload.IDLE, "laptop", "ac"))

    def test_gaming_boosts_fg_and_demotes_bg(self):
        p = build_params(self.pr, Workload.GAMING, "laptop", "ac")
        self.assertLess(p.charge_pct[1], p.charge_pct[0])      # FG charged less => more share
        self.assertGreater(p.charge_pct[3], p.charge_pct[0])   # BG charged more
        self.assertEqual(p.perf[1], 1024)

    def test_battery_caps_perf_and_stretches_slices(self):
        ac = build_params(self.pr, Workload.GAMING, "laptop", "ac")
        bat = build_params(self.pr, Workload.GAMING, "laptop", "battery")
        self.assertLessEqual(max(bat.perf), 640)
        self.assertGreater(bat.slice_ns[1], ac.slice_ns[1])
        self.assertGreater(bat.perf[0], 0)                      # 'untouched' class still capped off-AC

    def test_automotive_allow_list(self):
        self.assertIsNone(build_params(self.pr, Workload.AGENTIC, "automotive", "ac"))
        self.assertIsNone(build_params(self.pr, Workload.GAMING, "automotive", "ac"))
        self.assertIsNotNone(build_params(self.pr, Workload.CAMERA, "automotive", "ac"))

    def test_automotive_watchdog_is_tight(self):
        self.assertEqual(build_params(self.pr, Workload.CAMERA, "automotive", "ac").timeout_ms, 1000)

    def test_unknown_platform(self):
        with self.assertRaises(KeyError):
            build_params(self.pr, Workload.UI, "toaster", "ac")

    def test_power_state(self):
        pc = self.pr["platforms"]["mobile"]
        self.assertEqual(power_state(snap(ac=True), pc), "ac")
        self.assertEqual(power_state(snap(ac=False, bat=60), pc), "battery")
        self.assertEqual(power_state(snap(ac=False, bat=10), pc), "low_battery")
        self.assertEqual(power_state(snap(ac=False, bat=60, temp=85), pc), "thermal")

    def test_validate_bounds(self):
        good = build_params(self.pr, Workload.UI, "vm", "ac")
        for field, bad in (("slice_ns", [1, 1, 1, 1]), ("charge_pct", [1, 100, 100, 100]),
                           ("perf", [2000, 0, 0, 0]), ("timeout_ms", 5)):
            p = copy.deepcopy(good)
            setattr(p, field, bad)
            with self.assertRaises(ValueError, msg=field):
                validate_params(p)

    def test_every_combo_valid(self):
        for plat in self.pr["platforms"]:
            for wl in Workload:
                for st in self.pr["platforms"][plat]["states"]:
                    p = build_params(self.pr, wl, plat, st)
                    if p:
                        validate_params(p)


class TestForgeVerify(unittest.TestCase):
    def setUp(self):
        self.e = Env("vm")

    def _m(self):
        return self.e.forge.make(Workload.GAMING, "vm", "ac")

    def test_roundtrip_ok(self):
        ok, why = self.e.verifier.verify(self._m(), "vm")
        self.assertTrue(ok, why)

    def test_manifest_json_roundtrip(self):
        m = self._m()
        m2 = Manifest.from_json(m.to_json())
        self.assertEqual(m.hash, m2.hash)
        self.assertTrue(self.e.verifier.verify(m2, "vm")[0])

    def test_tampered_params_rejected(self):
        m = self._m()
        m.body["params"]["perf"][1] = 1023
        ok, why = self.e.verifier.verify(m, "vm")
        self.assertFalse(ok)
        self.assertEqual(why, "bad signature")

    def test_unsigned_rejected(self):
        m = self._m()
        m.sig_b64 = None
        self.assertEqual(self.e.verifier.verify(m, "vm")[1], "unsigned")

    def test_wrong_key_rejected(self):
        e2 = Env("vm")
        ok, why = e2.verifier.verify(self._m(), "vm")
        self.assertFalse(ok)

    def test_bpf_object_swap_rejected(self):
        m = self._m()
        with open(self.e.obj, "ab") as f:
            f.write(b"evil")
        v = Verifier(self.e.pub, self.e.obj)
        self.assertEqual(v.verify(m, "vm")[1], "bpf object digest mismatch")

    def test_platform_mismatch_rejected(self):
        self.assertFalse(self.e.verifier.verify(self._m(), "laptop")[0])

    def test_expired_rejected(self):
        f = Forge(self.e.profiles, self.e.obj, self.e.priv, clock=lambda: time.time() - 10 * 86400)
        m = f.make(Workload.UI, "vm", "ac")
        self.assertEqual(self.e.verifier.verify(m, "vm")[1], "expired")

    def test_out_of_bounds_params_rejected_even_if_signed(self):
        m = self._m()
        m.body["params"]["charge_pct"] = [1, 1, 1, 1]
        m.sig_b64 = sign_bytes(self.e.priv, canonical(m.body))
        ok, why = self.e.verifier.verify(m, "vm")
        self.assertFalse(ok)
        self.assertTrue(why.startswith("params invalid"))

    def test_sign_verify_primitives(self):
        sig = sign_bytes(self.e.priv, b"hello")
        self.assertTrue(verify_bytes(self.e.pub, b"hello", sig))
        self.assertFalse(verify_bytes(self.e.pub, b"hellO", sig))


if __name__ == "__main__":
    unittest.main()

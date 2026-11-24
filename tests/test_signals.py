import os, tempfile, unittest
from conductord.signals import Collector


def w(p, txt):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(txt)


class TestCollector(unittest.TestCase):
    def test_fake_proc_tree(self):
        d = tempfile.mkdtemp()
        proc, sysfs = os.path.join(d, "proc"), os.path.join(d, "sys")
        t = {"now": 0.0}
        c = Collector(proc, sysfs, hint_path=os.path.join(d, "hint.json"), clock=lambda: t["now"])
        c.hz = 100

        def write(ticks_cam, total, idle, forks):
            w(f"{proc}/stat", f"cpu  {total-idle} 0 0 {idle} 0 0 0 0\nprocesses {forks}\n")
            w(f"{proc}/pressure/cpu", "some avg10=12.50 avg60=3.00 avg300=1.00 total=1\n")
            w(f"{proc}/42/stat", f"42 (libcamera-hello) S 1 1 1 0 0 0 0 0 0 0 {ticks_cam} 0 0 0 20 0 1 0 1 1 1\n")
            os.makedirs(f"{proc}/42/fd", exist_ok=True)
            link = f"{proc}/42/fd/3"
            if not os.path.lexists(link):
                os.symlink("/dev/video0", link)
            w(f"{sysfs}/class/power_supply/BAT0/type", "Battery\n")
            w(f"{sysfs}/class/power_supply/BAT0/capacity", "55\n")
            w(f"{sysfs}/class/power_supply/AC/type", "Mains\n")
            w(f"{sysfs}/class/power_supply/AC/online", "0\n")
            w(f"{sysfs}/class/thermal/thermal_zone0/temp", "71000\n")
            w(f"{sysfs}/class/drm/card0/device/gpu_busy_percent", "33\n")

        write(0, 1000, 900, 100)
        c.collect()
        t["now"] = 1.0
        write(50, 1100, 950, 130)        # 0.5 s of CPU in 1 s -> 50 %
        s = c.collect()
        self.assertAlmostEqual(s.psi_cpu_some10, 12.5)
        self.assertAlmostEqual(s.cpu_util_pct, 50.0)
        self.assertAlmostEqual(s.fork_rate, 30.0)
        self.assertEqual(s.battery_pct, 55.0)
        self.assertFalse(s.on_ac)
        self.assertEqual(s.thermal_c, 71.0)
        self.assertEqual(s.gpu_busy_pct, 33.0)
        p = [x for x in s.procs if x.pid == 42][0]
        self.assertEqual(p.comm, "libcamera-hello")
        self.assertAlmostEqual(p.cpu_pct, 50.0)
        self.assertIn("v4l", p.tags)

    def test_hint_expiry(self):
        d = tempfile.mkdtemp()
        hp = os.path.join(d, "hint.json")
        c = Collector(os.path.join(d, "proc"), os.path.join(d, "sys"), hint_path=hp)
        w(hp, '{"workload":"gaming","expires":1}')
        self.assertIsNone(c._hint(100))
        w(hp, '{"workload":"gaming","expires":1000}')
        self.assertEqual(c._hint(100)["workload"], "gaming")
        w(hp, "not json")
        self.assertIsNone(c._hint(100))


if __name__ == "__main__":
    unittest.main()

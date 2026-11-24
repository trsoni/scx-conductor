import unittest
from conductord.classifier import Debouncer, classify
from conductord.model import Cls, Workload
from tests.helpers import P, snap


class TestClassifier(unittest.TestCase):
    def test_idle(self):
        self.assertEqual(classify(snap(util=1.0)).workload, Workload.IDLE)

    def test_ui_default(self):
        c = classify(snap([P(10, "gnome-shell", 6)], util=12))
        self.assertEqual(c.workload, Workload.UI)
        self.assertEqual(c.assignments[10], Cls.FG)

    def test_gaming_comm_and_bg_demotion(self):
        c = classify(snap([P(1, "steam", 40), P(2, "gnome-shell", 5), P(3, "cc1plus", 80), P(4, "pipewire", 2)], util=70))
        self.assertEqual(c.workload, Workload.GAMING)
        self.assertEqual(c.assignments[1], Cls.FG)
        self.assertEqual(c.assignments[2], Cls.FG)
        self.assertEqual(c.assignments[3], Cls.BG)
        self.assertEqual(c.assignments[4], Cls.MEDIA)

    def test_gaming_by_drm_and_gpu_busy(self):
        c = classify(snap([P(7, "someengine", 60, {"drm"})], util=50, gpu=85))
        self.assertEqual(c.workload, Workload.GAMING)

    def test_camera_by_fd_beats_everything(self):
        c = classify(snap([P(5, "libcamera-hello", 15, {"v4l", "media"}), P(6, "firefox", 30)], util=60))
        self.assertEqual(c.workload, Workload.CAMERA)
        self.assertEqual(c.assignments[5], Cls.MEDIA)

    def test_video(self):
        c = classify(snap([P(9, "mpv", 12, {"drm"})]))
        self.assertEqual(c.workload, Workload.VIDEO)
        self.assertEqual(c.assignments[9], Cls.MEDIA)

    def test_browser_needs_cpu(self):
        self.assertEqual(classify(snap([P(1, "firefox", 4)], util=8)).workload, Workload.UI)
        self.assertEqual(classify(snap([P(1, "firefox", 25)], util=30)).workload, Workload.BROWSER)

    def test_agentic_by_comm_and_fork_rate(self):
        c = classify(snap([P(3, "claude", 8)], util=40, forks=40))
        self.assertEqual(c.workload, Workload.AGENTIC)
        self.assertGreaterEqual(c.score, 0.9)

    def test_agentic_by_fork_rate_alone(self):
        c = classify(snap([P(3, "python3", 5)], util=45, forks=60))
        self.assertEqual(c.workload, Workload.AGENTIC)

    def test_batch(self):
        c = classify(snap([P(1, "cc1plus", 90), P(2, "cc1plus", 90)], util=95, psi=40))
        self.assertEqual(c.workload, Workload.BATCH)

    def test_hint_wins(self):
        c = classify(snap([P(1, "firefox", 90)], util=90, hint={"workload": "camera", "pids": [1]}))
        self.assertEqual(c.workload, Workload.CAMERA)
        self.assertEqual(c.assignments[1], Cls.MEDIA)

    def test_bad_hint_ignored(self):
        c = classify(snap(util=1, hint={"workload": "nonsense"}))
        self.assertEqual(c.workload, Workload.IDLE)


class TestDebouncer(unittest.TestCase):
    def _c(self, wl, score=0.8):
        from conductord.model import Classification
        return Classification(wl, score, [], {})

    def test_needs_confirmation_and_dwell(self):
        d = Debouncer(min_dwell_s=8, confirm_ticks=2)
        self.assertEqual(d.update(self._c(Workload.BROWSER), 0), Workload.IDLE)   # tick 1
        self.assertEqual(d.update(self._c(Workload.BROWSER), 1), Workload.IDLE)   # confirmed but dwell not met
        self.assertEqual(d.update(self._c(Workload.BROWSER), 9), Workload.BROWSER)

    def test_fast_path_for_strong_launch_from_idle(self):
        d = Debouncer(min_dwell_s=8, confirm_ticks=2)
        d.update(self._c(Workload.GAMING, 0.95), 0)
        self.assertEqual(d.update(self._c(Workload.GAMING, 0.95), 1), Workload.GAMING)

    def test_flapping_does_not_switch(self):
        d = Debouncer(min_dwell_s=0, confirm_ticks=3)
        for i, w in enumerate([Workload.GAMING, Workload.UI, Workload.GAMING, Workload.UI]):
            d.update(self._c(w), i)
        self.assertEqual(d.current, Workload.IDLE)


if __name__ == "__main__":
    unittest.main()

"""Stage: the real BPF scheduler loads, schedules, reports stats and unloads cleanly."""
import os, time
from tests.guest._common import *       # noqa
from conductord.host import LoaderHost
from conductord.policy import build_params, load_profiles
from conductord.model import Workload

pr = load_profiles(os.path.join(ROOT, "profiles", "profiles.json"))
p = build_params(pr, Workload.GAMING, "vm", "ac")

check("sched_ext idle before test", sx()["state"] in ("disabled", None), sx())
h = LoaderHost(LOADER)
ok, detail = h.start(p)
check("loader attached", ok, detail)
if ok:
    st = sx()
    check("sysfs state enabled", st["state"] == "enabled", st)
    check("ops name is conductor", st["ops"] == "conductor", st)
    h.set_class(os.getpid(), 1)
    t = time.perf_counter()
    while time.perf_counter() - t < 1.0:       # generate enqueue/dispatch traffic
        time.sleep(0.001)
    s = h.stats()
    check("stats event returned", s is not None)
    if s:
        enq = s["stats"][0] + s["stats"][1]        # direct-local + shared enqueues
        check("scheduler saw tasks", enq > 0, s["stats"])
        check("latency histogram populated", sum(sum(r) for r in s["lat"]) > 0)
        check("FG class histogram populated", sum(s["lat"][1]) > 0, s["lat"][1])
    info = h.stop()
    check("loader exited cleanly", info.get("rc") == 0, info)
    check("sysfs state back to disabled", wait_for(lambda: sx()["state"] in ("disabled", None), 3) is not None, sx())
finish("loader_smoke")

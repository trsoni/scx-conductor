"""Stage: a deliberately stalling scheduler is ejected by the KERNEL watchdog and the box recovers.

Uses --partial so only tasks that opt into SCHED_EXT are affected; the loader and
the rest of the guest stay on the fair class and keep running.
"""
import os, subprocess, sys, time
from tests.guest._common import *       # noqa
from conductord.host import LoaderHost
from conductord.policy import build_params, load_profiles
from conductord.model import Workload

pr = load_profiles(os.path.join(ROOT, "profiles", "profiles.json"))
p = build_params(pr, Workload.UI, "vm", "ac")
p.timeout_ms = 1000

h = LoaderHost(LOADER)
ok, detail = h.start(p, partial=True, inject_stall=True)
check("stalling scheduler attached (partial)", ok, detail)
victim = None
if ok:
    victim = subprocess.Popen([sys.executable, "-c",
        "import os,time;os.sched_setscheduler(0,7,os.sched_param(0))\nwhile True: time.sleep(0.01)"])
    t0 = time.monotonic()
    ejected = wait_for(lambda: h.proc.poll() is not None, 20, 0.2)
    dt = time.monotonic() - t0
    check("kernel ejected the scheduler", ejected is not None, f"after {dt:.1f}s")
    check("loader reported kernel ejection (rc=3)", h.proc.returncode == 3, h.proc.returncode)
    check("ejected within 10x watchdog timeout", ejected is not None and dt < 10, f"{dt:.1f}s")
    check("sysfs back to disabled", wait_for(lambda: sx()["state"] in ("disabled", None), 3) is not None, sx())
    info = h.reap_if_dead()
    check("exit info recorded", info is not None and info.get("rc") == 3, info)
if victim:
    victim.kill(); victim.wait()
finish("watchdog")

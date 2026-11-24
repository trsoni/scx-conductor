"""Stage: A/B wakeup latency, fair-class baseline vs conductor with the probe marked FG.

This is a FUNCTIONAL check that the class plumbing works under contention. Do not
read performance conclusions from QEMU numbers: TCG timing is noisy and the host
may be oversubscribed. The assertion is only that the conductor run stays inside
the canary latency budget; the ratio is reported for the record.
"""
import json, os, subprocess, sys
from tests.guest._common import *       # noqa
from conductord.host import LoaderHost
from conductord.policy import build_params, load_profiles
from conductord.model import Workload

PROBE = os.path.join(ROOT, "tools", "workloads", "lat_probe.py")
HOGS = max(2, (os.cpu_count() or 2) * 2)


def probe(extra=()):
    r = subprocess.run([sys.executable, PROBE, "--duration", "6", "--hogs", str(HOGS), *extra],
                       capture_output=True, timeout=60)
    return json.loads(r.stdout)


base = probe()
print("baseline:", base)
pr = load_profiles(os.path.join(ROOT, "profiles", "profiles.json"))
h = LoaderHost(LOADER)
ok, d = h.start(build_params(pr, Workload.GAMING, "vm", "ac"))
check("conductor attached", ok, d)
if ok:
    pr_ = subprocess.Popen([sys.executable, PROBE, "--duration", "6", "--hogs", str(HOGS)],
                           stdout=subprocess.PIPE)
    h.set_class(pr_.pid, 1)                      # probe = FG; its hogs are separate processes => NORMAL
    out = json.loads(pr_.communicate(timeout=60)[0])
    print("conductor:", out)
    s = h.stats()
    h.stop()
    check("probe ran under conductor", out["n"] > 100, out)
    check("p99 within canary budget (50ms)", out["p99_us"] <= 50000, out["p99_us"])
    check("FG-class enqueues observed", s and s["stats"][3] > 0, s and s["stats"])   # index 3 == ST_ENQ_CLS1
    check("FG histogram populated", s and sum(s["lat"][1]) > 0)
    print(json.dumps({"baseline_p99_us": base["p99_us"], "conductor_p99_us": out["p99_us"],
                      "ratio": round(out["p99_us"] / max(1, base["p99_us"]), 3),
                      "improved": out["p99_us"] < base["p99_us"]}))
finish("ab_latency")

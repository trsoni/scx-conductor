"""Canary: prove a specialised scheduler loads, runs and doesn't stall *on this device*
before it is allowed to manage the whole system.

The scheduler is loaded in SCX_OPS_SWITCH_PARTIAL mode, so only tasks that
explicitly opt into SCHED_EXT (our probe + hogs) are scheduled by it; everything
else keeps running under the stock fair scheduler. This is the scheduler analogue
of Shirudo's "monitor how a shield would affect applications before enforcing".
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

DEFAULT_PROBE = os.path.join(os.path.dirname(__file__), "..", "tools", "workloads", "lat_probe.py")


def make_canary(secs: float, p99_limit_us: int, probe: str = DEFAULT_PROBE, hogs: int = 2):
    def run(host, manifest):
        ok, detail = host.start(manifest.params, partial=True)
        if not ok:
            return False, detail
        try:
            st = host.sched_ext_state()
            if st.get("state") not in (None, "enabled"):
                return False, f"sched_ext state {st}"
            r = subprocess.run([sys.executable, probe, "--ext", "--duration", str(secs),
                                "--hogs", str(hogs)], capture_output=True, timeout=secs + 20)
            if r.returncode != 0:
                return False, f"probe rc={r.returncode}: {r.stderr.decode(errors='replace')[-200:]}"
            res = json.loads(r.stdout)
            if not res.get("policy_ok"):
                return False, "could not switch probe to SCHED_EXT"
            if not host.alive():
                return False, "scheduler ejected during canary"
            if res["p99_us"] > p99_limit_us:
                return False, f"p99 {res['p99_us']}us > {p99_limit_us}us"
            return True, res
        except (subprocess.TimeoutExpired, ValueError, KeyError) as e:
            return False, f"canary error: {e}"
        finally:
            host.stop()
    return run

"""Canary: prove a specialised scheduler loads, runs and doesn't stall *on this device*
before it is allowed to manage the whole system.

The scheduler is loaded in SCX_OPS_SWITCH_PARTIAL mode, so only tasks that
explicitly opt into SCHED_EXT (our probe + hogs) are scheduled by it; everything
else keeps running under the stock fair scheduler. This is the scheduler analogue
of Shirudo's "monitor how a shield would affect applications before enforcing".
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from typing import Callable

DEFAULT_PROBE = os.path.join(os.path.dirname(__file__), "..", "tools", "workloads", "lat_probe.py")


MIN_LAT_SAMPLES = 20        # a generated scheduler must feed the latency histogram
MIN_HOG_SHARE = 0.10        # each hog must get >= 10 % of one CPU over the canary


def _run_canary(host, params, generated: bool, secs: float, p99_limit_us: int, probe: str, hogs: int):
    ok, detail = host.start(params, partial=True)
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
        if generated:
            # Extra checks for model-written schedulers: it must not starve the hogs (the
            # watchdog only fires after seconds), and it must keep the telemetry contract.
            dur = res.get("duration_ms") or secs * 1000
            hog_ms = res.get("hog_cpu_ms") or []
            if hog_ms and min(hog_ms) < MIN_HOG_SHARE * dur:
                return False, f"a CPU hog received only {min(hog_ms):.0f} ms of {dur:.0f} ms (starved)"
            stats = host.stats()
            if not stats or "lat" not in stats:
                return False, "no telemetry: the scheduler did not report stats"
            samples = sum(sum(row) for row in stats["lat"])
            if samples < MIN_LAT_SAMPLES:
                return False, f"only {samples} latency samples: conductor_note_running()/mark_enq() not wired"
        return True, res
    except (subprocess.TimeoutExpired, ValueError, KeyError) as e:
        return False, f"canary error: {e}"
    finally:
        host.stop()


def make_canary(secs: float, p99_limit_us: int, probe: str = DEFAULT_PROBE, hogs: int = 2):
    """Lifecycle canary: (host, manifest) -> (ok, detail). Generated manifests get the
    extra starvation and telemetry checks."""
    def run(host, manifest):
        return _run_canary(host, manifest.params, getattr(manifest, "is_generated", False),
                           secs, p99_limit_us, probe, hogs)
    return run


def make_dir_canary(secs: float, p99_limit_us: int, host_for_dir: Callable, sysfs_reader: Callable,
                    probe: str = DEFAULT_PROBE, hogs: int = 2, lock=None):
    """Generator-side early canary for a freshly built artifact: (artifact_dir, params) ->
    (ok | None, detail). Returns ok=None ("skipped") when another sched_ext scheduler is
    active, because only one can be attached at a time; the lifecycle runs the canary again
    at activation either way."""
    def run(artifact_dir, params):
        # `lock` is the Lifecycle's: hold it so the governor cannot attach something between
        # our "is the slot free?" check and our load.
        with (lock if lock is not None else contextlib.nullcontext()):
            st = sysfs_reader()
            if st.get("state") not in (None, "disabled"):
                return None, f"skipped: another sched_ext scheduler is active ({st})"
            return _run_canary(host_for_dir(artifact_dir), params, True, secs, p99_limit_us, probe, hogs)
    return run

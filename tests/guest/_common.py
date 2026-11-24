"""Helpers for in-guest tests. Run as root on a sched_ext kernel."""
import json, os, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
BUILD = os.environ.get("CONDUCTOR_BUILD", os.path.join(ROOT, "build"))
LOADER = os.path.join(BUILD, "conductor_load")
BPF_OBJ = os.path.join(BUILD, "scx_conductor.bpf.o")
SYSFS = "/sys/kernel/sched_ext"

_results = []


def check(name, cond, detail=""):
    _results.append({"check": name, "ok": bool(cond), "detail": str(detail)[:300]})
    print(("  ok   " if cond else "  FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""), flush=True)
    return bool(cond)


def sx():
    from conductord.host import read_sched_ext
    return read_sched_ext(SYSFS)


def wait_for(fn, timeout, step=0.25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return None


def finish(stage):
    ok = all(r["ok"] for r in _results)
    print(json.dumps({"stage": stage, "ok": ok, "checks": _results}))
    sys.exit(0 if ok else 1)

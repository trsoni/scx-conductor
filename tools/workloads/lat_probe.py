#!/usr/bin/env python3
"""Wakeup-latency probe + CPU hogs. Prints one JSON line.

  lat_probe.py --duration 5 --hogs 4            # baseline (stock scheduler)
  lat_probe.py --duration 5 --hogs 4 --ext      # probe + hogs opt into SCHED_EXT (=7)
  lat_probe.py --duration 5 --hogs 4 --cls-comm fg_probe   # rename comm for class tests

Latency = (actual wake time - requested wake time) of a 1 ms sleep loop, so it
measures timer-wakeup scheduling delay under contention.
"""
import argparse, ctypes, json, os, signal, subprocess, sys, time

SCHED_EXT = 7


def set_ext() -> bool:
    try:
        os.sched_setscheduler(0, SCHED_EXT, os.sched_param(0))
        return True
    except OSError:
        return False


def set_comm(name: str):
    try:
        ctypes.CDLL("libc.so.6").prctl(15, name.encode()[:15], 0, 0, 0)   # PR_SET_NAME
    except OSError:
        pass


def hog_main(ext: bool):
    if ext:
        set_ext()
    while True:
        pass


def pct(v, p):
    return v[min(len(v) - 1, int(len(v) * p))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=5)
    ap.add_argument("--hogs", type=int, default=2)
    ap.add_argument("--ext", action="store_true")
    ap.add_argument("--hog-child", action="store_true")
    ap.add_argument("--comm", default=None)
    a = ap.parse_args()
    if a.hog_child:
        hog_main(a.ext)
    if a.comm:
        set_comm(a.comm)
    policy_ok = set_ext() if a.ext else True

    hogs = [subprocess.Popen([sys.executable, __file__, "--hog-child", "--duration", "0"] + (["--ext"] if a.ext else []))
            for _ in range(a.hogs)]
    lat, end = [], time.perf_counter() + a.duration
    try:
        while time.perf_counter() < end:
            t0 = time.perf_counter_ns()
            time.sleep(0.001)
            lat.append(max(0, (time.perf_counter_ns() - t0 - 1_000_000) // 1000))
    finally:
        for h in hogs:
            h.send_signal(signal.SIGKILL)
            h.wait()
    lat.sort()
    print(json.dumps({"n": len(lat), "p50_us": pct(lat, .5), "p99_us": pct(lat, .99),
                      "max_us": lat[-1] if lat else 0, "policy_ok": policy_ok,
                      "ext": a.ext, "hogs": a.hogs}))


if __name__ == "__main__":
    main()

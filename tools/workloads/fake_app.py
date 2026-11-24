#!/usr/bin/env python3
"""Synthetic 'application' for end-to-end classifier tests.

Renames its own comm (so the classifier's name rules match), optionally opens a
device node (so fd-tag rules match), and burns a duty-cycled amount of CPU.

  fake_app.py --comm steam --cpu 40 --duration 30
  fake_app.py --comm libcamera-hello --cpu 15 --open /dev/null   # fd tag needs a real /dev/video*; see docs/TESTING.md
"""
import argparse, ctypes, os, time


def set_comm(name):
    try:
        ctypes.CDLL("libc.so.6").prctl(15, name.encode()[:15], 0, 0, 0)  # PR_SET_NAME
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--comm", required=True)
    ap.add_argument("--cpu", type=float, default=30.0, help="target %% of one CPU")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--open", action="append", default=[], help="keep this path open (fd tagging)")
    a = ap.parse_args()
    set_comm(a.comm)
    fds = [os.open(p, os.O_RDONLY) for p in a.open]
    period = 0.02
    busy = period * a.cpu / 100.0
    end = time.monotonic() + a.duration
    while time.monotonic() < end:
        t0 = time.perf_counter()
        while time.perf_counter() - t0 < busy:
            pass
        time.sleep(max(0.0, period - busy))
    for fd in fds:
        os.close(fd)


if __name__ == "__main__":
    main()

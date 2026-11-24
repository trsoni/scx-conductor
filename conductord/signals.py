"""Signal collection. Reads only /proc, /sys and an optional hint file.

procfs/sysfs roots are injectable so unit tests can use a fake tree.
Platform integrations (Android top-app, automotive HMI, desktop shells) feed
`hint.json` instead of patching this module.
"""
from __future__ import annotations

import glob
import json
import os
import time
from typing import Optional

from .model import ProcInfo, Snapshot

FD_TAGS = (
    ("/dev/dri/", "drm"),
    ("/dev/video", "v4l"),
    ("/dev/media", "media"),
    ("/dev/snd/", "snd"),
    ("/dev/dma_heap/", "dmabuf"),
    ("/dev/kgsl", "gpu"),
    ("/dev/mali", "gpu"),
    ("/dev/nvidia", "gpu"),
)


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.read()
    except OSError:
        return None


class Collector:
    def __init__(self, procfs="/proc", sysfs="/sys", hint_path="/run/conductor/hint.json",
                 fd_scan_min_cpu=0.5, clock=time.monotonic):
        self.procfs, self.sysfs, self.hint_path = procfs, sysfs, hint_path
        self.fd_scan_min_cpu = fd_scan_min_cpu
        self.clock = clock
        self.hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        self._prev_ticks: dict = {}
        self._prev_total: Optional[tuple] = None
        self._prev_forks: Optional[int] = None
        self._prev_t: Optional[float] = None

    # ---- system-wide ----
    def _cpu_stat(self):
        txt = _read(f"{self.procfs}/stat") or ""
        total = idle = forks = None
        for line in txt.splitlines():
            if line.startswith("cpu "):
                v = [int(x) for x in line.split()[1:]]
                total, idle = sum(v[:8]), v[3] + (v[4] if len(v) > 4 else 0)
            elif line.startswith("processes "):
                forks = int(line.split()[1])
        return total, idle, forks

    def _psi(self) -> float:
        txt = _read(f"{self.procfs}/pressure/cpu") or ""
        for line in txt.splitlines():
            if line.startswith("some"):
                for kv in line.split()[1:]:
                    if kv.startswith("avg10="):
                        return float(kv.split("=")[1])
        return 0.0

    def _gpu_busy(self) -> Optional[float]:
        vals = []
        for p in glob.glob(f"{self.sysfs}/class/drm/card*/device/gpu_busy_percent"):
            t = _read(p)
            if t and t.strip().isdigit():
                vals.append(float(t))
        return max(vals) if vals else None

    def _power(self):
        on_ac, bat = None, None
        for d in glob.glob(f"{self.sysfs}/class/power_supply/*"):
            typ = (_read(f"{d}/type") or "").strip()
            if typ == "Battery":
                c = (_read(f"{d}/capacity") or "").strip()
                if c.isdigit():
                    bat = float(c)
            elif typ in ("Mains", "USB", "USB_C", "USB_PD"):
                o = (_read(f"{d}/online") or "").strip()
                if o in ("0", "1"):
                    on_ac = (on_ac or False) or o == "1"
        return on_ac, bat

    def _thermal(self) -> Optional[float]:
        temps = []
        for p in glob.glob(f"{self.sysfs}/class/thermal/thermal_zone*/temp"):
            t = (_read(p) or "").strip()
            try:
                temps.append(int(t) / 1000.0)
            except ValueError:
                pass
        return max(temps) if temps else None

    def _hint(self, now_wall: float) -> Optional[dict]:
        txt = _read(self.hint_path)
        if not txt:
            return None
        try:
            h = json.loads(txt)
        except ValueError:
            return None
        if h.get("expires") and h["expires"] < now_wall:
            return None
        return h

    # ---- per process ----
    def _proc_ticks(self, pid: str):
        txt = _read(f"{self.procfs}/{pid}/stat")
        if not txt:
            return None
        r = txt.rfind(")")
        comm = txt[txt.find("(") + 1:r]
        f = txt[r + 2:].split()
        return comm, int(f[11]) + int(f[12])      # utime + stime

    def _fd_tags(self, pid: str) -> frozenset:
        tags = set()
        try:
            for fd in os.listdir(f"{self.procfs}/{pid}/fd"):
                try:
                    tgt = os.readlink(f"{self.procfs}/{pid}/fd/{fd}")
                except OSError:
                    continue
                for prefix, tag in FD_TAGS:
                    if tgt.startswith(prefix):
                        tags.add(tag)
        except OSError:
            pass
        return frozenset(tags)

    def collect(self) -> Snapshot:
        now = self.clock()
        dt = (now - self._prev_t) if self._prev_t is not None else None
        total, idle, forks = self._cpu_stat()

        util = 0.0
        if self._prev_total and total is not None:
            dtot, didle = total - self._prev_total[0], idle - self._prev_total[1]
            util = 100.0 * (dtot - didle) / dtot if dtot > 0 else 0.0
        fork_rate = 0.0
        if self._prev_forks is not None and forks is not None and dt:
            fork_rate = max(0.0, (forks - self._prev_forks) / dt)

        procs, ticks = [], {}
        for pid in os.listdir(self.procfs) if os.path.isdir(self.procfs) else []:
            if not pid.isdigit():
                continue
            r = self._proc_ticks(pid)
            if not r:
                continue
            comm, t = r
            ticks[pid] = t
            cpu = 0.0
            if dt and pid in self._prev_ticks:
                cpu = 100.0 * (t - self._prev_ticks[pid]) / self.hz / dt
            tags = self._fd_tags(pid) if cpu >= self.fd_scan_min_cpu else frozenset()
            procs.append(ProcInfo(int(pid), comm, cpu, tags))

        on_ac, bat = self._power()
        snap = Snapshot(ts=now, cpu_util_pct=util, psi_cpu_some10=self._psi(), fork_rate=fork_rate,
                        gpu_busy_pct=self._gpu_busy(), on_ac=on_ac, battery_pct=bat,
                        thermal_c=self._thermal(), procs=procs, hint=self._hint(time.time()))
        self._prev_ticks, self._prev_total, self._prev_forks, self._prev_t = ticks, (total, idle), forks, now
        return snap

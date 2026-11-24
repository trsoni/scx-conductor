"""The governor loop: observe -> classify -> decide -> (forge) -> apply -> guard."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from typing import Optional

from .classifier import Debouncer, classify
from .forge import ApprovedStore, Forge, Manifest
from .lifecycle import Lifecycle
from .model import Snapshot, Workload
from .policy import power_state


class Governor:
    def __init__(self, profiles: dict, platform: str, collector, forge: Forge, lifecycle: Lifecycle,
                 audit, store: Optional[ApprovedStore] = None, min_switch_s: float = 8.0,
                 clock=time.monotonic):
        self.profiles, self.platform = profiles, platform
        self.pcfg = profiles["platforms"][platform]
        self.collector, self.forge, self.lc, self.audit, self.store = collector, forge, lifecycle, audit, store
        self.deb = Debouncer(min_dwell_s=min_switch_s)
        self.clock = clock
        self.min_switch_s = min_switch_s
        self.last_switch = -1e9
        self.pinned: Optional[str] = None           # 'baseline' | workload name
        self.hint: Optional[dict] = None
        self.last_class = None
        self.last_state = "ac"
        self.last_event: Optional[str] = None

    # ---- manifest selection (generate vs approved-only) ----
    def desired_manifest(self, wl: Workload, state: str) -> Optional[Manifest]:
        name = f"{wl.value}@{self.platform}/{state}"
        if self.pcfg.get("approved_only"):
            return self.store.find(name) if self.store else None
        return self.forge.make(wl, self.platform, state)

    def step(self, snap: Optional[Snapshot] = None) -> dict:
        now = self.clock()
        s = snap or self.collector.collect()
        if self.hint and self.hint.get("expires", 0) < time.time():
            self.hint = None
        if self.hint and not s.hint:
            s.hint = self.hint
        c = classify(s)
        wl = self.deb.update(c, now)
        state = power_state(s, self.pcfg)

        if self.pinned == "baseline":
            wl_eff = Workload.IDLE
        elif self.pinned:
            wl_eff = Workload(self.pinned)
        else:
            wl_eff = wl

        thermal_trip = state == "thermal" and self.last_state != "thermal"
        want = self.desired_manifest(wl_eff, state)
        cur = self.lc.active
        changed = (want is None and cur is not None) or (want is not None and (cur is None or cur.hash != want.hash))

        if changed and (now - self.last_switch >= self.min_switch_s or thermal_trip or self.pinned):
            self.audit.record("decision", workload=wl_eff.value, score=round(c.score, 2),
                              evidence=c.evidence, power_state=state,
                              manifest=(want.name if want else "baseline"))
            if want is None:
                self.lc.unload(f"workload={wl_eff.value}: stock scheduler")
            else:
                self.lc.apply(want, psi_baseline=s.psi_cpu_some10)
            self.last_switch = now
        self.last_state = state

        if c.workload == wl or self.pinned:
            self.lc.sync_classes(c.assignments)
        self.last_event = self.lc.tick(s.psi_cpu_some10)
        self.last_class = c
        return {"workload": wl_eff.value, "classified": c.workload.value, "score": round(c.score, 2),
                "power_state": state, "active": self.lc.active.name if self.lc.active else None,
                "event": self.last_event}

    def status(self) -> dict:
        return {"platform": self.platform, "workload": self.deb.current.value,
                "active": self.lc.active.name if self.lc.active else None,
                "pinned": self.pinned, "quarantined": len(self.lc.quarantine),
                "audit_seq": self.audit.seq, "audit_head": self.audit.head[:16]}

    def run(self, interval: float = 1.0, duration: Optional[float] = None, stop: Optional[threading.Event] = None):
        end = time.monotonic() + duration if duration else None
        stop = stop or threading.Event()
        try:
            while not stop.is_set() and (end is None or time.monotonic() < end):
                t0 = time.monotonic()
                try:
                    self.step()
                except Exception as e:                          # never let the loop die with a scheduler loaded
                    self.audit.record("governor-error", error=repr(e))
                    self.lc.unload("governor error")
                stop.wait(max(0.0, interval - (time.monotonic() - t0)))
        finally:
            self.lc.unload("governor shutdown")                 # always leave the box on the stock scheduler


class ControlServer(threading.Thread):
    """JSON-line UNIX socket: status | hint | hold | release | rollback."""

    def __init__(self, gov: Governor, path: str):
        super().__init__(daemon=True)
        self.gov, self.path = gov, path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            os.unlink(path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        os.chmod(path, 0o660)
        self.sock.listen(4)
        self.sock.settimeout(0.5)
        self._stop = threading.Event()

    def handle(self, req: dict) -> dict:
        cmd = req.get("cmd")
        g = self.gov
        if cmd == "status":
            return {"ok": True, **g.status()}
        if cmd == "hint":
            ttl = float(req.get("ttl", 30))
            g.hint = {"workload": req["workload"], "pids": req.get("pids", []), "expires": time.time() + ttl}
            return {"ok": True}
        if cmd == "hold":
            g.pinned = req["workload"]
            return {"ok": True}
        if cmd == "release":
            g.pinned, g.hint = None, None
            return {"ok": True}
        if cmd == "rollback":
            g.lc.unload("operator rollback")
            g.pinned = "baseline"
            return {"ok": True}
        return {"ok": False, "error": "unknown cmd"}

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    data = conn.makefile().readline()
                    resp = self.handle(json.loads(data))
                except Exception as e:
                    resp = {"ok": False, "error": str(e)}
                conn.sendall((json.dumps(resp) + "\n").encode())

    def stop(self):
        self._stop.set()
        self.sock.close()
        if os.path.exists(self.path):
            os.unlink(self.path)


def ctl_request(path: str, req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    s.sendall((json.dumps(req) + "\n").encode())
    return json.loads(s.makefile().readline())

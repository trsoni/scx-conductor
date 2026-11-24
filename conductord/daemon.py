"""The governor loop: observe -> classify -> decide -> (forge) -> apply -> guard."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .classifier import Debouncer, classify
from .forge import ApprovedStore, Forge, Manifest
from .generator import GenManager
from .genstore import GenForge, GenStore
from .lifecycle import Lifecycle
from .model import Snapshot, Workload
from .policy import build_params, power_state


@dataclass
class GenSupport:
    """Everything the governor needs to use (and optionally request) generated schedulers."""
    store: GenStore
    forge: GenForge
    machine: str
    release: str
    manager: Optional[GenManager] = None      # None: use approved artifacts, never generate
    on_demand: bool = False                   # opt-in: ask the backend when no artifact exists


class Governor:
    def __init__(self, profiles: dict, platform: str, collector, forge: Forge, lifecycle: Lifecycle,
                 audit, store: Optional[ApprovedStore] = None, min_switch_s: float = 8.0,
                 clock=time.monotonic, gen: Optional[GenSupport] = None):
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
        self.gen = gen
        self._gen_ok: dict = {}                     # manifest hash -> (ok, reason): verify once, not per tick

    # ---- manifest selection (approved-only / generated / reference template) ----
    def desired_manifest(self, wl: Workload, state: str) -> Optional[Manifest]:
        name = f"{wl.value}@{self.platform}/{state}"
        if self.pcfg.get("approved_only"):
            return self.store.find(name) if self.store else None
        template = self.forge.make(wl, self.platform, state)
        if self.gen is None or not self.pcfg.get("allow_device_generation") or template is None:
            return template                         # idle (None) never gets a custom scheduler
        params = build_params(self.profiles, wl, self.platform, state)
        gm = self._generated_manifest(wl, state, params) if params else None
        if gm is not None:
            return gm
        if params and self.gen.on_demand and self.gen.manager is not None:
            self.gen.manager.request(wl, self.platform, state, params)   # non-blocking
        return template

    def _generated_manifest(self, wl: Workload, state: str, params) -> Optional[Manifest]:
        """An operator-approved, kernel-matching generated scheduler for this workload, if one
        exists and is currently usable; otherwise None and the reference template is used."""
        g = self.gen
        gid = g.store.lookup(wl.value, self.platform, g.machine, g.release)
        if not gid:
            return None
        m = g.forge.make(gid, wl, self.platform, state, params)
        if m is None or self.lc.is_quarantined(m.hash):
            return None
        res = self._gen_ok.get(m.hash)
        if res is None:
            res = self._gen_ok[m.hash] = self.lc.verifier.verify(m, self.platform)
            if not res[0]:
                self.audit.record("gen-unusable", gen_id=gid, reason=res[1])
        return m if res[0] else None

    def request_generation(self, workload: str) -> dict:
        if self.gen is None or self.gen.manager is None:
            return {"ok": False, "error": "no generation backend configured (--gen-backend)"}
        if not self.pcfg.get("allow_device_generation"):
            return {"ok": False, "error": f"platform {self.platform!r} does not allow on-device generation"}
        wl = Workload(workload)
        params = build_params(self.profiles, wl, self.platform, self.last_state)
        if params is None:
            return {"ok": False, "error": f"{workload} uses the stock scheduler"}
        return {"ok": True, "result": self.gen.manager.request(wl, self.platform, self.last_state, params)}

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
        st = {"platform": self.platform, "workload": self.deb.current.value,
              "active": self.lc.active.name if self.lc.active else None,
              "pinned": self.pinned, "quarantined": len(self.lc.quarantine),
              "audit_seq": self.audit.seq, "audit_head": self.audit.head[:16]}
        if self.gen is not None:
            counts: dict = {}
            for m in self.gen.store.list():
                counts[m.get("status", "?")] = counts.get(m.get("status", "?"), 0) + 1
            st["gen"] = {"on_demand": self.gen.on_demand, "artifacts": counts,
                         "manager": self.gen.manager.status() if self.gen.manager else None}
        return st

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
    """JSON-line UNIX socket: status | hint | hold | release | rollback | gen."""

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
        if cmd == "gen":
            return g.request_generation(req["workload"])
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

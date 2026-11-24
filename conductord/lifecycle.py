"""Lifecycle: verify -> (canary) -> load -> guard -> unload / rollback.

Shirudo parallel
  monitor-before-enforce  ->  canary load in SCX_OPS_SWITCH_PARTIAL mode: only
                              tasks that opt into SCHED_EXT are touched, so a bad
                              scheduler cannot affect the rest of the system
  approve + signed load   ->  Verifier (signature, digest, platform, TTL, bounds)
  live protection         ->  loader process owns the struct_ops link
  verifiable record       ->  AuditLog (hash chain, optional TPM PCR extend)
  remove shield           ->  unload; kernel falls back to the fair class
Extra safety unique to scheduling: the kernel watchdog (timeout_ms) ejects a
stalling scheduler on its own; we detect that, quarantine the manifest, and stay
on the stock scheduler.
"""
from __future__ import annotations

import functools
import threading
import time
from typing import Callable, Optional

from .forge import Manifest, Verifier
from .audit import AuditLog


def _locked(fn):
    """Serialise lifecycle operations. The generator's early canary runs on another thread and
    needs the (single) sched_ext slot, so it takes the same lock."""
    @functools.wraps(fn)
    def wrapper(self, *a, **kw):
        with self.lock:
            return fn(self, *a, **kw)
    return wrapper


def lat_breach(delta_lat: list, slo: dict) -> bool:
    """delta_lat: [class][bucket] counts since the last check. Looks at FG and MEDIA."""
    for cls in (1, 2):
        h = delta_lat[cls]
        total = sum(h)
        if total >= slo["lat_min_samples"]:
            bad = sum(h[slo["lat_bad_bucket"]:])
            if bad / total >= slo["lat_bad_frac"]:
                return True
    return False


class Lifecycle:
    def __init__(self, host, verifier: Verifier, audit: AuditLog, profiles: dict, platform: str,
                 canary_fn: Optional[Callable] = None, clock=time.monotonic,
                 host_factory: Optional[Callable] = None, lock: Optional[threading.RLock] = None):
        # host_factory(manifest) -> host: lets a generated scheduler (its own loader binary)
        # and the reference template (the shared loader) live behind one Lifecycle.
        self.host, self.verifier, self.audit = host, verifier, audit
        self.host_factory = host_factory
        self.lock = lock or threading.RLock()
        self.profiles, self.platform = profiles, platform
        self.pcfg = profiles["platforms"][platform]
        self.slo = profiles["slo"]
        self.canary_fn, self.clock = canary_fn, clock
        self.active: Optional[Manifest] = None
        self.canary_passed: set = set()
        self.quarantine: dict = {}
        self.synced: dict = {}
        self.psi_baseline = 0.0
        self._psi_bad = 0
        self._lat_bad = 0
        self._last_lat: Optional[list] = None
        self._ticks = 0

    # ---------- apply / unload ----------
    @_locked
    def apply(self, m: Manifest, psi_baseline: float = 0.0) -> tuple:
        h = m.hash
        if self.active and self.active.hash == h and self.host.alive():
            return True, "unchanged"
        until = self.quarantine.get(h)
        if until is not None and self.clock() < until:
            self.audit.record("skip-quarantined", name=m.name, manifest=h)
            return False, "quarantined"

        ok, why = self.verifier.verify(m, self.platform)
        if not ok:
            self.audit.record("rejected", name=m.name, manifest=h, reason=why)
            return False, why

        if self.active:
            self.unload("switch")
        if self.host_factory:
            chosen = self.host_factory(m)
            if chosen is not None:
                self.host = chosen          # the previous host was stopped just above

        if self.pcfg.get("canary") and self.canary_fn and h not in self.canary_passed:
            self.audit.record("canary-start", name=m.name, manifest=h)
            cok, detail = self.canary_fn(self.host, m)
            self.audit.record("canary-result", name=m.name, manifest=h, ok=cok, detail=detail)
            if not cok:
                self._quarantine(h, "canary failed")
                return False, "canary failed"
            self.canary_passed.add(h)

        sok, detail = self.host.start(m.params, partial=False)
        if not sok:
            self.audit.record("load-failed", name=m.name, manifest=h, detail=detail)
            self._quarantine(h, "load failed")
            return False, "load failed"

        st = self.host.sched_ext_state()
        if st.get("state") is not None and (st["state"] != "enabled" or st.get("ops") != m.ops_name):
            self.host.stop()
            self.audit.record("load-failed", name=m.name, manifest=h, detail=f"sysfs state {st}")
            self._quarantine(h, "sysfs state mismatch")
            return False, "sysfs mismatch"

        self.active, self.synced = m, {}
        self.psi_baseline, self._psi_bad, self._lat_bad, self._last_lat = psi_baseline, 0, 0, None
        self.audit.record("load", name=m.name, manifest=h, params=m.body["params"], sched_ext=st,
                          template_sha256=m.body["template_sha256"], gen_id=m.body.get("gen_id"))
        return True, "loaded"

    @_locked
    def unload(self, reason: str) -> None:
        if not self.active:
            return
        info = self.host.stop()
        self.audit.record("unload", name=self.active.name, manifest=self.active.hash,
                          reason=reason, info=info)
        self.active, self.synced = None, {}

    def is_quarantined(self, h: str) -> bool:
        until = self.quarantine.get(h)
        return until is not None and self.clock() < until

    def _quarantine(self, h: str, why: str) -> None:
        self.quarantine[h] = self.clock() + self.slo["quarantine_s"]
        self.audit.record("quarantine", manifest=h, reason=why, seconds=self.slo["quarantine_s"])

    # ---------- per-process class sync ----------
    @_locked
    def sync_classes(self, assignments: dict) -> None:
        if not self.active or not self.host.alive():
            return
        want = {pid: int(c) for pid, c in assignments.items() if int(c) != 0}
        for pid, c in want.items():
            if self.synced.get(pid) != c and self.host.set_class(pid, c):
                self.synced[pid] = c
        for pid in [p for p in self.synced if p not in want]:
            self.host.clear_class(pid)
            del self.synced[pid]

    # ---------- guard ----------
    @_locked
    def tick(self, psi_some10: float) -> Optional[str]:
        """Call once per governor tick. Returns 'ejected' | 'rollback' | None."""
        if not self.active:
            return None
        self._ticks += 1
        dead = self.host.reap_if_dead()
        if dead is not None or not self.host.alive():
            self.audit.record("ejected", name=self.active.name, manifest=self.active.hash, info=dead)
            self._quarantine(self.active.hash, "ejected by kernel or loader died")
            self.active, self.synced = None, {}
            return "ejected"

        limit = max(self.psi_baseline + self.slo["psi_regress_abs"], self.slo["psi_floor"])
        self._psi_bad = self._psi_bad + 1 if psi_some10 > limit else 0
        if self._psi_bad >= self.slo["psi_breach_ticks"]:
            return self._rollback(f"psi {psi_some10:.0f} > {limit:.0f}")

        if self._ticks % 5 == 0:
            st = self.host.stats()
            if st and "lat" in st:
                cur = st["lat"]
                if self._last_lat is not None:
                    delta = [[max(0, a - b) for a, b in zip(cur[c], self._last_lat[c])] for c in range(len(cur))]
                    self._lat_bad = self._lat_bad + 1 if lat_breach(delta, self.slo) else 0
                self._last_lat = cur
                if self._lat_bad >= self.slo["lat_breach_checks"]:
                    return self._rollback("latency SLO (fg/media tail)")
        return None

    def _rollback(self, why: str) -> str:
        name, h = self.active.name, self.active.hash
        self.unload(f"rollback: {why}")
        self.audit.record("rollback", name=name, manifest=h, reason=why)
        self._quarantine(h, why)
        return "rollback"

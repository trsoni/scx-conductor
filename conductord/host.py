"""Hosts: the thing that actually owns a loaded sched_ext scheduler.

LoaderHost  - spawns build/conductor_load and talks its line protocol.
FakeHost    - same interface, no kernel; used by unit tests and --dry-run.
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import time
from typing import Optional

from .model import Params

SYSFS = "/sys/kernel/sched_ext"


def read_sched_ext(sysfs: str = SYSFS) -> dict:
    """{'state': 'enabled'|'disabled'|None, 'ops': name|None}. Handles old/new layouts."""
    def rd(p):
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError:
            return None
    return {"state": rd(f"{sysfs}/state"), "ops": rd(f"{sysfs}/root/ops") or rd(f"{sysfs}/ops")}


def csv(v) -> str:
    return ",".join(str(int(x)) for x in v)


class LoaderHost:
    def __init__(self, loader_path: str, sysfs: str = SYSFS, extra_args: Optional[list] = None):
        self.loader_path, self.sysfs = loader_path, sysfs
        self.extra_args = extra_args or []
        self.proc: Optional[subprocess.Popen] = None
        self._buf = b""
        self.exit_info: Optional[dict] = None

    # ---- line IO with timeout (no stdio buffering surprises) ----
    def _readline(self, timeout: float) -> Optional[dict]:
        end = time.monotonic() + timeout
        fd = self.proc.stdout.fileno()
        while time.monotonic() < end:
            if b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                try:
                    return json.loads(line)
                except ValueError:
                    continue
            r, _, _ = select.select([fd], [], [], max(0.0, end - time.monotonic()))
            if not r:
                break
            chunk = os.read(fd, 65536)
            if not chunk:
                return None
            self._buf += chunk
        return None

    def start(self, p: Params, partial: bool = False, inject_stall: bool = False,
              timeout: float = 15.0) -> tuple:
        """Returns (ok, detail)."""
        if self.proc:
            self.stop()
        cmd = [self.loader_path, "--slice-ns", csv(p.slice_ns), "--credit-ns", csv(p.credit_ns),
               "--charge-pct", csv(p.charge_pct), "--perf", csv(p.perf),
               "--timeout-ms", str(p.timeout_ms)] + self.extra_args
        if partial:
            cmd.append("--partial")
        if inject_stall:
            cmd.append("--inject-stall")
        self._buf, self.exit_info = b"", None
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        ev = self._readline(timeout)
        if not ev or ev.get("event") != "attached":
            err = b""
            if self.proc.poll() is not None:
                err = self.proc.stderr.read() or b""
            self._kill()
            return False, f"loader did not attach: {err.decode(errors='replace')[-400:]}"
        return True, "attached"

    def _send(self, line: str) -> bool:
        try:
            self.proc.stdin.write((line + "\n").encode())
            self.proc.stdin.flush()
            return True
        except (BrokenPipeError, OSError, AttributeError):
            return False

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def set_class(self, tgid: int, cls: int) -> bool:
        return self._send(f"set {tgid} {int(cls)}")

    def clear_class(self, tgid: int) -> bool:
        return self._send(f"clr {tgid}")

    def stats(self, timeout: float = 2.0) -> Optional[dict]:
        if not self.alive() or not self._send("stats"):
            return None
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            ev = self._readline(max(0.05, end - time.monotonic()))
            if ev and ev.get("event") == "stats":
                return ev
        return None

    def sched_ext_state(self) -> dict:
        return read_sched_ext(self.sysfs)

    def _kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
        if self.proc:
            self.proc.wait()
        self.proc = None

    def stop(self, timeout: float = 5.0) -> dict:
        """Unload. Closing the struct_ops link reverts every task to the fair class."""
        info = {"rc": None}
        if not self.proc:
            return info
        if self.proc.poll() is None:
            self._send("quit")
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait()
        info["rc"] = self.proc.returncode
        # drain a final "exited" event if present
        try:
            tail = self.proc.stdout.read() or b""
            for ln in tail.split(b"\n"):
                if b'"exited"' in ln:
                    info["exited"] = json.loads(ln)
        except (OSError, ValueError):
            pass
        self.exit_info = info
        self.proc = None
        return info

    def reap_if_dead(self) -> Optional[dict]:
        """If the kernel ejected the scheduler (watchdog) the loader exits 3: collect why."""
        if self.proc is not None and self.proc.poll() is not None:
            return self.stop()
        return None


class FakeHost:
    """In-memory host with scriptable failures, same surface as LoaderHost."""

    def __init__(self):
        self.running = False
        self.params: Optional[Params] = None
        self.partial = False
        self.classes: dict = {}
        self.history: list = []
        self.fail_start = False
        self.dead = False
        self.stats_payload: Optional[dict] = None
        self.state_ops = "conductor"

    def start(self, p, partial=False, inject_stall=False, timeout=0.0):
        self.history.append(("start", partial))
        if self.fail_start:
            return False, "verifier rejected (fake)"
        self.running, self.params, self.partial, self.dead, self.classes = True, p, partial, False, {}
        return True, "attached"

    def alive(self):
        return self.running and not self.dead

    def set_class(self, tgid, cls):
        self.classes[tgid] = int(cls)
        return True

    def clear_class(self, tgid):
        self.classes.pop(tgid, None)
        return True

    def stats(self, timeout=0.0):
        return self.stats_payload

    def sched_ext_state(self):
        return {"state": "enabled" if self.alive() else "disabled",
                "ops": self.state_ops if self.alive() else None}

    def stop(self, timeout=0.0):
        self.history.append(("stop", None))
        self.running = False
        return {"rc": 0}

    def reap_if_dead(self):
        if self.running and self.dead:
            self.running = False
            return {"rc": 3, "exited": {"kernel_ejected": 1}}
        return None

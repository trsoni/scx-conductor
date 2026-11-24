"""Shared data model (stdlib only, so it runs on minimal images)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Workload(str, Enum):
    IDLE = "idle"
    UI = "ui"
    BROWSER = "browser"
    GAMING = "gaming"
    VIDEO = "video"
    CAMERA = "camera"
    GRAPHICS = "graphics"
    AGENTIC = "agentic"
    BATCH = "batch"


class Cls(int, Enum):
    """Mirrors enum conductor_class in bpf/conductor.h."""
    NORMAL = 0
    FG = 1
    MEDIA = 2
    BG = 3


NR_CLS = 4


@dataclass
class ProcInfo:
    pid: int                      # tgid
    comm: str
    cpu_pct: float = 0.0          # of one CPU, over the last interval
    tags: frozenset = frozenset() # fd tags: drm, v4l, media, snd, gpu, dmabuf


@dataclass
class Snapshot:
    ts: float = 0.0
    cpu_util_pct: float = 0.0     # whole-system, 0..100
    psi_cpu_some10: float = 0.0
    fork_rate: float = 0.0        # processes/s
    gpu_busy_pct: Optional[float] = None
    on_ac: Optional[bool] = None
    battery_pct: Optional[float] = None
    thermal_c: Optional[float] = None
    procs: list = field(default_factory=list)
    hint: Optional[dict] = None   # {"workload": "gaming", "pids": [..]}


@dataclass
class Classification:
    workload: Workload
    score: float
    evidence: list
    assignments: dict             # tgid -> Cls (only FG/MEDIA/BG; NORMAL is implicit)


@dataclass
class Params:
    """Everything the loader needs to specialise the BPF template."""
    slice_ns: list
    credit_ns: list
    charge_pct: list
    perf: list
    timeout_ms: int = 5000
    partial: bool = False

    def to_dict(self) -> dict:
        return {
            "slice_ns": list(self.slice_ns), "credit_ns": list(self.credit_ns),
            "charge_pct": list(self.charge_pct), "perf": list(self.perf),
            "timeout_ms": self.timeout_ms, "partial": self.partial,
        }

    @staticmethod
    def from_dict(d: dict) -> "Params":
        return Params(list(d["slice_ns"]), list(d["credit_ns"]), list(d["charge_pct"]),
                      list(d["perf"]), int(d.get("timeout_ms", 5000)), bool(d.get("partial", False)))

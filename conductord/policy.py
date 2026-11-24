"""Policy: (workload, platform, power state) -> specialised scheduler Params."""
from __future__ import annotations

import json
import os
import platform as _platform
from typing import Optional

from .model import NR_CLS, Params, Snapshot, Workload

MIN_SLICE_NS = 500_000
MAX_SLICE_NS = 50_000_000


def load_profiles(path: str) -> dict:
    with open(path) as f:
        d = json.load(f)
    if d.get("schema") != 1:
        raise ValueError("unsupported profiles schema")
    return d


def detect_platform(sysfs="/sys", procfs="/proc", override: Optional[str] = None) -> str:
    """Best-effort class guess. Production images should set it explicitly
    (/etc/conductor/platform or CONDUCTOR_PLATFORM); a wrong guess is fail-safe
    only for 'approved_only' classes, so we default to 'vm'/'laptop' not 'automotive'."""
    if override:
        return override
    env = os.environ.get("CONDUCTOR_PLATFORM")
    if env:
        return env
    try:
        with open("/etc/conductor/platform") as f:
            return f.read().strip()
    except OSError:
        pass
    if os.path.exists("/system/build.prop"):
        return "mobile"
    try:
        with open(f"{procfs}/cpuinfo") as f:
            for line in f:
                if line.startswith("flags") and "hypervisor" in line.split():
                    return "vm"
    except OSError:
        pass
    try:
        with open(f"{sysfs}/class/dmi/id/chassis_type") as f:
            if f.read().strip() in {"8", "9", "10", "14", "30", "31", "32"}:
                return "laptop"
    except OSError:
        pass
    if os.path.isdir(f"{sysfs}/class/power_supply") and any(
            "BAT" in n for n in os.listdir(f"{sysfs}/class/power_supply")):
        return "laptop"
    return "iot" if _platform.machine() in ("aarch64", "armv7l") else "laptop"


def power_state(s: Snapshot, pcfg: dict) -> str:
    states = pcfg.get("states", {})
    lim = states.get("thermal", {}).get("limit_c")
    if lim is not None and s.thermal_c is not None and s.thermal_c >= lim:
        return "thermal"
    if s.on_ac is False and s.battery_pct is not None:
        return "low_battery" if s.battery_pct <= 20 else "battery"
    return "ac"


def build_params(profiles: dict, workload: Workload, platform: str, state: str) -> Optional[Params]:
    """Returns None => run the stock scheduler (unload anything custom)."""
    pcfg = profiles["platforms"].get(platform)
    if pcfg is None:
        raise KeyError(f"unknown platform {platform!r}")
    wl = profiles["workloads"].get(workload.value)
    if wl is None:
        return None
    allowed = pcfg.get("allowed_workloads")
    if allowed is not None and workload.value not in allowed:
        return None

    st = pcfg["states"].get(state) or pcfg["states"]["ac"]
    cap, scale = int(st["perf_cap"]), float(st["slice_scale"])
    slice_ns = [min(MAX_SLICE_NS, max(MIN_SLICE_NS, int(us * 1000 * scale))) for us in wl["slice_us"]]
    credit_ns = [int(us * 1000) for us in wl["credit_us"]]
    perf = []
    for v in wl["perf"]:
        # 0 means "leave cpufreq alone"; off-AC we still cap so power state is honoured.
        v = cap if (v == 0 and state != "ac") else v
        perf.append(0 if v == 0 else min(v, cap))
    p = Params(slice_ns, credit_ns, list(wl["charge_pct"]), perf, int(pcfg["timeout_ms"]), False)
    validate_params(p)
    return p


def validate_params(p: Params) -> None:
    """Hard bounds: the manifest verifier applies the same checks on-device."""
    for name in ("slice_ns", "credit_ns", "charge_pct", "perf"):
        v = getattr(p, name)
        if len(v) != NR_CLS or not all(isinstance(x, int) and x >= 0 for x in v):
            raise ValueError(f"{name}: need {NR_CLS} non-negative ints")
    if not all(MIN_SLICE_NS <= x <= MAX_SLICE_NS for x in p.slice_ns):
        raise ValueError("slice_ns out of bounds")
    if not all(x <= 100_000_000 for x in p.credit_ns):
        raise ValueError("credit_ns out of bounds")
    if not all(10 <= x <= 1000 for x in p.charge_pct):
        raise ValueError("charge_pct out of bounds (10..1000)")
    if not all(x <= 1024 for x in p.perf):
        raise ValueError("perf out of bounds (<=1024)")
    if not 100 <= p.timeout_ms <= 30000:
        raise ValueError("timeout_ms out of bounds (100..30000)")

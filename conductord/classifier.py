"""Workload classification: signals -> (workload, per-process class assignments).

Deliberately rule-based and explainable: every decision carries evidence that
goes into the audit log. An ML/LLM classifier can replace `classify()` later
without touching the rest of the pipeline; it must still emit the same
Classification so the signed-manifest path stays unchanged.
"""
from __future__ import annotations

from .model import Classification, Cls, ProcInfo, Snapshot, Workload

# comm is truncated to 15 chars by the kernel, so we match by prefix.
GAME = ("steam", "gamescope", "wine", "proton", "retroarch", "yuzu", "ryujinx", "dolphin-emu",
        "godot", "unity", "unrealeditor", "lutris", "heroic")
BROWSER = ("firefox", "chrome", "chromium", "brave", "epiphany", "vivaldi", "msedge", "opera",
           "webkitwebproce", "web content", "gpu-process")
VIDEO = ("mpv", "vlc", "ffmpeg", "ffplay", "gst-play", "totem", "celluloid", "kodi", "mediaserver",
         "mediacodec", "android.hardwar")
CAMERA = ("libcamera", "cam", "camera", "cameraserver", "v4l2", "gst-launch", "cheese", "snapshot",
          "rkisp", "isp_")
GRAPHICS = ("blender", "gimp", "krita", "inkscape", "darktable", "unigine", "glmark2", "vkcube")
AGENT = ("claude", "codex", "aider", "cursor", "ollama", "llama", "opencode", "gemini", "goose",
         "mcp-")
BATCH = ("make", "ninja", "cargo", "rustc", "gcc", "cc1", "cc1plus", "clang", "ld", "ld.lld",
         "bitbake", "pytest", "stress", "stress-ng")
SHELL = ("gnome-shell", "kwin_wayland", "kwin_x11", "xorg", "xwayland", "sway", "weston", "mutter",
         "plasmashell", "surfaceflinger", "systemui", "hmi", "cluster", "labwc")
AUDIO = ("pipewire", "pipewire-pulse", "wireplumber", "pulseaudio", "audioserver", "jackd")

TIE_ORDER = [Workload.CAMERA, Workload.GAMING, Workload.VIDEO, Workload.GRAPHICS,
             Workload.AGENTIC, Workload.BROWSER, Workload.BATCH, Workload.UI, Workload.IDLE]


def _m(comm: str, names) -> bool:
    c = comm.lower()
    return any(c == n or c.startswith(n) for n in names)


def _sum_cpu(procs, names) -> float:
    return sum(p.cpu_pct for p in procs if _m(p.comm, names))


def classify(s: Snapshot) -> Classification:
    # Explicit hint (Android top-app, automotive HMI, desktop shell, `conductorctl hint`) wins.
    if s.hint and s.hint.get("workload") in {w.value for w in Workload}:
        wl = Workload(s.hint["workload"])
        pids = set(s.hint.get("pids", []))
        return _assign(wl, 1.0, ["hint"], s, hint_pids=pids)

    scores = {w: 0.0 for w in Workload}
    ev = {w: [] for w in Workload}

    def bump(w, v, why):
        if v > scores[w]:
            scores[w] = v
        ev[w].append(why)

    for p in s.procs:
        if p.cpu_pct < 1.0:
            continue
        if ({"v4l", "media"} & p.tags):
            bump(Workload.CAMERA, 0.95 if _m(p.comm, CAMERA) else 0.8, f"{p.comm}:camera-fd")
        elif _m(p.comm, CAMERA) and p.cpu_pct >= 3:
            bump(Workload.CAMERA, 0.7, f"{p.comm}:camera-comm")
        if _m(p.comm, GAME) and p.cpu_pct >= 5:
            bump(Workload.GAMING, 0.9, f"{p.comm}:game-comm")
        elif "drm" in p.tags and p.cpu_pct >= 30 and (s.gpu_busy_pct or 0) >= 60:
            bump(Workload.GAMING, 0.7, f"{p.comm}:drm+gpu-busy")
        if _m(p.comm, VIDEO):
            bump(Workload.VIDEO, 0.95 if ({"drm", "v4l", "dmabuf"} & p.tags) else 0.85, f"{p.comm}:video-comm")
        if _m(p.comm, GRAPHICS) and p.cpu_pct >= 10:
            bump(Workload.GRAPHICS, 0.8, f"{p.comm}:graphics-comm")
        if _m(p.comm, AGENT) and p.cpu_pct >= 2:
            bump(Workload.AGENTIC, 0.75 + (0.15 if s.fork_rate >= 20 else 0.0), f"{p.comm}:agent-comm")

    if (s.gpu_busy_pct or 0) >= 70 and scores[Workload.GAMING] < 0.7:
        bump(Workload.GRAPHICS, 0.5, f"gpu_busy={s.gpu_busy_pct:.0f}")
    if s.fork_rate >= 30 and s.cpu_util_pct >= 30 and scores[Workload.AGENTIC] == 0.0:
        bump(Workload.AGENTIC, 0.5, f"fork_rate={s.fork_rate:.0f}/s")
    if _sum_cpu(s.procs, BROWSER) >= 10:
        bump(Workload.BROWSER, 0.7, "browser-cpu>=10")
    if _sum_cpu(s.procs, BATCH) >= 50 or (s.psi_cpu_some10 >= 20 and s.cpu_util_pct >= 70):
        bump(Workload.BATCH, 0.8 if _sum_cpu(s.procs, BATCH) >= 50 else 0.5, "batch-cpu/psi")
    if s.cpu_util_pct < 3 and max(scores.values()) == 0.0:
        bump(Workload.IDLE, 0.9, f"util={s.cpu_util_pct:.1f}%")
    elif max(scores.values()) == 0.0:
        bump(Workload.UI, 0.4, "interactive-default")

    best = max(TIE_ORDER, key=lambda w: (scores[w], -TIE_ORDER.index(w)))
    return _assign(best, scores[best], ev[best][:6], s)


def _assign(wl: Workload, score: float, evidence: list, s: Snapshot, hint_pids=frozenset()) -> Classification:
    """Map processes to BPF classes for the chosen workload."""
    a: dict = {}
    interactive = wl in (Workload.UI, Workload.BROWSER, Workload.GAMING, Workload.VIDEO,
                         Workload.CAMERA, Workload.GRAPHICS)
    for p in s.procs:
        if p.pid in hint_pids:
            a[p.pid] = Cls.MEDIA if wl in (Workload.CAMERA, Workload.VIDEO) else Cls.FG
        elif _m(p.comm, AUDIO):
            a[p.pid] = Cls.MEDIA
        elif _m(p.comm, SHELL) and wl != Workload.IDLE:
            a[p.pid] = Cls.FG
        elif wl == Workload.CAMERA and (({"v4l", "media"} & p.tags) or _m(p.comm, CAMERA)):
            a[p.pid] = Cls.MEDIA
        elif wl == Workload.VIDEO and (_m(p.comm, VIDEO) or ({"v4l", "dmabuf"} & p.tags)):
            a[p.pid] = Cls.MEDIA
        elif wl == Workload.GAMING and (_m(p.comm, GAME) or ("drm" in p.tags and p.cpu_pct >= 30)):
            a[p.pid] = Cls.FG
        elif wl == Workload.GRAPHICS and (_m(p.comm, GRAPHICS) or "drm" in p.tags and p.cpu_pct >= 10):
            a[p.pid] = Cls.FG
        elif wl == Workload.BROWSER and _m(p.comm, BROWSER):
            a[p.pid] = Cls.FG
        elif wl == Workload.AGENTIC and _m(p.comm, AGENT):
            a[p.pid] = Cls.FG
        elif interactive and (_m(p.comm, AGENT) or _m(p.comm, BATCH)):
            a[p.pid] = Cls.BG
    return Classification(wl, score, evidence, a)


class Debouncer:
    """Hysteresis: confirm over N ticks, hold at least min_dwell_s, fast-path strong launches."""

    def __init__(self, min_dwell_s=8.0, confirm_ticks=2, fast_score=0.9):
        self.min_dwell_s, self.confirm_ticks, self.fast_score = min_dwell_s, confirm_ticks, fast_score
        self.current = Workload.IDLE
        self._since = None
        self._cand = None
        self._cand_n = 0

    def update(self, c: Classification, now: float) -> Workload:
        if self._since is None:
            self._since = now
        if c.workload == self.current:
            self._cand, self._cand_n = None, 0
            return self.current
        if c.workload == self._cand:
            self._cand_n += 1
        else:
            self._cand, self._cand_n = c.workload, 1
        dwell_ok = (now - self._since) >= self.min_dwell_s
        fast = c.score >= self.fast_score and self.current in (Workload.IDLE, Workload.UI)
        if self._cand_n >= self.confirm_ticks and (dwell_ok or fast):
            self.current, self._since, self._cand, self._cand_n = c.workload, now, None, 0
        return self.current

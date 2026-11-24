"""On-device scheduler generation: an agent writes the BPF C, a pipeline decides if it may run.

    prompt ──> backend ──> extract C ──> static gate ──> clang/bpftool/cc ──> kernel verifier
                  ^                           |                |                (load, no attach)
                  └──── repair feedback ──────┴────────────────┘                      |
                                                                  canary (if possible) ┘
                                                                          |
                                      pending ──(operator: gen-approve, signs digests)──> approved
                                                                          |
              Verifier (signature + digests + approval) -> Lifecycle (canary, load, guard, rollback)

This is the Shirudo loop applied to schedulers: the model writes, deterministic tooling
checks, the kernel verifier proves memory safety, a person approves, and only a signed
record can be loaded. The model never touches the device except through that path.

Privacy: the prompt carries only numbers about the device (CPU count, kernel release,
power state, SLO thresholds, baseline parameters) and the contents of three repository
files. It never contains process names, paths, usernames or window titles. Use
`conductord gen --print-prompt` to see exactly what would be sent.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import genstatic
from .genbackends import Backend, GenError, extract_c
from .genbuild import Toolchain, write_file
from .genstore import GenStore, source_id
from .model import Params, Workload

# What each workload is trying to achieve, in scheduler terms. Deliberately qualitative:
# the numbers come from the baseline parameters and the model's judgement.
INTENTS = {
    "ui": "Interactive desktop/mobile UI. Minimise input-to-photon latency: foreground (FG) tasks "
          "must wake and run almost immediately and keep slices short; background (BG) work absorbs "
          "what is left with longer slices.",
    "browser": "Web browsing: bursty main/render threads and many short-lived helpers. Favour wake-up "
               "latency for FG, keep throughput reasonable for the many MEDIA/NORMAL helper threads.",
    "gaming": "Real-time game loop: minimise frame-time tail latency. FG (game, compositor) gets the "
              "shortest wake-up latency; MEDIA (audio) must never be delayed by more than ~1-2 ms; BG "
              "(shader compilers, launchers, agents) yields. Avoid migrations that cost cache warmth.",
    "video": "Video playback/transcode: periodic pipelines with a steady cadence. MEDIA tasks need "
             "bounded, predictable latency (dropped frames are the failure); prefer power efficiency "
             "(fewer wake-ups and context switches, longer slices for BG).",
    "camera": "Camera/ISP capture pipeline: periodic, deadline-like MEDIA work that must not stall "
              "(dropped frames), with the UI still responsive. Short MEDIA wake-up latency, bounded BG.",
    "graphics": "GPU-bound creative or benchmark workload: the CPU side feeds the GPU. FG submission "
                "threads need low latency; everything else is throughput.",
    "agentic": "Agentic/LLM tool workloads: many short process spawns plus heavy CPU bursts. Favour "
               "throughput and fairness; do not demote the agent itself; keep the foreground UI usable.",
    "batch": "Throughput batch work (builds, compression): maximise throughput with long slices and "
             "few context switches; interactive tasks must still stay responsive.",
}

CLASS_MEANING = {"CLS_NORMAL": 0, "CLS_FG": 1, "CLS_MEDIA": 2, "CLS_BG": 3}


def _system_prompt() -> str:
    helpers = ", ".join(genstatic.ALLOWED_BPF_HELPERS + genstatic.ALLOWED_SCX_KFUNCS)
    ops = ", ".join("." + o for o in genstatic.ALLOWED_OPS)
    return f"""You write a Linux sched_ext (BPF) CPU scheduler as ONE C source file, for an on-device scheduler governor.

A deterministic pipeline checks everything you write: a static gate, clang, the kernel BPF verifier, a canary run, and finally a person approves it before it can ever run. Violations are reported back to you with the exact error so you can repair them. Be conservative: a scheduler is on every task's critical path.

Hard rules:
1. Start from the reference scheduler below and keep its structure; change policy, not plumbing.
2. Begin with  #include "conductor_abi.bpf.h"  (it provides the maps, UEI, licence and helpers; never redefine them).
3. Define the ops with  SCX_OPS_DEFINE(gen_ops, ...)  and  .name = "conductor_gen". Allowed members: {ops}. Do NOT set .flags or .timeout_ms (the loader owns them).
4. Telemetry contract: call conductor_mark_enq(p, cls, slice) whenever you queue a task, conductor_note_running(p) from .running, UEI_RECORD(uei, ei) from .exit, and use conductor_move_to_local(dsq) instead of scx_bpf_dsq_move_to_local.
5. Never starve any task: every runnable task must eventually run whatever its class. A single shared vtime DSQ (as in the reference) guarantees this; if you add queues, prove every one is drained.
6. Only these bpf helpers / kfuncs may appear: {helpers}. Plain C, struct field reads such as p->scx.dsq_vtime, p->tgid, p->nr_cpus_allowed, and the SCX_*/CLS_*/ST_* constants are fine.
7. Forbidden: inline asm, extern, SEC(), __attribute__, defining your own maps, function-pointer casts, integer-to-pointer casts, #pragma, token pasting (##), any #include other than the ABI header.
8. There are no runtime knobs: write the numbers into the source. Keep slices within 0.5 ms .. 50 ms and arithmetic free of overflow and division by zero.
9. Reply with exactly one fenced ```c block containing the complete file. A short comment at the top explaining the policy is welcome. No other prose."""


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def collect_ctx(workload: Workload, platform: str, state: str, params: Params, *,
                release: str, arch: str, profiles: Optional[dict] = None) -> dict:
    """Numbers about the device and the target. No names, no paths, nothing user-derived."""
    st = {}
    canary_p99 = None
    if profiles:
        st = profiles.get("platforms", {}).get(platform, {}).get("states", {}).get(state, {})
        canary_p99 = profiles.get("canary_p99_us")
    return {
        "workload": workload.value, "platform": platform, "power_state": state,
        "arch": arch, "kernel_release": release, "nr_cpus": os.cpu_count() or 1,
        "perf_cap": st.get("perf_cap"), "slice_scale": st.get("slice_scale"),
        "canary_p99_limit_us": canary_p99, "watchdog_ms": params.timeout_ms,
        "baseline": {"slice_ns": params.slice_ns, "credit_ns": params.credit_ns,
                     "charge_pct": params.charge_pct, "cpuperf": params.perf},
    }


def build_prompt(ctx: dict, repo_root: str, feedback: Optional[dict] = None) -> tuple:
    """(system, user). `feedback` = {"stage", "errors", "source"} from the previous attempt."""
    bpf = os.path.join(repo_root, "bpf")
    intent = INTENTS.get(ctx["workload"], "General-purpose scheduling.")
    parts = [
        f"## Target\n\nWorkload: {ctx['workload']}\n\nIntent: {intent}",
        "## Device and constraints (numbers only)\n\n```json\n" + json.dumps(ctx, indent=1, sort_keys=True) + "\n```\n\n"
        "Classes (index into the baseline arrays): " + ", ".join(f"{k}={v}" for k, v in CLASS_MEANING.items()) +
        ". The governor assigns a class per process; read it with conductor_class_of(p). "
        "`baseline` holds the per-class values the hand-written template would use for this workload and "
        "power state: slice (ns), sleeper credit (ns), vtime charge (percent per ns run; lower = more CPU "
        "share), and a cpuperf hint (0..1024, 0 = leave alone). Improve on them only with a reason you state "
        "in a comment. The watchdog ejects a scheduler that leaves a runnable task undispatched for "
        f"{ctx.get('watchdog_ms')} ms.",
        "## conductor_abi.bpf.h\n\n```c\n" + _read(os.path.join(bpf, "conductor_abi.bpf.h")) + "```",
        "## conductor.h\n\n```c\n" + _read(os.path.join(bpf, "conductor.h")) + "```",
        "## Reference scheduler (scx_conductor.bpf.c)\n\n```c\n" + _read(os.path.join(bpf, "scx_conductor.bpf.c")) + "```",
    ]
    if feedback:
        errs = feedback["errors"]
        if len(errs) > 3500:
            errs = errs[:1200] + "\n...[truncated]...\n" + errs[-2200:]
        parts.append(f"## Your previous attempt failed at: {feedback['stage']}\n\n```\n{errs}\n```\n\n"
                     "Previous source:\n\n```c\n" + (feedback.get("source") or "(none)") + "```\n\n"
                     "Fix exactly these problems and return the complete corrected file.")
    else:
        parts.append("Write the scheduler now.")
    return _system_prompt(), "\n\n".join(parts)


@dataclass
class GenOutcome:
    ok: bool
    gen_id: Optional[str] = None
    status: str = ""             # pending | approved | rejected | failed | duplicate
    stage: str = ""              # where it stopped if not ok
    detail: str = ""
    attempts: int = 0
    log: list = field(default_factory=list)


class Generator:
    def __init__(self, *, backend: Backend, toolchain: Toolchain, store: GenStore, repo_root: str,
                 audit, verify_fn: Callable, canary_fn: Optional[Callable] = None,
                 approval: str = "ask", priv_key: Optional[str] = None, max_attempts: int = 3,
                 profiles: Optional[dict] = None, clock=time.time):
        if approval not in ("ask", "auto"):
            raise ValueError("approval must be 'ask' or 'auto'")
        if approval == "auto" and not priv_key:
            raise ValueError("approval=auto needs a signing key")
        self.backend, self.tc, self.store, self.repo_root = backend, toolchain, store, repo_root
        self.audit, self.verify_fn, self.canary_fn = audit, verify_fn, canary_fn
        self.approval, self.priv_key, self.max_attempts = approval, priv_key, max(1, max_attempts)
        self.profiles, self.clock = profiles, clock
        self.template_path = os.path.join(repo_root, "bpf", "scx_conductor.bpf.c")

    # ------------------------------------------------------------------ pipeline
    def preview(self, workload: Workload, platform: str, state: str, params: Params) -> tuple:
        ctx = collect_ctx(workload, platform, state, params, release=self.tc.release,
                          arch=self.tc.machine, profiles=self.profiles)
        return build_prompt(ctx, self.repo_root)

    def generate(self, workload: Workload, platform: str, state: str, params: Params) -> GenOutcome:
        ctx = collect_ctx(workload, platform, state, params, release=self.tc.release,
                          arch=self.tc.machine, profiles=self.profiles)
        out = GenOutcome(False)
        ident = {"workload": workload.value, "platform": platform, "power_state": state}
        self.audit.record("gen-start", backend=self.backend.describe(), **ident)
        feedback: Optional[dict] = None

        def fail(stage: str, detail: str, src: Optional[str], attempt: int) -> None:
            nonlocal feedback
            out.stage, out.detail, out.attempts = stage, detail[-600:], attempt
            out.log.append({"attempt": attempt, "stage": stage, "detail": detail[-300:]})
            self.audit.record("gen-attempt", attempt=attempt, stage=stage, ok=False,
                              detail=detail[-300:], **ident)
            feedback = {"stage": stage, "errors": detail, "source": src}

        for attempt in range(1, self.max_attempts + 1):
            system, user = build_prompt(ctx, self.repo_root, feedback)
            try:
                raw = self.backend.complete(system, user, {"params": params, **ctx})
            except GenError as e:
                fail("backend", str(e), None, attempt)
                break                                   # network/auth problems are not repairable here
            try:
                src = extract_c(raw)
            except GenError as e:
                fail("format", f"{e}. Reply with exactly one fenced ```c block.", None, attempt)
                continue

            problems = genstatic.check(src)
            if problems:
                fail("static-gate", "\n".join(problems), src, attempt)
                continue

            gid = source_id(src)
            prior = self.store.meta(gid)
            if prior and prior.get("status") in ("pending", "approved") and \
                    (prior.get("workload"), prior.get("platform"), prior.get("arch"),
                     prior.get("kernel_release")) == (workload.value, platform, self.tc.machine, self.tc.release):
                out.ok, out.gen_id, out.status, out.attempts = True, gid, "duplicate", attempt
                self.audit.record("gen-ready", gen_id=gid, status=prior["status"], duplicate=True, **ident)
                return out
            d = self.store.begin(gid)
            build = self.tc.build(src, d)
            if not build.ok:
                self._mark_failed(gid, ident, build.stage, build.log, attempt)
                fail(f"build:{build.stage}", build.log, src, attempt)
                continue
            vok, vlog = self.verify_fn(d)
            if not vok:
                self._mark_failed(gid, ident, "verifier", vlog, attempt)
                fail("kernel-verifier", vlog, src, attempt)
                continue

            cres = {"ok": None, "detail": "not run"}
            if self.canary_fn:
                cok, cdetail = self.canary_fn(d, params)
                cres = {"ok": cok, "detail": cdetail if isinstance(cdetail, (str, dict)) else str(cdetail)}
            status = "rejected" if cres["ok"] is False else "pending"
            meta = {"id": gid, "status": status, **ident, "arch": self.tc.machine,
                    "kernel_release": self.tc.release, "created": int(self.clock()),
                    "backend": self.backend.describe(), "attempts": attempt, "gate": "pass",
                    "build": {"files": build.files, "tools": build.tools},
                    "verify": {"ok": True, "detail": (vlog or "accepted")[-300:]},
                    "canary": cres, "params": params.to_dict()}
            if status == "rejected":
                meta["reject_reason"] = "canary failed"
            self.store.write_meta(gid, meta)
            self.store.write_review(gid, self.template_path)
            self.audit.record("gen-built", gen_id=gid, files=build.files, attempts=attempt, **ident)
            self.audit.record("gen-verified", gen_id=gid, canary=cres, **ident)
            if status == "pending" and self.approval == "auto":
                self.store.approve(gid, self.priv_key, approver="auto")
                status = "approved"
                self.audit.record("gen-approved", gen_id=gid, by="auto", **ident)
            self.audit.record("gen-ready", gen_id=gid, status=status, **ident)
            self.store.prune_failed()
            out.ok, out.gen_id, out.status, out.attempts = status != "rejected", gid, status, attempt
            if status == "rejected":
                out.stage, out.detail = "canary", str(cres["detail"])[-300:]
            return out

        self.audit.record("gen-failed", stage=out.stage, detail=out.detail, attempts=out.attempts, **ident)
        return out

    def _mark_failed(self, gid: str, ident: dict, stage: str, log: str, attempt: int) -> None:
        self.store.write_meta(gid, {"id": gid, "status": "failed", **ident, "arch": self.tc.machine,
                                    "kernel_release": self.tc.release, "created": int(self.clock()),
                                    "stage": stage, "attempts": attempt})
        try:
            write_file(os.path.join(self.store.dir(gid), "build.log"), log)
        except OSError:
            pass


class GenManager:
    """Runs generation in the background, one at a time, with cooldowns.

    The governor calls request() from its tick; request() never blocks. A workload that
    already has a pending/approved scheduler for this kernel is not regenerated, a recent
    rejection or failure is respected for `cooldown_s`, and only one generation runs at once.
    """

    def __init__(self, generator: Generator, *, cooldown_s: float = 900.0,
                 rejected_cooldown_s: float = 6 * 3600.0, clock=time.monotonic,
                 wall=time.time, sync: bool = False):
        self.gen, self.cooldown_s, self.rejected_cooldown_s = generator, cooldown_s, rejected_cooldown_s
        self.clock, self.wall, self.sync = clock, wall, sync
        self._lock = threading.Lock()
        self._busy: Optional[tuple] = None
        self._cool: dict = {}
        self._thread: Optional[threading.Thread] = None
        self.last: Optional[dict] = None

    def _key(self, workload: Workload, platform: str) -> tuple:
        return (workload.value, platform, self.gen.tc.machine, self.gen.tc.release)

    def request(self, workload: Workload, platform: str, state: str, params: Params) -> str:
        key = self._key(workload, platform)
        store = self.gen.store
        for m in store.list():
            if (m.get("workload"), m.get("platform"), m.get("arch"), m.get("kernel_release")) == key:
                if m.get("status") in ("pending", "approved"):
                    return "exists"
                if m.get("status") == "rejected" and self.wall() < m.get("created", 0) + self.rejected_cooldown_s:
                    return "cooldown"
        with self._lock:
            if self._busy is not None:
                return "busy"
            until = self._cool.get(key)
            if until is not None and self.clock() < until:
                return "cooldown"
            self._busy = key
        if self.sync:
            self._run(key, workload, platform, state, params)
        else:
            self._thread = threading.Thread(target=self._run, args=(key, workload, platform, state, params),
                                            name="conductor-gen", daemon=True)
            self._thread.start()
        return "started"

    def _run(self, key, workload, platform, state, params) -> None:
        try:
            res = self.gen.generate(workload, platform, state, params)
            self.last = {"workload": workload.value, "ok": res.ok, "gen_id": res.gen_id,
                         "status": res.status, "stage": res.stage, "detail": res.detail,
                         "attempts": res.attempts, "at": int(self.wall())}
            if not res.ok:
                with self._lock:
                    self._cool[key] = self.clock() + self.cooldown_s
        except Exception as e:  # noqa: BLE001 - the worker must never take the daemon down
            self.last = {"workload": workload.value, "ok": False, "stage": "exception",
                         "detail": f"{type(e).__name__}: {e}", "at": int(self.wall())}
            try:
                self.gen.audit.record("gen-failed", stage="exception", detail=str(e)[-300:])
            except Exception:  # noqa: BLE001
                pass
            with self._lock:
                self._cool[key] = self.clock() + self.cooldown_s
        finally:
            with self._lock:
                self._busy = None

    def join(self, timeout: float = 30.0) -> None:
        if self._thread:
            self._thread.join(timeout)

    def status(self) -> dict:
        with self._lock:
            return {"busy": self._busy is not None, "last": self.last, "cooling": len(self._cool)}

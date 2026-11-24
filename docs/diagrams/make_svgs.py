#!/usr/bin/env python3
"""Generates the architecture diagrams as plain SVG (no external deps).

    python3 docs/diagrams/make_svgs.py        # rewrites docs/diagrams/*.svg
    rsvg-convert -w 1400 docs/diagrams/architecture.svg -o /tmp/a.png   # optional preview

Everything is drawn from a few helpers so layout changes stay one-line edits.
"""
import os
from xml.sax.saxutils import escape

OUT = os.path.dirname(os.path.abspath(__file__))

PAL = {
    "sig":  ("#F4F4F5", "#71717A"),
    "gov":  ("#EAF2FB", "#2B6CB0"),
    "ker":  ("#E9F6EC", "#2F855A"),
    "frg":  ("#FDF3E1", "#B7791F"),
    "saf":  ("#FDECEC", "#C53030"),
    "plat": ("#F1ECFA", "#6B46C1"),
    "wht":  ("#FFFFFF", "#4A5568"),
}


class Svg:
    def __init__(self, w, h, title):
        self.w, self.h, self.title = w, h, title
        self.p = []

    def box(self, x, y, w, h, title, lines=(), kind="wht", dashed=False, tsize=13, lsize=11, r=8, align="middle",
            bold_lines=(), colors=None):
        fill, stroke = PAL[kind]
        colors = colors or {}
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        self.p.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="1.5"{dash}/>')
        tx = x + w / 2 if align == "middle" else x + 12
        anchor = "middle" if align == "middle" else "start"
        ty = y + 8 + tsize
        if not title and lines:                      # title-less box: centre the lines vertically
            block = len(lines) * (lsize + 4)
            ty = y + (h - block) / 2 - 2
        if title:
            self.p.append(f'<text x="{tx}" y="{ty}" font-size="{tsize}" font-weight="700" text-anchor="{anchor}" fill="#1a202c">{escape(title)}</text>')
            ty += 4
        for i, ln in enumerate(lines):
            ty += lsize + 4
            wgt = ' font-weight="700"' if i in bold_lines else ""
            col = colors.get(i, "#2d3748")
            self.p.append(f'<text x="{tx}" y="{ty}" font-size="{lsize}" text-anchor="{anchor}" fill="{col}"{wgt}>{escape(ln)}</text>')

    def text(self, x, y, s, size=11, anchor="middle", color="#2d3748", bold=False, italic=False):
        extra = (' font-weight="700"' if bold else "") + (' font-style="italic"' if italic else "")
        self.p.append(f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}" fill="{color}"{extra}>{escape(s)}</text>')

    def arrow(self, x1, y1, x2, y2, label="", dashed=False, color="#4A5568", lx=None, ly=None, lanchor="middle", both=False):
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        start = ' marker-start="url(#ah)"' if both else ""
        self.p.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1.6"{dash} marker-end="url(#ah)"{start}/>')
        if label:
            lx = (x1 + x2) / 2 if lx is None else lx
            ly = (y1 + y2) / 2 - 5 if ly is None else ly
            self.text(lx, ly, label, 10, lanchor, color="#4A5568", italic=True)

    def poly(self, pts, label="", dashed=False, color="#4A5568", lx=None, ly=None):
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        s = " ".join(f"{a},{b}" for a, b in pts)
        self.p.append(f'<polyline points="{s}" fill="none" stroke="{color}" stroke-width="1.6"{dash} marker-end="url(#ah)"/>')
        if label:
            self.text(lx, ly, label, 10, "middle", color="#4A5568", italic=True)

    def save(self, name):
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" '
                f'font-family="Helvetica, Arial, sans-serif" role="img" aria-label="{escape(self.title)}">'
                '<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                '<path d="M0,0 L10,5 L0,10 z" fill="#4A5568"/></marker></defs>'
                f'<rect width="{self.w}" height="{self.h}" fill="#ffffff"/>'
                f'<text x="{self.w/2}" y="22" font-size="16" font-weight="700" text-anchor="middle" fill="#1a202c">{escape(self.title)}</text>')
        with open(os.path.join(OUT, name), "w") as f:
            f.write(head + "".join(self.p) + "</svg>\n")


# ------------------------------------------------------------------ 1. architecture
def architecture():
    s = Svg(1100, 930, "scx-conductor architecture: observe → classify → specialise → sign/verify → load/unload sched_ext")

    # signals
    for x, w, t, ls in [
        (30, 205, "/proc per-process", ["CPU %, comm, fd targets:", "/dev/dri video* media* snd"]),
        (248, 170, "Pressure & rates", ["PSI /proc/pressure/cpu", "fork rate, CPU util"]),
        (431, 185, "Power / thermal / GPU", ["AC / battery %, thermal", "gpu_busy_percent (DRM)"]),
        (629, 161, "Platform hints", ["hint.json · ctl hint", "top-app · HMI · shell"]),
    ]:
        s.box(x, 38, w, 70, t, ls, "sig")
        s.arrow(x + w / 2, 108, x + w / 2, 128)

    # governor
    s.box(30, 130, 760, 340, "", [], "gov", r=10)
    s.text(410, 150, "conductord — governor (userspace Python, stdlib only; no BPF bindings)", 13, bold=True, color="#1a365d")
    s.box(50, 170, 160, 62, "Collector", ["/proc /sys PSI hints", "fd tags: drm v4l snd"], "wht")
    s.box(240, 170, 160, 62, "Classifier", ["rules + hysteresis →", "workload + per-pid class"], "wht")
    s.box(430, 170, 160, 62, "Policy", ["workload × platform", "× power state → Params"], "wht")
    s.box(620, 170, 150, 62, "Forge", ["bounded Params →", "Ed25519 manifest"], "wht")
    s.arrow(210, 201, 240, 201)
    s.arrow(400, 201, 430, 201)
    s.arrow(590, 201, 620, 201)

    s.box(620, 262, 150, 98, "Verifier", ["fail-closed:", "signature · BPF digest", "platform · arch · TTL", "param bounds"], "wht", lsize=10)
    s.arrow(695, 232, 695, 262)
    s.box(50, 262, 160, 62, "Control socket", ["status · hint · hold", "release · rollback"], "wht")
    s.arrow(210, 280, 330, 233, "hint / hold", lx=262, ly=244)

    s.box(380, 262, 215, 112, "Lifecycle", ["1 canary (SWITCH_PARTIAL)", "2 load + sync classes", "3 guard: PSI + latency SLO", "4 rollback / quarantine"], "wht")
    s.arrow(620, 301, 595, 301)
    s.box(50, 350, 295, 96, "Audit log", ["hash-chained JSONL: every decision,", "load, unload, rejection, rollback;", "head extended into a TPM PCR", "when a TPM is present"], "wht", lsize=10)
    s.arrow(380, 345, 346, 380, dashed=True)

    # forge host
    s.box(830, 38, 240, 292, "Forge host / CI (offline)", [
        "holds the private key", "", "reviewed BPF object digest", "", "pre-signs manifests for", "iot + automotive", "",
        "approved_only platforms:", "manifests never signed", "on the device"], "frg")
    s.arrow(830, 301, 772, 301, "approved", dashed=True, lx=800, ly=293)

    # loader
    s.box(30, 500, 560, 92, "conductor_load  (C + libbpf, one process per loaded scheduler)", [
        "writes rodata knobs BEFORE load → verifier sees constants (a genuinely different program per profile)",
        "owns the struct_ops link · stdin: set/clr <tgid> <class> · stdout: stats JSON",
        "exit == unload: closing the link returns every task to the fair class"], "gov", lsize=10, tsize=12)
    s.arrow(487, 374, 487, 500, "spawn + line protocol", lx=497, ly=440, lanchor="start")

    # safety
    s.box(620, 500, 450, 92, "Fail-safe by construction", [
        "kernel watchdog (timeout_ms) ejects a stalled scheduler",
        "canary runs in SCHED_EXT-only mode before any full load",
        "failed / ejected / regressing manifests are quarantined",
        "idle or unknown ⇒ stock scheduler, nothing custom loaded"], "saf", lsize=10, tsize=12, align="start")

    # kernel
    s.box(30, 630, 1040, 150, "", [], "ker", r=10)
    s.text(550, 650, "Linux kernel — sched_ext (CONFIG_SCHED_CLASS_EXT)", 13, bold=True, color="#1c4532")
    s.box(50, 664, 500, 100, "scx_conductor  (BPF struct_ops)", [
        "select_cpu · enqueue · dispatch · running · stopping · enable",
        "one shared vtime DSQ  ⇒ starvation-free by construction",
        "per-class slice, sleeper credit, vtime charge, cpuperf hint",
        "per-class enqueue→run latency histogram (the SLO signal)"], "wht", lsize=10, tsize=12)
    s.box(575, 664, 230, 100, "BPF maps", ["tgid_class  (governor writes)", "stats, lat_hist  (per-CPU)", "task_ctx  (task storage)"], "wht", lsize=10, tsize=12)
    s.box(830, 664, 220, 100, "Fallbacks", ["fair class (stock CFS/EEVDF)", "SysRq-S · watchdog · error", "⇒ revert all tasks"], "wht", lsize=10, tsize=12)
    s.arrow(200, 592, 200, 664, "load · map updates", lx=208, ly=616, lanchor="start")
    s.arrow(420, 664, 420, 592, "stats · exit info", lx=428, ly=616, lanchor="start")

    # platforms
    s.text(550, 812, "Deployment profiles (profiles/profiles.json) — same code on x86_64 and arm64, CO-RE BPF", 13, bold=True, color="#44337a")
    cols = [
        ("laptop", ["generate on device", "canary · 5 s watchdog", "AC / battery / thermal caps"]),
        ("mobile", ["generate on device", "canary · 3 s watchdog", "tighter battery + thermal"]),
        ("iot", ["approved-only manifests", "no canary · 8 s watchdog", "long slices, low perf caps"]),
        ("automotive", ["approved-only + allow-list", "ui video camera graphics", "1 s watchdog · canary"]),
        ("vm (QEMU)", ["CI target: q35 + virt", "x86_64 and arm64", "same canary + e2e tests"]),
    ]
    for i, (t, ls) in enumerate(cols):
        s.box(30 + i * 210, 826, 196, 84, t, ls, "plat", lsize=10, tsize=12)
    s.save("architecture.svg")


# ------------------------------------------------------------------ 2. Shirudo → scx-conductor mapping
def mapping():
    s = Svg(1100, 560, "Shirudo concepts and their scx-conductor counterparts")
    s.box(30, 40, 480, 30, "Shirudo (OpenAI + Cisco): eBPF 'shields' for running Linux systems", [], "frg", tsize=12)
    s.box(590, 40, 480, 30, "scx-conductor: sched_ext schedulers for running workloads", [], "gov", tsize=12)
    rows = [
        ("Shield: small eBPF program attached to a live system", "Scheduler: struct_ops program specialised per workload"),
        ("Agents generate and validate shields per vulnerability", "LLM backend writes the scheduler C on the device; gates + build + kernel verifier"),
        ("Test the shield against exploit and real workloads", "Canary in SWITCH_PARTIAL mode: latency probe, starvation, telemetry"),
        ("Monitor impact before enforcing", "Partial mode: only opted-in tasks are scheduled by it"),
        ("Operator approves what is deployed", "gen-approve signs the digests; approved_only platforms never generate"),
        ("Signed and verified before loading; kernel verifier", "Ed25519 manifest pins obj/loader/source/approval digests; kernel verifier"),
        ("Live protection, no restart, removable", "Hot load / unload; closing the link ⇒ stock scheduler"),
        ("TPM-backed record of load / removal", "Hash-chained audit log, head extended into a TPM PCR"),
        ("Same operation can be exploit or legitimate request", "Same CPU can be a game or a build: classify, don't guess"),
    ]
    y = 90
    for a, b in rows:
        s.box(30, y, 480, 38, "", [a], "frg", lsize=11)
        s.box(590, y, 480, 38, "", [b], "gov", lsize=11)
        s.arrow(512, y + 19, 588, y + 19)
        y += 48
    s.text(550, 538, "Added because scheduling differs from security: kernel watchdog ejects stalls on its own; PSI + latency SLO guard triggers rollback.", 11, italic=True)
    s.save("shirudo-mapping.svg")


# ------------------------------------------------------------------ 3. lifecycle state machine
def lifecycle():
    s = Svg(1100, 610, "Scheduler lifecycle (per manifest): only VERIFY → CANARY/LOADING ever loads code, and VERIFY fails closed")
    RED = "#C53030"
    s.box(30, 210, 140, 70, "STOCK", ["fair class", "nothing custom loaded"], "ker")
    s.box(290, 210, 160, 70, "VERIFY", ["signature · BPF digest", "platform · arch · TTL · bounds"], "gov", lsize=10)
    s.box(540, 90, 170, 76, "CANARY", ["partial mode + probe", "p99 under budget?", "✕ fail → quarantine"], "gov", colors={2: RED}, lsize=10)
    s.box(540, 330, 170, 76, "LOADING", ["full struct_ops load", "sysfs enabled + ops name", "✕ fail → quarantine"], "gov", colors={2: RED}, lsize=10)
    s.box(850, 210, 170, 70, "ACTIVE", ["guard ticks: PSI,", "latency SLO, liveness"], "ker")
    s.box(500, 485, 280, 62, "QUARANTINE", ["manifest blocked 300 s (slo.quarantine_s);", "system keeps running on STOCK"], "saf", lsize=10)

    s.arrow(170, 245, 290, 245)
    s.text(230, 232, "workload changed", 10, italic=True)
    s.text(230, 264, "(confirmed + dwell)", 10, italic=True)
    s.poly([(450, 225), (495, 225), (495, 128), (540, 128)])
    s.text(488, 175, "canary required", 10, anchor="end", italic=True)
    s.poly([(450, 265), (495, 265), (495, 368), (540, 368)])
    s.text(488, 322, "no canary / already passed", 10, anchor="end", italic=True)
    s.arrow(625, 166, 625, 330)
    s.text(633, 252, "canary passed", 10, anchor="start", italic=True)
    s.poly([(710, 380), (790, 380), (790, 262), (850, 262)])
    s.text(798, 330, "loaded", 10, anchor="start", italic=True)
    s.poly([(935, 210), (935, 58), (370, 58), (370, 210)])
    s.text(652, 52, "workload or power state changed: unload old, verify new", 10, italic=True)
    s.poly([(980, 280), (980, 585), (100, 585), (100, 280)])
    s.text(540, 579, "workload idle / unknown: unload, back to STOCK", 10, italic=True)
    s.poly([(880, 280), (880, 516), (780, 516)])
    s.text(872, 440, "PSI / latency SLO rollback,", 10, anchor="end", italic=True)
    s.text(872, 454, "kernel watchdog eject,", 10, anchor="end", italic=True)
    s.text(872, 468, "loader died", 10, anchor="end", italic=True)
    s.save("lifecycle-states.svg")


# ------------------------------------------------------------------ 4. sequence: a game launches
def sequence():
    actors = ["App / user", "Collector +\nClassifier", "Policy + Forge", "Verifier", "Lifecycle", "conductor_load", "Kernel\nsched_ext"]
    W = 1200
    s = Svg(W, 770, "Sequence: game launches → scheduler generated, verified, canaried, loaded; game exits → unloaded")
    xs = [90 + i * 170 for i in range(len(actors))]
    for x, a in zip(xs, actors):
        l = a.split("\n")
        s.box(x - 65, 40, 130, 44, l[0], [l[1]] if len(l) > 1 else [], "gov", tsize=12, lsize=11)
        s.p.append(f'<line x1="{x}" y1="84" x2="{x}" y2="735" stroke="#A0AEC0" stroke-width="1" stroke-dasharray="4 4"/>')

    def msg(i, j, y, text, dashed=False):
        x1, x2 = xs[i], xs[j]
        s.arrow(x1, y, x2, y, "", dashed=dashed)
        s.text((x1 + x2) / 2, y - 5, text, 10, "middle", italic=True)

    y = 116
    seq = [
        (0, 1, "launch: comm=steam, drm fds", False),
        (1, 1, "classify + debounce", False),
        (1, 2, "workload = gaming", False),
        (2, 2, "params = f(workload, platform, power)", False),
        (2, 4, "signed manifest", False),
        (4, 3, "verify", False),
        (3, 4, "ok  (or reject, audited)", True),
        (4, 5, "canary: start --partial", False),
        (5, 6, "load struct_ops (partial)", False),
        (4, 4, "probe: wake p99 within budget", False),
        (4, 5, "stop  (link closed)", False),
        (4, 5, "start (full), rodata knobs", False),
        (5, 6, "load struct_ops", False),
        (4, 5, "set <tgid> FG/MEDIA/BG", False),
        (5, 6, "update tgid_class map", False),
        (4, 5, "stats every 5 ticks", True),
        (0, 1, "game exits, idle past dwell", False),
        (4, 5, "quit  (reason: stock)", False),
        (5, 6, "link closed: fair class", False),
    ]
    for k, (i, j, t, d) in enumerate(seq):
        if i == j:
            s.text(xs[i] + 12, y - 6, t, 10, "start", italic=True)
            y += 22
            continue
        msg(i, j, y, t, d)
        y += 34
    s.text(W / 2, 750, "audit log records: decision, canary-start/result, load, unload. Guard ticks watch PSI and the FG/MEDIA latency tail and roll back on regression.", 11, italic=True)
    s.save("sequence-switch.svg")


# ------------------------------------------------------------------ 5. on-device generation pipeline
def generation():
    s = Svg(1100, 580, "On-device generation: model writes the scheduler, gates and the kernel check it, an operator approves, a signed digest loads it")
    W, G, X0 = 184, 30, 30
    xs = [X0 + i * (W + G) for i in range(5)]
    H = 128
    R1, R2 = 52, 300
    row1 = [
        ("1 Context", ["numbers only: workload,", "platform, power state, arch,", "kernel, CPUs, limits, baseline", "+ 3 repo files as examples"], "sig"),
        ("2 Backend", ["anthropic API | local command", "| template (tests)", "writes ONE C source file", "one request in, one file out"], "frg"),
        ("3 Static gate", ["ASCII, <= 48 KB, 2 includes", "no asm / extern / SEC / ##", "kfunc + helper allowlists", "fixed ops table + name"], "gov"),
        ("4 Build", ["clang -target bpf -Wall", "ELF sections + 4 ABI maps", "bpftool skeleton", "cc -> gen_load (loader)"], "gov"),
        ("5 Kernel verifier", ["gen_load --verify-only:", "struct_ops loaded, NOT attached", "kernel proves memory safety", "and termination"], "ker"),
    ]
    for x, (t, ls, k) in zip(xs, row1):
        s.box(x, R1, W, H, t, ls, k, lsize=10.5)
    for i in range(4):
        s.arrow(xs[i] + W, R1 + H / 2, xs[i + 1], R1 + H / 2)

    # repair loop: gate / build / verifier errors go back to the model as text
    s.box(xs[1], 208, xs[3] + W - xs[1], 44, "", ["error text goes back to the model, up to 3 attempts (stored as 'failed' for debugging)"],
          "saf", lsize=10.5)
    s.arrow(xs[1] + 60, 208, xs[1] + 60, R1 + H, "repair", lx=xs[1] + 36, ly=190, lanchor="end")
    s.arrow(xs[2] + W / 2, R1 + H, xs[2] + W / 2, 208)
    s.arrow(xs[3] + W / 2, R1 + H, xs[3] + W / 2, 208)
    s.poly([(xs[4] + 26, R1 + H), (xs[4] + 26, 230), (xs[3] + W, 230)], dashed=True)

    row2 = [   # right to left
        (4, "6 Early canary", ["partial mode, probe + hogs", "only if no other sched_ext", "scheduler is attached", "fail -> rejected, not repaired"], "ker"),
        (3, "7 PENDING artifact", ["id = sha256(source)[:12]", "for one (workload, platform,", "arch, kernel release)", "never loadable as is"], "wht"),
        (2, "8 Operator approval", ["conductord gen-approve <id>", "human reads review.md and the", "diff vs the reference", "signs approval.json (digests)"], "frg"),
        (1, "9 Signed manifest", ["GenForge, template=scx_gen", "pins obj, loader, source,", "approval digests, kernel", "release, ops name, TTL"], "gov"),
        (0, "10 Verify, canary, load", ["same fail-closed Verifier", "canary + starvation + telemetry", "load, sysfs ops == conductor_gen", "any failure: template scheduler"], "gov"),
    ]
    for idx, t, ls, k in row2:
        s.box(xs[idx], R2, W, H, t, ls, k, lsize=10.5)
    s.arrow(xs[4] + W / 2, R1 + H, xs[4] + W / 2, R2, "", lx=0)
    s.text(xs[4] + W / 2 + 8, 264, "built + verified", 10, anchor="start", italic=True)
    for idx in (4, 3, 2, 1):
        s.arrow(xs[idx], R2 + H / 2, xs[idx - 1] + W, R2 + H / 2)

    y = 462
    s.box(30, y, 330, 96, "Who can stop it", ["the kernel: verifier, and the watchdog that", "ejects a stalled scheduler by itself", "a human: nothing loads without step 8", "the Verifier: any changed byte, arch or kernel"], "wht", lsize=10.5)
    s.box(385, y, 330, 96, "What goes off the device", ["only the step 1 prompt, and only for the", "anthropic backend (gen --print-prompt shows it)", "no process names, paths, users or logs", "command / template backends stay local"], "wht", lsize=10.5)
    s.box(740, y, 330, 96, "Not proven by any of this", ["that the scheduler is fair or fast: the verifier", "checks safety, not quality. That is what the", "canary, the runtime guard and the operator", "are for. Untuned, unmeasured."], "saf", lsize=10.5)
    s.save("generation-pipeline.svg")


if __name__ == "__main__":
    architecture(); mapping(); lifecycle(); sequence(); generation()
    print("wrote", ", ".join(sorted(f for f in os.listdir(OUT) if f.endswith(".svg"))))

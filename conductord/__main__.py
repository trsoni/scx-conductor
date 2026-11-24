"""CLI: python3 -m conductord <run|ctl|keygen|forge-approved|audit-verify|doctor|gen|gen-list|gen-show|gen-approve|gen-reject>"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import signal

from . import audit as audit_mod
from .canary import make_canary, make_dir_canary
from .daemon import ControlServer, GenSupport, Governor, ctl_request
from .forge import ApprovedStore, Forge, Verifier, keygen
from .genbackends import GenError, make_backend, AnthropicBackend
from .genbuild import Toolchain
from .generator import GenManager, Generator
from .genstore import GenForge, GenStore
from .host import FakeHost, LoaderHost, read_sched_ext, verify_only
from .lifecycle import Lifecycle
from .model import Workload
from .policy import build_params, detect_platform, load_profiles
from .signals import Collector

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
D = {
    "profiles": os.path.join(ROOT, "profiles", "profiles.json"),
    "bpf_obj": os.path.join(ROOT, "build", "scx_conductor.bpf.o"),
    "loader": os.path.join(ROOT, "build", "conductor_load"),
    "state": "/var/lib/conductor",
    "sock": "/run/conductor/ctl.sock",
}
TEMPLATE_SRC = os.path.join(ROOT, "bpf", "scx_conductor.bpf.c")
POWER_STATES = ["ac", "battery", "low_battery", "thermal"]


# ------------------------------------------------------------------ generation wiring
def _gen_dir(a) -> str:
    return getattr(a, "gen_dir", None) or os.path.join(a.state, "generated")


def _toolchain(a) -> Toolchain:
    return Toolchain(ROOT, a.state, scx_inc=getattr(a, "scx_inc", None),
                     drop_user=getattr(a, "gen_sandbox_user", None))


def _backend(a):
    return make_backend(getattr(a, "gen_backend", "none"), cmd=getattr(a, "gen_cmd", None),
                        model=getattr(a, "gen_model", None), template_path=TEMPLATE_SRC)


def _gen_stack(a, profiles, platform, audit, priv, dry_run: bool, lock=None):
    """(store, GenForge, manager | None). Raises GenError for a bad backend choice."""
    store = GenStore(_gen_dir(a))
    gforge = GenForge(store, priv)
    backend = _backend(a)
    if backend is None:
        return store, gforge, None
    pcfg = profiles["platforms"][platform]
    tc = _toolchain(a)
    if dry_run:
        verify = lambda d: (True, "dry-run: not loaded into a kernel")        # noqa: E731
        canary = None
    else:
        verify = lambda d: verify_only(os.path.join(d, "gen_load"))           # noqa: E731
        canary = None
        if pcfg.get("canary"):
            canary = make_dir_canary(
                pcfg.get("canary_s", 3), profiles.get("canary_p99_us", 50000),
                lambda d: LoaderHost(os.path.join(d, "gen_load"), knobs=False), read_sched_ext, lock=lock)
    approval = getattr(a, "gen_approval", "ask")
    gen = Generator(backend=backend, toolchain=tc, store=store, repo_root=ROOT, audit=audit,
                    verify_fn=verify, canary_fn=canary, approval=approval,
                    priv_key=priv if approval == "auto" else None,
                    max_attempts=getattr(a, "gen_max_attempts", 3), profiles=profiles)
    return store, gforge, GenManager(gen)


# ------------------------------------------------------------------ commands
def cmd_run(a):
    profiles = load_profiles(a.profiles)
    platform = detect_platform(override=a.platform)
    os.makedirs(a.state, exist_ok=True)
    priv, pub = os.path.join(a.state, "dev-signing.key"), os.path.join(a.state, "trusted.pub")
    if a.pubkey:
        pub = a.pubkey
    elif a.dev_self_sign and not os.path.exists(priv):
        keygen(priv, pub)
    audit = audit_mod.AuditLog(os.path.join(a.state, "audit.jsonl"))
    have_key = a.dev_self_sign and os.path.exists(priv)
    forge = Forge(profiles, a.bpf_obj, priv if have_key else None)
    verifier = Verifier(pub, a.bpf_obj)
    template_host = FakeHost() if a.dry_run else LoaderHost(a.loader)
    pcfg = profiles["platforms"][platform]
    canary = None
    if pcfg.get("canary") and not a.dry_run:
        canary = make_canary(pcfg.get("canary_s", 3), profiles.get("canary_p99_us", 50000))

    lock = threading.RLock()
    gen = host_factory = None
    if pcfg.get("allow_device_generation") and not pcfg.get("approved_only") and have_key:
        if a.gen_approval == "auto":
            print("WARNING: --gen-approval auto: model-written schedulers are signed and loaded "
                  "WITHOUT operator review. Lab use only.", file=sys.stderr)
            audit.record("gen-auto-approval-enabled")
        try:
            store, gforge, mgr = _gen_stack(a, profiles, platform, audit, priv, a.dry_run, lock)
        except GenError as e:
            print(f"conductord: {e}", file=sys.stderr)
            return 2
        gen = GenSupport(store, gforge, os.uname().machine, os.uname().release, manager=mgr,
                         on_demand=bool(a.gen_on_demand and mgr))
        gen_fake = FakeHost()
        gen_fake.state_ops = "conductor_gen"

        def host_factory(m):
            if not m.is_generated:
                return template_host
            if a.dry_run:
                return gen_fake
            return LoaderHost(os.path.join(m.artifact_dir, "gen_load"), knobs=False)

    lc = Lifecycle(template_host, verifier, audit, profiles, platform, canary_fn=canary,
                   host_factory=host_factory, lock=lock)
    store = ApprovedStore(a.approved_dir) if a.approved_dir else None
    gov = Governor(profiles, platform, Collector(hint_path=a.hint_file), forge, lc, audit, store,
                   min_switch_s=a.min_switch, gen=gen)
    audit.record("daemon-start", platform=platform, dry_run=a.dry_run, arch=os.uname().machine,
                 kernel=os.uname().release, gen=bool(gen), gen_backend=a.gen_backend,
                 gen_on_demand=bool(gen and gen.on_demand))
    srv = ControlServer(gov, a.sock) if a.sock else None
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    if srv:
        srv.start()
    try:
        gov.run(a.interval, a.duration, stop)
    finally:
        audit.record("daemon-stop")
        if srv:
            srv.stop()
    return 0


def cmd_ctl(a):
    req = {"cmd": a.action}
    if a.action in ("hint", "hold", "gen"):
        req["workload"] = a.arg
    if a.action == "hint":
        req["pids"] = [int(x) for x in a.pids]
        req["ttl"] = a.ttl
    print(json.dumps(ctl_request(a.sock, req)))
    return 0


def cmd_keygen(a):
    keygen(a.priv, a.pub)
    print(f"wrote {a.priv} (keep offline) and {a.pub} (ship to devices)")
    return 0


def cmd_forge_approved(a):
    """Pre-generate + sign every manifest for a platform (run on the forge host / CI)."""
    profiles = load_profiles(a.profiles)
    forge = Forge(profiles, a.bpf_obj, a.priv, ttl_s=a.ttl_days * 86400)
    store, n = ApprovedStore(a.out), 0
    for wl in Workload:
        for state in profiles["platforms"][a.platform]["states"]:
            m = forge.make(wl, a.platform, state, arch=a.arch)
            if m:
                store.save(m)
                n += 1
    print(f"signed {n} manifests for {a.platform}/{a.arch} -> {a.out}")
    return 0


def cmd_audit_verify(a):
    ok, n, err = audit_mod.verify_chain(a.path)
    print(json.dumps({"ok": ok, "entries": n, "error": err}))
    return 0 if ok else 1


def cmd_gen(a):
    """One-shot generation: write, check, build, kernel-verify, canary -> a pending artifact."""
    profiles = load_profiles(a.profiles)
    platform = detect_platform(override=a.platform)
    pcfg = profiles["platforms"][platform]
    if pcfg.get("approved_only") or not pcfg.get("allow_device_generation"):
        print(f"conductord: platform {platform!r} does not allow on-device generation "
              "(approved-only manifests)", file=sys.stderr)
        return 2
    wl = Workload(a.workload)
    params = build_params(profiles, wl, platform, a.power_state)
    if params is None:
        print(f"conductord: {wl.value} uses the stock scheduler; nothing to generate", file=sys.stderr)
        return 2
    os.makedirs(a.state, exist_ok=True)
    try:
        backend = _backend(a)
    except GenError as e:
        print(f"conductord: {e}", file=sys.stderr)
        return 2
    if backend is None and not a.print_prompt:
        print("conductord: choose a backend with --gen-backend {anthropic,command,template}", file=sys.stderr)
        return 2
    audit = audit_mod.AuditLog(os.path.join(a.state, "audit.jsonl"))
    priv = os.path.join(a.state, "dev-signing.key")
    store = GenStore(_gen_dir(a))
    tc = _toolchain(a)
    pcanary = pcfg.get("canary")
    canary = None
    if pcanary and not a.no_canary:
        canary = make_dir_canary(pcfg.get("canary_s", 3), profiles.get("canary_p99_us", 50000),
                                 lambda d: LoaderHost(os.path.join(d, "gen_load"), knobs=False),
                                 read_sched_ext)
    approval = a.gen_approval
    if approval == "auto" and not os.path.exists(priv):
        print(f"conductord: --gen-approval auto needs {priv} (run `conductord run --dev-self-sign` once)",
              file=sys.stderr)
        return 2
    gen = Generator(backend=backend or make_backend("template", template_path=TEMPLATE_SRC),
                    toolchain=tc, store=store, repo_root=ROOT, audit=audit,
                    verify_fn=lambda d: verify_only(os.path.join(d, "gen_load")), canary_fn=canary,
                    approval=approval, priv_key=priv if approval == "auto" else None,
                    max_attempts=a.gen_max_attempts, profiles=profiles)
    if a.print_prompt:
        system, user = gen.preview(wl, platform, a.power_state, params)
        print("=== SYSTEM ===\n" + system + "\n\n=== USER ===\n" + user)
        print(f"\n[{len(system) + len(user)} characters; this is everything a remote backend would receive]",
              file=sys.stderr)
        return 0
    res = gen.generate(wl, platform, a.power_state, params)
    print(json.dumps({"ok": res.ok, "id": res.gen_id, "status": res.status, "stage": res.stage,
                      "detail": res.detail, "attempts": res.attempts}, indent=1))
    if res.ok and res.status in ("pending", "duplicate"):
        print(f"\nReview:   conductord gen-show {res.gen_id}\nApprove:  conductord gen-approve {res.gen_id}",
              file=sys.stderr)
    return 0 if res.ok else 1


def cmd_gen_list(a):
    rows = GenStore(_gen_dir(a)).list(include_failed=a.all)
    if not rows:
        print("(no generated schedulers)")
        return 0
    print(f"{'ID':<14}{'STATUS':<10}{'WORKLOAD':<10}{'PLATFORM':<9}{'ARCH':<8}KERNEL")
    for m in rows:
        print(f"{m['id']:<14}{m.get('status', '?'):<10}{m.get('workload', ''):<10}"
              f"{m.get('platform', ''):<9}{m.get('arch', ''):<8}{m.get('kernel_release', '')}")
    return 0


def cmd_gen_show(a):
    store = GenStore(_gen_dir(a))
    m = store.meta(a.id)
    if not m:
        print(f"unknown artifact {a.id}", file=sys.stderr)
        return 1
    path = os.path.join(store.dir(a.id), "source.bpf.c" if a.source else "review.md")
    try:
        with open(path) as f:
            sys.stdout.write(f.read())
    except OSError:
        print(json.dumps(m, indent=1))
    return 0


def _signing_key(a) -> str:
    return a.priv or os.path.join(a.state, "dev-signing.key")


def cmd_gen_approve(a):
    store = GenStore(_gen_dir(a))
    m = store.meta(a.id)
    if not m:
        print(f"unknown artifact {a.id}", file=sys.stderr)
        return 1
    key = _signing_key(a)
    if not os.path.exists(key):
        print(f"conductord: signing key {key} not found (run `conductord run --dev-self-sign` once, "
              "or pass --priv)", file=sys.stderr)
        return 2
    print(f"artifact {m['id']}  workload={m.get('workload')} platform={m.get('platform')} "
          f"kernel={m.get('kernel_release')}\n  status:  {m.get('status')}\n  verify:  {m.get('verify')}\n"
          f"  canary:  {m.get('canary')}\n  review:  {os.path.join(store.dir(a.id), 'review.md')}\n"
          f"  source:  {os.path.join(store.dir(a.id), 'source.bpf.c')}")
    if not a.yes:
        typed = input("\nYou are about to let this model-written scheduler run on every task on this "
                      f"machine.\nType the id ({a.id}) to approve: ").strip()
        if typed != a.id:
            print("not approved")
            return 1
    try:
        store.approve(a.id, key, approver=os.environ.get("SUDO_USER") or os.environ.get("USER") or "operator")
    except (ValueError, OSError) as e:
        print(f"conductord: {e}", file=sys.stderr)
        return 1
    audit_mod.AuditLog(os.path.join(a.state, "audit.jsonl")).record(
        "gen-approved", gen_id=a.id, by=os.environ.get("SUDO_USER") or os.environ.get("USER") or "operator")
    print(f"approved {a.id}. A running daemon will pick it up on its next tick.")
    return 0


def cmd_gen_reject(a):
    store = GenStore(_gen_dir(a))
    try:
        store.reject(a.id, a.reason or "")
    except ValueError as e:
        print(f"conductord: {e}", file=sys.stderr)
        return 1
    audit_mod.AuditLog(os.path.join(a.state, "audit.jsonl")).record("gen-rejected", gen_id=a.id, reason=a.reason or "")
    print(f"rejected {a.id}")
    return 0


def cmd_doctor(a):
    """Can this machine build, verify and load generated schedulers?"""
    rows = _toolchain(a).check()
    rows.append(("running as root", os.geteuid() == 0, "needed to load BPF and attach sched_ext"))
    rows.append(("state dir writable", os.access(a.state, os.W_OK) if os.path.isdir(a.state)
                 else os.access(os.path.dirname(a.state.rstrip("/")) or "/", os.W_OK), a.state))
    try:
        platform = detect_platform(override=getattr(a, "platform", None))
        rows.append((f"platform = {platform}", True, "set it explicitly with --platform or /etc/conductor/platform"))
    except Exception as e:  # noqa: BLE001
        rows.append(("platform", False, str(e)))
    b = AnthropicBackend()
    rows.append(("anthropic API key", b.have_key(),
                 f"model {b.model}; env ANTHROPIC_API_KEY or {b._key_file} (optional: other backends work)"))
    import shutil as _sh
    rows.append(("claude CLI (command backend)", _sh.which("claude"), "optional: --gen-backend command --gen-cmd 'claude -p'"))
    optional = {"prlimit", "anthropic API key", "claude CLI (command backend)"}
    bad = [r for r in rows if not r[1] and r[0] not in optional]
    width = max(len(r[0]) for r in rows)
    for name, ok, detail in rows:
        mark = "ok  " if ok else ("--  " if name in optional else "FAIL")
        print(f"[{mark}] {name:<{width}}  {detail if detail else ''}")
    print("\nREADY to build, verify and load generated schedulers." if not bad else
          "\nNOT READY: fix the FAIL rows above (see docs/LAPTOP.md).")
    return 0 if not bad else 1


# ------------------------------------------------------------------ argument parsing
def _add_gen_flags(p, run: bool = False):
    p.add_argument("--gen-dir", help="where generated schedulers live (default <state>/generated)")
    p.add_argument("--gen-backend", choices=["none", "anthropic", "command", "template"],
                   default="none" if run else "none",
                   help="who writes new schedulers: anthropic API, a local command, or the deterministic template")
    p.add_argument("--gen-cmd", help="command for --gen-backend command (prompt on stdin, C on stdout), e.g. 'claude -p'")
    p.add_argument("--gen-model", help="model for --gen-backend anthropic (default $CONDUCTOR_GEN_MODEL or claude-sonnet-5-5)")
    p.add_argument("--gen-approval", choices=["ask", "auto"], default="ask",
                   help="ask: an operator must run gen-approve (default). auto: lab only, no human review")
    p.add_argument("--gen-max-attempts", type=int, default=3)
    p.add_argument("--gen-sandbox-user", help="run clang as this unprivileged user (root only)")
    p.add_argument("--scx-inc", help="directory containing scx/common.bpf.h (default: SCX_INC, third_party/scx-include, system paths)")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="conductord")
    sub = ap.add_subparsers(dest="c", required=True)

    r = sub.add_parser("run")
    r.add_argument("--platform", choices=["laptop", "mobile", "iot", "automotive", "vm"])
    r.add_argument("--profiles", default=D["profiles"])
    r.add_argument("--bpf-obj", default=D["bpf_obj"])
    r.add_argument("--loader", default=D["loader"])
    r.add_argument("--state", default=D["state"])
    r.add_argument("--sock", default=D["sock"])
    r.add_argument("--pubkey")
    r.add_argument("--approved-dir")
    r.add_argument("--hint-file", default="/run/conductor/hint.json")
    r.add_argument("--dev-self-sign", action="store_true", help="dev/test only: sign with a local key")
    r.add_argument("--dry-run", action="store_true", help="no kernel interaction (FakeHost)")
    r.add_argument("--interval", type=float, default=1.0)
    r.add_argument("--duration", type=float)
    r.add_argument("--min-switch", type=float, default=8.0)
    r.add_argument("--gen-on-demand", action="store_true",
                   help="ask the backend for a scheduler when a workload has none (opt-in; may send the prompt off-device)")
    _add_gen_flags(r, run=True)
    r.set_defaults(fn=cmd_run)

    c = sub.add_parser("ctl")
    c.add_argument("action", choices=["status", "hint", "hold", "release", "rollback", "gen"])
    c.add_argument("arg", nargs="?")
    c.add_argument("--pids", nargs="*", default=[])
    c.add_argument("--ttl", type=float, default=30)
    c.add_argument("--sock", default=D["sock"])
    c.set_defaults(fn=cmd_ctl)

    k = sub.add_parser("keygen")
    k.add_argument("--priv", required=True)
    k.add_argument("--pub", required=True)
    k.set_defaults(fn=cmd_keygen)

    f = sub.add_parser("forge-approved")
    f.add_argument("--platform", required=True)
    f.add_argument("--arch", default="any")
    f.add_argument("--priv", required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--ttl-days", type=int, default=365)
    f.add_argument("--profiles", default=D["profiles"])
    f.add_argument("--bpf-obj", default=D["bpf_obj"])
    f.set_defaults(fn=cmd_forge_approved)

    v = sub.add_parser("audit-verify")
    v.add_argument("path")
    v.set_defaults(fn=cmd_audit_verify)

    g = sub.add_parser("gen", help="write a scheduler for a workload on this device (one shot)")
    g.add_argument("--workload", required=True, choices=[w.value for w in Workload if w != Workload.IDLE])
    g.add_argument("--platform", choices=["laptop", "mobile", "vm"])
    g.add_argument("--power-state", default="ac", choices=POWER_STATES)
    g.add_argument("--profiles", default=D["profiles"])
    g.add_argument("--state", default=D["state"])
    g.add_argument("--print-prompt", action="store_true", help="show exactly what a backend would receive, then exit")
    g.add_argument("--no-canary", action="store_true", help="skip the early canary (the lifecycle still runs one at load)")
    _add_gen_flags(g)
    g.set_defaults(fn=cmd_gen)

    for name, fn, helptext in (("gen-list", cmd_gen_list, "list generated schedulers"),
                               ("gen-show", cmd_gen_show, "show a review sheet (or --source)"),
                               ("gen-approve", cmd_gen_approve, "operator approval: sign the digests so it can be loaded"),
                               ("gen-reject", cmd_gen_reject, "reject a generated scheduler")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--state", default=D["state"])
        s.add_argument("--gen-dir")
        if name == "gen-list":
            s.add_argument("--all", action="store_true", help="include failed attempts")
        else:
            s.add_argument("id")
        if name == "gen-show":
            s.add_argument("--source", action="store_true")
        if name == "gen-approve":
            s.add_argument("--yes", action="store_true", help="skip the typed confirmation")
            s.add_argument("--priv", help="signing key (default <state>/dev-signing.key)")
        if name == "gen-reject":
            s.add_argument("--reason", default="")
        s.set_defaults(fn=fn)

    d = sub.add_parser("doctor", help="check that this machine can build, verify and load generated schedulers")
    d.add_argument("--state", default=D["state"])
    d.add_argument("--platform", choices=["laptop", "mobile", "iot", "automotive", "vm"])
    d.add_argument("--scx-inc")
    d.set_defaults(fn=cmd_doctor)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

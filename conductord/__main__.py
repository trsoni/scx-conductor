"""CLI: python3 -m conductord <run|ctl|keygen|forge-approved|audit-verify|print-manifest>"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import signal

from . import audit as audit_mod
from .canary import make_canary
from .daemon import ControlServer, Governor, ctl_request
from .forge import ApprovedStore, Forge, Verifier, keygen
from .host import FakeHost, LoaderHost
from .lifecycle import Lifecycle
from .model import Workload
from .policy import detect_platform, load_profiles
from .signals import Collector

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
D = {
    "profiles": os.path.join(ROOT, "profiles", "profiles.json"),
    "bpf_obj": os.path.join(ROOT, "build", "scx_conductor.bpf.o"),
    "loader": os.path.join(ROOT, "build", "conductor_load"),
    "state": "/var/lib/conductor",
    "sock": "/run/conductor/ctl.sock",
}


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
    forge = Forge(profiles, a.bpf_obj, priv if (a.dev_self_sign and os.path.exists(priv)) else None)
    verifier = Verifier(pub, a.bpf_obj)
    host = FakeHost() if a.dry_run else LoaderHost(a.loader)
    pcfg = profiles["platforms"][platform]
    canary = None
    if pcfg.get("canary") and not a.dry_run:
        canary = make_canary(pcfg.get("canary_s", 3), profiles.get("canary_p99_us", 50000))
    lc = Lifecycle(host, verifier, audit, profiles, platform, canary_fn=canary)
    store = ApprovedStore(a.approved_dir) if a.approved_dir else None
    gov = Governor(profiles, platform, Collector(hint_path=a.hint_file), forge, lc, audit, store,
                   min_switch_s=a.min_switch)
    audit.record("daemon-start", platform=platform, dry_run=a.dry_run, arch=os.uname().machine,
                 kernel=os.uname().release)
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
    if a.action in ("hint", "hold"):
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
    r.set_defaults(fn=cmd_run)

    c = sub.add_parser("ctl")
    c.add_argument("action", choices=["status", "hint", "hold", "release", "rollback"])
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

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

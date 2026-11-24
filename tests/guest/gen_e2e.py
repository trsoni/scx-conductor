"""Stage: on-device generation against the real kernel.

Everything Shirudo does, with the deterministic `template` backend standing in for the model so the
run is reproducible (the model only changes who writes the C; every gate after that is the same):

  doctor -> gen (static gate, clang, bpftool, cc, kernel verifier via --verify-only, canary)
         -> pending artifact is NOT loadable -> operator approval -> governor loads it
         -> kernel reports ops "conductor_gen" -> switch to the template scheduler and back
         -> rollback -> stock scheduler.
Plus the negative paths that do not need a model: source rejected by the static gate, and an
artifact tampered with after approval.
"""
import json, os, shutil, signal, subprocess, sys, tempfile
from tests.guest._common import *       # noqa
from conductord.audit import verify_chain
from conductord.daemon import ctl_request

state = tempfile.mkdtemp(prefix="cgen-")
sock = os.path.join(state, "ctl.sock")
env = dict(os.environ, PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1")
env.setdefault("CONDUCTOR_BUILD", BUILD)


def cli(*args, timeout=300, stdin=None):
    r = subprocess.run([sys.executable, "-m", "conductord", *args], env=env, cwd=ROOT, input=stdin,
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def gen_json(out):
    start = out.find("{")
    return json.loads(out[start:out.rindex("}") + 1]) if start >= 0 else {}


# ---- 0. can this machine do it at all?
rc, out, err = cli("doctor", "--state", state, "--platform", "vm")
print(out + err)
if not check("doctor: toolchain ready (clang, bpftool, libbpf, scx headers)", rc == 0, out[-300:]):
    finish("gen_e2e")

# ---- 1. generate with the template backend: real clang + bpftool + cc + kernel verifier + canary
rc, out, err = cli("keygen", "--priv", os.path.join(state, "dev-signing.key"),
                   "--pub", os.path.join(state, "trusted.pub"))
check("signing key created", rc == 0, err)

rc, out, err = cli("gen", "--workload", "gaming", "--platform", "vm", "--state", state,
                   "--gen-backend", "template")
res = gen_json(out)
check("gen gaming: pipeline succeeded", rc == 0 and res.get("ok"), out + err)
check("gen gaming: artifact is pending (never self-approved)", res.get("status") == "pending", res)
gid = res.get("id")
adir = os.path.join(state, "generated", gid or "none")
for f in ("source.bpf.c", "sched.bpf.o", "gen_load", "review.md", "meta.json"):
    check(f"artifact has {f}", os.path.exists(os.path.join(adir, f)))
with open(os.path.join(adir, "meta.json")) as f:
    meta = json.load(f)
check("meta: kernel verifier accepted it", (meta.get("verify") or {}).get("ok") is True, meta.get("verify"))
canary = meta.get("canary") or {}
check("meta: early canary ran (or was explicitly skipped, never silently absent)",
      canary.get("ok") in (True, None), canary)
x = sx()
check("generation left no scheduler attached", x["state"] in ("disabled", None), x)

rc, out, err = cli("gen-list", "--state", state)
check("gen-list shows the pending artifact", gid in out and "pending" in out, out)

# ---- 2. a pending artifact must never be loaded
gov_args = [sys.executable, "-m", "conductord", "run", "--platform", "vm", "--dev-self-sign", "--state", state,
            "--sock", sock, "--bpf-obj", BPF_OBJ, "--loader", LOADER, "--interval", "0.5", "--min-switch", "2",
            "--duration", "300"]
gov = subprocess.Popen(gov_args, env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def st():
    try:
        return ctl_request(sock, {"cmd": "status"})
    except OSError:
        return {}


def wait_active(pred, timeout):
    return wait_for(lambda: (lambda s: s if pred(s.get("active")) else None)(st()), timeout, 0.5)


check("governor control socket up", wait_for(lambda: os.path.exists(sock), 20) is not None)
ctl_request(sock, {"cmd": "hold", "workload": "gaming"})
s = wait_active(lambda a: bool(a) and a.endswith("gaming@vm/ac"), 60)
check("unapproved artifact is ignored: the reference gaming scheduler loads", s is not None
      and not s["active"].startswith("gen:"), st())
x = sx()
check("kernel shows the reference scheduler 'conductor'", x["state"] == "enabled" and x["ops"] == "conductor", x)

# ---- 3. operator approval, then the running governor picks it up
rc, out, err = cli("gen-approve", "--state", state, "--yes", gid)
check("gen-approve (operator) signs the digests", rc == 0, out + err)
ctl_request(sock, {"cmd": "hold", "workload": "camera"})                 # force a switch so the choice is re-evaluated
wait_active(lambda a: a == "camera@vm/ac", 30)
ctl_request(sock, {"cmd": "hold", "workload": "gaming"})
s = wait_active(lambda a: bool(a) and a.startswith(f"gen:{gid}/gaming@vm/"), 90)   # includes the canary
check("approved artifact is loaded for gaming", s is not None, st())
x = sx()
check("kernel shows the GENERATED scheduler 'conductor_gen' enabled", x["state"] == "enabled"
      and x["ops"] == "conductor_gen", x)
stats = ctl_request(sock, {"cmd": "status"})
check("status reports the generation block", "gen" in stats, list(stats))

# ---- 4. switching away unloads it; only one scheduler at a time
ctl_request(sock, {"cmd": "hold", "workload": "camera"})
s = wait_active(lambda a: a == "camera@vm/ac", 30)
check("hold camera -> generated scheduler replaced by the template one", s is not None, st())
x = sx()
check("kernel shows exactly 'conductor' again", x["state"] == "enabled" and x["ops"] == "conductor", x)

ctl_request(sock, {"cmd": "hold", "workload": "gaming"})
s = wait_active(lambda a: bool(a) and a.startswith("gen:"), 60)
check("hold gaming again -> generated scheduler reloaded", s is not None, st())

ctl_request(sock, {"cmd": "rollback"})
s = wait_active(lambda a: a is None, 15)
check("rollback -> stock scheduler", s is not None, st())
check("kernel back to disabled", wait_for(lambda: sx()["state"] in ("disabled", None), 5) is not None, sx())

# ---- 5. tamper with the approved binary: it must not load again
ctl_request(sock, {"cmd": "release"})
with open(os.path.join(adir, "gen_load"), "ab") as f:
    f.write(b"\0tampered")
ctl_request(sock, {"cmd": "hold", "workload": "gaming"})
s = wait_active(lambda a: bool(a) and a.endswith("gaming@vm/ac") and not a.startswith("gen:"), 90)
check("tampered artifact rejected: falls back to the reference scheduler", s is not None, st())
x = sx()
check("kernel runs the reference scheduler, not the tampered one", x["ops"] == "conductor", x)

gov.send_signal(signal.SIGTERM)
try:
    gov.wait(30)
except subprocess.TimeoutExpired:
    gov.kill(); gov.wait()
check("governor shut down", gov.returncode is not None)
check("kernel left on stock scheduler", wait_for(lambda: sx()["state"] in ("disabled", None), 5) is not None, sx())

ok, n, err = verify_chain(os.path.join(state, "audit.jsonl"))
check("audit hash chain verifies", ok, err)
with open(os.path.join(state, "audit.jsonl")) as f:
    rows = [json.loads(l) for l in f]
events = [r["event"] for r in rows]
for ev in ("gen-approved", "canary-result", "load", "unload", "gen-unusable"):
    check(f"audit contains '{ev}'", ev in events, events[-30:])
check("a 'load' event names the generated artifact",
      any(r["event"] == "load" and r["data"].get("gen_id") == gid for r in rows))
check("no ejection or governor error", not ({"ejected", "governor-error"} & set(events)))

# ---- 6. static gate rejects a hostile 'model' output before anything is compiled
bad = os.path.join(state, "evil.c")
with open(os.path.join(adir, "source.bpf.c")) as f:
    src = f.read()
with open(bad, "w") as f:
    f.write("```c\n" + src.replace("static u64 vtime_now;",
                                   'static u64 vtime_now;\nstatic void evil(void){ asm volatile("r0 = 0" ::: "r0"); }', 1)
            + "```\n")
rc, out, err = cli("gen", "--workload", "video", "--platform", "vm", "--state", state, "--gen-backend", "command",
                   "--gen-cmd", f"cat {bad}", "--gen-max-attempts", "1")
res = gen_json(out)
check("hostile source (inline asm) is refused", rc != 0 and res.get("ok") is False, out + err)
check("refused at the static gate, not later", res.get("stage") == "static-gate", res)
check("nothing was built or stored for it", not [m for m in os.listdir(os.path.join(state, "generated"))
                                                 if m != gid and os.path.exists(
                                                     os.path.join(state, "generated", m, "gen_load"))])

shutil.rmtree(state, ignore_errors=True)
finish("gen_e2e")

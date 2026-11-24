"""Stage: the full governor against the real kernel scheduler.

Pinned phases are deterministic (hold/rollback); the last phase checks genuine
classification: a synthetic 'steam' process must cause a gaming scheduler to
load, and its exit must lead to it being replaced/unloaded again.
"""
import json, os, signal, subprocess, sys, tempfile, time
from tests.guest._common import *       # noqa
from conductord.audit import verify_chain
from conductord.daemon import ctl_request

state = tempfile.mkdtemp(prefix="cstate-")
sock = os.path.join(state, "ctl.sock")
env = dict(os.environ, PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1")
gov = subprocess.Popen([sys.executable, "-m", "conductord", "run", "--platform", "vm",
                        "--dev-self-sign", "--state", state, "--sock", sock,
                        "--bpf-obj", BPF_OBJ, "--loader", LOADER,
                        "--interval", "0.5", "--min-switch", "2", "--duration", "240"],
                       env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def st():
    try:
        return ctl_request(sock, {"cmd": "status"})
    except OSError:
        return {}


def wait_active(pred, timeout):
    return wait_for(lambda: (lambda s: s if pred(s.get("active")) else None)(st()), timeout, 0.5)


check("governor control socket up", wait_for(lambda: os.path.exists(sock), 20) is not None)

ctl_request(sock, {"cmd": "hold", "workload": "gaming"})
s = wait_active(lambda a: a == "gaming@vm/ac", 60)         # includes the canary
check("hold gaming -> gaming scheduler active", s is not None, st())
x = sx()
check("kernel shows conductor enabled", x["state"] == "enabled" and x["ops"] == "conductor", x)

ctl_request(sock, {"cmd": "hold", "workload": "camera"})
s = wait_active(lambda a: a == "camera@vm/ac", 30)
check("hold camera -> switched (old unloaded, new loaded)", s is not None, st())
x = sx()
check("still exactly one conductor scheduler", x["state"] == "enabled" and x["ops"] == "conductor", x)

ctl_request(sock, {"cmd": "rollback"})
s = wait_active(lambda a: a is None, 15)
check("rollback -> stock scheduler", s is not None, st())
check("kernel back to disabled", wait_for(lambda: sx()["state"] in ("disabled", None), 5) is not None, sx())

ctl_request(sock, {"cmd": "release"})
app = subprocess.Popen([sys.executable, os.path.join(ROOT, "tools", "workloads", "fake_app.py"),
                        "--comm", "steam", "--cpu", "40", "--duration", "60"])
s = wait_active(lambda a: bool(a) and a.startswith("gaming@"), 60)
check("synthetic game process -> gaming scheduler loaded by classification", s is not None, st())
app.kill(); app.wait()
s = wait_active(lambda a: a is None or a.startswith("ui@"), 60)
check("game exit -> gaming scheduler replaced/unloaded", s is not None, st())

gov.send_signal(signal.SIGTERM)
try:
    gov.wait(30)
except subprocess.TimeoutExpired:
    gov.kill(); gov.wait()
check("governor shut down", gov.returncode is not None)
check("kernel left on stock scheduler after shutdown", wait_for(lambda: sx()["state"] in ("disabled", None), 5) is not None, sx())

ok, n, err = verify_chain(os.path.join(state, "audit.jsonl"))
check("audit hash chain verifies", ok, err)
with open(os.path.join(state, "audit.jsonl")) as f:
    events = [json.loads(l)["event"] for l in f]
for ev in ("daemon-start", "decision", "canary-result", "load", "unload", "daemon-stop"):
    check(f"audit contains '{ev}'", ev in events, events[:30])
check("no loader load-failed/ejected events", not ({"load-failed", "ejected", "governor-error"} & set(events)),
      [e for e in events if e in ("load-failed", "ejected", "governor-error")])
finish("governor_e2e")

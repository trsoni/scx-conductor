import os, tempfile, json
from conductord.model import ProcInfo, Snapshot
from conductord.policy import load_profiles
from conductord.forge import Forge, Verifier, keygen
from conductord.audit import AuditLog

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROFILES = os.path.join(ROOT, "profiles", "profiles.json")


def profiles():
    return load_profiles(PROFILES)


def snap(procs=(), util=20.0, psi=0.0, forks=0.0, gpu=None, ac=True, bat=None, temp=None, hint=None):
    return Snapshot(ts=0, cpu_util_pct=util, psi_cpu_some10=psi, fork_rate=forks, gpu_busy_pct=gpu,
                    on_ac=ac, battery_pct=bat, thermal_c=temp, procs=list(procs), hint=hint)


def P(pid, comm, cpu=10.0, tags=()):
    return ProcInfo(pid, comm, cpu, frozenset(tags))


class Env:
    """Temp dir with a fake 'bpf object', dev keys, audit log; platform default 'vm'."""
    def __init__(self, platform="vm"):
        self.d = tempfile.mkdtemp(prefix="cond-test-")
        self.obj = os.path.join(self.d, "scx_conductor.bpf.o")
        with open(self.obj, "wb") as f:
            f.write(b"\x7fELF-fake-bpf-object")
        self.priv, self.pub = os.path.join(self.d, "k.pem"), os.path.join(self.d, "k.pub")
        keygen(self.priv, self.pub)
        self.profiles = profiles()
        self.platform = platform
        self.forge = Forge(self.profiles, self.obj, self.priv)
        self.verifier = Verifier(self.pub, self.obj)
        self.audit = AuditLog(os.path.join(self.d, "audit.jsonl"), use_tpm=False)

    def events(self):
        with open(self.audit.path) as f:
            return [json.loads(l)["event"] for l in f]

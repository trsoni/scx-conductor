"""Store for generated schedulers, the operator approval, and per-state manifests.

Layout (default /var/lib/conductor/generated):

  <id>/source.bpf.c      what the agent wrote (read-only copy)
  <id>/sched.bpf.o       compiled object (digest is signed)
  <id>/gen_load          loader built against that object (digest is signed)
  <id>/meta.json         who/what/why: workload, platform, kernel, backend, gate/verify/canary results
  <id>/review.md         human review sheet: results + diff against the reference scheduler
  <id>/approval.json     present only after `conductord gen-approve`: signed digests

<id> is the first 12 hex digits of sha256(source), so identical source maps to the same
artifact. An artifact is only usable for the (workload, platform, arch, kernel release)
it was generated, verified and approved for.

Status flow:  building -> pending -> approved           (operator ran gen-approve)
                      \\-> failed                        (gate / compile / verifier)
                       \\-> rejected                     (canary failed, or operator said no)

Shirudo parallel: "operator approval" is an explicit signed record here, and the signed
manifest that finally reaches the loader names the approval's digest, so a manifest for an
unapproved artifact cannot verify.
"""
from __future__ import annotations

import difflib
import json
import os
import shutil
import threading
import time
from typing import Optional

from .forge import Manifest, canonical, manifest_hash, sha256_file, sign_bytes, verify_bytes
from .model import Params, Workload

GEN_TEMPLATE = "scx_gen"
GEN_OPS_NAME = "conductor_gen"
KERNEL_MIN = "6.13"
ARTIFACTS = {"source": "source.bpf.c", "obj": "sched.bpf.o", "loader": "gen_load"}


def source_id(source: str) -> str:
    import hashlib
    return hashlib.sha256(source.encode()).hexdigest()[:12]


def _write_json(path: str, obj) -> None:
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _read_json(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def approval_digest(approval: dict) -> str:
    return manifest_hash({"body": approval["body"], "sig": approval["sig"]})


def check_artifact_dir(adir: str, body: dict, pub_key: str) -> tuple:
    """Verifier support: do the files on disk match the manifest, and is there a valid approval?

    Fail-closed; returns (ok, reason). Does not trust anything in the directory except
    by digest and by the signature on approval.json.
    """
    if not adir or not os.path.isdir(adir):
        return False, "generated artifact directory missing"
    want = {"source": body.get("source_sha256"), "obj": body.get("template_sha256"),
            "loader": body.get("loader_sha256")}
    for key, fname in ARTIFACTS.items():
        p = os.path.join(adir, fname)
        try:
            got = sha256_file(p)
        except OSError:
            return False, f"{fname} missing"
        if not want[key] or got != want[key]:
            return False, f"{fname} digest mismatch"
    ap = _read_json(os.path.join(adir, "approval.json"))
    if not ap or "body" not in ap or "sig" not in ap:
        return False, "no operator approval"
    if not verify_bytes(pub_key, canonical(ap["body"]), ap["sig"]):
        return False, "approval signature invalid"
    ab = ap["body"]
    if (ab.get("source_sha256"), ab.get("obj_sha256"), ab.get("loader_sha256")) != \
            (want["source"], want["obj"], want["loader"]):
        return False, "approval does not match artifact digests"
    if approval_digest(ap) != body.get("approval_sha256"):
        return False, "approval digest mismatch"
    if (ab.get("arch"), ab.get("kernel_release")) != (body.get("arch"), body.get("kernel_release")):
        return False, "approval is for a different arch/kernel"
    return True, "ok"


class GenStore:
    def __init__(self, root: str, clock=time.time):
        self.root, self.clock = root, clock
        self._lock = threading.Lock()

    # ------------------------------------------------------------ paths / meta
    def dir(self, gid: str) -> str:
        if not gid or not all(c in "0123456789abcdef" for c in gid):
            raise ValueError(f"bad artifact id {gid!r}")
        return os.path.join(self.root, gid)

    def exists(self, gid: str) -> bool:
        return os.path.isdir(self.dir(gid))

    def meta(self, gid: str) -> Optional[dict]:
        return _read_json(os.path.join(self.dir(gid), "meta.json"))

    def write_meta(self, gid: str, meta: dict) -> None:
        os.makedirs(self.dir(gid), exist_ok=True)
        _write_json(os.path.join(self.dir(gid), "meta.json"), meta)

    def begin(self, gid: str) -> str:
        d = self.dir(gid)
        os.makedirs(d, exist_ok=True)
        return d

    def discard(self, gid: str) -> None:
        shutil.rmtree(self.dir(gid), ignore_errors=True)

    def list(self, include_failed: bool = False) -> list:
        out = []
        try:
            names = sorted(os.listdir(self.root))
        except OSError:
            return out
        for n in names:
            m = _read_json(os.path.join(self.root, n, "meta.json"))
            if not m:
                continue
            if m.get("status") in ("failed", "building") and not include_failed:
                continue
            out.append(m)
        out.sort(key=lambda m: m.get("created", 0), reverse=True)
        return out

    def prune_failed(self, keep: int = 10) -> int:
        failed = [m for m in self.list(include_failed=True) if m.get("status") in ("failed", "building")]
        n = 0
        for m in failed[keep:]:
            self.discard(m["id"])
            n += 1
        return n

    # ------------------------------------------------------------ review sheet
    def write_review(self, gid: str, template_path: Optional[str]) -> str:
        m = self.meta(gid) or {}
        d = self.dir(gid)
        with open(os.path.join(d, "source.bpf.c")) as f:
            src = f.read()
        diff = ""
        if template_path and os.path.isfile(template_path):
            with open(template_path) as f:
                ref = f.read()
            diff = "".join(difflib.unified_diff(ref.splitlines(True), src.splitlines(True),
                                                "reference/scx_conductor.bpf.c", f"generated/{gid}/source.bpf.c"))
        files = (m.get("build") or {}).get("files", {})
        lines = [
            f"# Generated scheduler {gid}", "",
            f"- workload: **{m.get('workload')}**   platform: **{m.get('platform')}**   power state: {m.get('power_state')}",
            f"- kernel: `{m.get('kernel_release')}`   arch: `{m.get('arch')}`",
            f"- backend: {json.dumps(m.get('backend'))}   attempts: {m.get('attempts')}",
            f"- static gate: {m.get('gate')}",
            f"- kernel verifier (load without attach): {json.dumps(m.get('verify'))}",
            f"- canary (partial mode): {json.dumps(m.get('canary'))}",
            f"- toolchain: {json.dumps((m.get('build') or {}).get('tools'))}",
            "", "## Digests", "",
            *[f"- {k}: `{v}`" for k, v in sorted(files.items())],
            "", "## What to check before approving", "",
            "- Does it dispatch EVERY runnable task eventually (no class can starve)?",
            "- Is the slice/charge/credit arithmetic bounded (no overflow, no unbounded loops)?",
            "- Does it call conductor_mark_enq() / conductor_note_running() so telemetry is honest?",
            "- Anything unexpected in the diff below (new maps, odd kfuncs, hard-coded CPU ids)?",
            "", "## Diff against the reference scheduler", "", "```diff", diff or "(no reference available)", "```", "",
            f"Approve:  `conductord gen-approve {gid}`      Reject:  `conductord gen-reject {gid} --reason ...`", ""]
        p = os.path.join(d, "review.md")
        with open(p, "w") as f:
            f.write("\n".join(lines))
        return p

    # ------------------------------------------------------------ approve / reject
    def approve(self, gid: str, priv_key: str, approver: str = "operator") -> dict:
        with self._lock:
            m = self.meta(gid)
            if not m:
                raise ValueError(f"unknown artifact {gid}")
            if m.get("status") == "approved":
                return m
            if m.get("status") != "pending":
                raise ValueError(f"{gid} is {m.get('status')}, only pending artifacts can be approved")
            if not (m.get("verify") or {}).get("ok"):
                raise ValueError("kernel verifier did not accept this artifact; refusing to approve")
            if (m.get("canary") or {}).get("ok") is False:
                raise ValueError("canary failed for this artifact; refusing to approve")
            d = self.dir(gid)
            want = (m.get("build") or {}).get("files", {})
            got = {k: sha256_file(os.path.join(d, fn)) for k, fn in ARTIFACTS.items()}
            if got != want:
                raise ValueError("artifact files changed since they were built (tamper or corruption)")
            body = {"schema": 1, "id": gid, "source_sha256": got["source"], "obj_sha256": got["obj"],
                    "loader_sha256": got["loader"], "arch": m["arch"], "kernel_release": m["kernel_release"],
                    "workload": m["workload"], "platform": m["platform"],
                    "approved_by": approver, "approved_at": int(self.clock())}
            _write_json(os.path.join(d, "approval.json"),
                        {"body": body, "sig": sign_bytes(priv_key, canonical(body))})
            m["status"], m["approved_at"], m["approved_by"] = "approved", body["approved_at"], approver
            self.write_meta(gid, m)
            return m

    def reject(self, gid: str, reason: str = "") -> dict:
        with self._lock:
            m = self.meta(gid)
            if not m:
                raise ValueError(f"unknown artifact {gid}")
            try:
                os.unlink(os.path.join(self.dir(gid), "approval.json"))
            except OSError:
                pass
            m["status"], m["reject_reason"] = "rejected", reason
            self.write_meta(gid, m)
            return m

    def approval(self, gid: str) -> Optional[dict]:
        return _read_json(os.path.join(self.dir(gid), "approval.json"))

    # ------------------------------------------------------------ lookup
    def lookup(self, workload: str, platform: str, arch: str, release: str,
               statuses: tuple = ("approved",)) -> Optional[str]:
        best = None
        for m in self.list():
            if m.get("status") in statuses and (m.get("workload"), m.get("platform"),
                                                m.get("arch"), m.get("kernel_release")) == \
                    (workload, platform, arch, release):
                if best is None or m.get("created", 0) > best.get("created", 0):
                    best = m
        return best["id"] if best else None


class GenForge:
    """Mints the signed, per-power-state manifest for an *approved* generated scheduler.

    Like forge.Forge, results are cached for half the TTL: `created` is inside the signed
    body, so minting on every tick would change the manifest hash and hot-reload an
    identical scheduler once per second.
    """

    def __init__(self, store: GenStore, priv_key: str, clock=time.time, ttl_s: int = 24 * 3600):
        self.store, self.priv_key, self.clock, self.ttl_s = store, priv_key, clock, ttl_s
        self._cache: dict = {}

    def make(self, gid: str, workload: Workload, platform: str, state: str,
             params: Params) -> Optional[Manifest]:
        m = self.store.meta(gid)
        ap = self.store.approval(gid)
        if not m or not ap or m.get("status") != "approved":
            return None
        key = (gid, workload.value, platform, state)
        hit = self._cache.get(key)
        if hit is not None and self.clock() < hit.body["created"] + self.ttl_s // 2:
            return hit
        d = self.store.dir(gid)
        files = {k: sha256_file(os.path.join(d, fn)) for k, fn in ARTIFACTS.items()}
        body = {
            "schema": 1, "template": GEN_TEMPLATE, "template_sha256": files["obj"],
            "gen_id": gid, "source_sha256": files["source"], "loader_sha256": files["loader"],
            "approval_sha256": approval_digest(ap), "ops_name": GEN_OPS_NAME,
            "name": f"gen:{gid}/{workload.value}@{platform}/{state}",
            "workload": workload.value, "platform": platform, "power_state": state,
            "arch": m["arch"], "kernel_release": m["kernel_release"], "kernel_min": KERNEL_MIN,
            "created": int(self.clock()), "ttl_s": self.ttl_s, "params": params.to_dict(),
        }
        man = Manifest(body, sign_bytes(self.priv_key, canonical(body)), artifact_dir=d)
        self._cache[key] = man
        return man

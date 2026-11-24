"""Forge: turns policy output into a *signed manifest*; Verifier gates every load.

Shirudo parallel: "shields are cryptographically signed and verified before
loading". Here the signed artefact is (reviewed BPF object digest + bounded
parameter vector + platform/kernel constraints + TTL). The device only needs the
public key; the private key lives on the forge host / CI (or, in dev mode,
locally).

Uses the `openssl` CLI (Ed25519, OpenSSL >= 3.0) so there is no Python crypto
dependency on minimal images.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform as _platform
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

from .model import Params, Workload
from .policy import build_params, validate_params

TEMPLATE = "scx_conductor"
GEN_TEMPLATE = "scx_gen"          # manifests for schedulers written on the device (genstore.py)
GEN_OPS_NAME = "conductor_gen"
KERNEL_MIN = "6.13"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_hash(body: dict) -> str:
    return hashlib.sha256(canonical(body)).hexdigest()


@dataclass
class Manifest:
    body: dict
    sig_b64: Optional[str] = None
    # Where a generated scheduler's files live. NOT part of the signed body or the JSON:
    # the verifier checks the files in this directory against digests that are signed.
    artifact_dir: Optional[str] = None

    @property
    def is_generated(self) -> bool:
        return self.body.get("template") == GEN_TEMPLATE

    @property
    def ops_name(self) -> str:
        return self.body.get("ops_name", "conductor")

    @property
    def hash(self) -> str:
        return manifest_hash(self.body)

    @property
    def name(self) -> str:
        return self.body["name"]

    @property
    def params(self) -> Params:
        return Params.from_dict(self.body["params"])

    def to_json(self) -> str:
        return json.dumps({"body": self.body, "sig": self.sig_b64}, sort_keys=True, indent=1)

    @staticmethod
    def from_json(txt: str) -> "Manifest":
        d = json.loads(txt)
        return Manifest(d["body"], d.get("sig"))


# ---------------- keys / signatures (openssl) ----------------
def keygen(priv_path: str, pub_path: str) -> None:
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", priv_path],
                   check=True, capture_output=True)
    os.chmod(priv_path, 0o600)
    subprocess.run(["openssl", "pkey", "-in", priv_path, "-pubout", "-out", pub_path],
                   check=True, capture_output=True)


def _with_tmp(data: bytes):
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(data)
    f.close()
    return f.name


def sign_bytes(priv_path: str, data: bytes) -> str:
    inp, out = _with_tmp(data), tempfile.mktemp()
    try:
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", priv_path, "-rawin",
                        "-in", inp, "-out", out], check=True, capture_output=True)
        with open(out, "rb") as f:
            return base64.b64encode(f.read()).decode()
    finally:
        for p in (inp, out):
            if os.path.exists(p):
                os.unlink(p)


def verify_bytes(pub_path: str, data: bytes, sig_b64: str) -> bool:
    inp = _with_tmp(data)
    sig = _with_tmp(base64.b64decode(sig_b64))
    try:
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub_path,
                            "-rawin", "-in", inp, "-sigfile", sig], capture_output=True)
        return r.returncode == 0
    finally:
        os.unlink(inp)
        os.unlink(sig)


# ---------------- forge ----------------
class Forge:
    def __init__(self, profiles: dict, bpf_obj: str, priv_key: Optional[str] = None,
                 clock=time.time, ttl_s: int = 24 * 3600):
        self.profiles, self.bpf_obj, self.priv_key = profiles, bpf_obj, priv_key
        self.clock, self.ttl_s = clock, ttl_s
        self._digest = None
        self._cache: dict = {}

    def template_digest(self) -> str:
        if self._digest is None:
            self._digest = sha256_file(self.bpf_obj)
        return self._digest

    def make(self, workload: Workload, platform: str, state: str,
             arch: Optional[str] = None) -> Optional[Manifest]:
        """Deterministic per (workload, platform, state, arch) for half the TTL.

        The creation timestamp is part of the signed body, so without this cache
        every governor tick would mint a manifest with a new hash and the
        lifecycle would hot-reload an identical scheduler once per second (and
        spawn an openssl process per tick to sign it).
        """
        p = build_params(self.profiles, workload, platform, state)
        if p is None:
            return None
        key = (workload.value, platform, state, arch or _platform.machine())
        hit = self._cache.get(key)
        if hit is not None and self.clock() < hit.body["created"] + self.ttl_s // 2:
            return hit
        body = {
            "schema": 1, "template": TEMPLATE, "template_sha256": self.template_digest(),
            "name": f"{workload.value}@{platform}/{state}",
            "workload": workload.value, "platform": platform, "power_state": state,
            "arch": arch or _platform.machine(), "kernel_min": KERNEL_MIN,
            "created": int(self.clock()), "ttl_s": self.ttl_s,
            "params": p.to_dict(),
        }
        m = Manifest(body)
        if self.priv_key:
            m.sig_b64 = sign_bytes(self.priv_key, canonical(body))
        self._cache[key] = m
        return m


class ApprovedStore:
    """approved_only platforms (iot, automotive): never generate on-device, only
    load pre-signed manifests shipped with the image."""

    def __init__(self, directory: str):
        self.dir = directory

    def find(self, name: str) -> Optional[Manifest]:
        p = os.path.join(self.dir, name.replace("/", "__").replace("@", "_at_") + ".json")
        try:
            with open(p) as f:
                return Manifest.from_json(f.read())
        except OSError:
            return None

    def save(self, m: Manifest) -> str:
        os.makedirs(self.dir, exist_ok=True)
        p = os.path.join(self.dir, m.name.replace("/", "__").replace("@", "_at_") + ".json")
        with open(p, "w") as f:
            f.write(m.to_json())
        return p


# ---------------- verifier ----------------
class Verifier:
    def __init__(self, pub_key: str, bpf_obj: str, clock=time.time, max_skew_s: int = 300,
                 release: Optional[str] = None):
        self.pub_key, self.bpf_obj, self.clock, self.max_skew_s = pub_key, bpf_obj, clock, max_skew_s
        self.release = release or _platform.release()
        self._digest = None

    def digest(self) -> str:
        if self._digest is None:
            self._digest = sha256_file(self.bpf_obj)
        return self._digest

    def verify(self, m: Manifest, platform: str) -> tuple:
        """Returns (ok, reason). Every check is fail-closed."""
        b = m.body
        gen = b.get("template") == GEN_TEMPLATE
        if b.get("schema") != 1 or b.get("template") not in (TEMPLATE, GEN_TEMPLATE):
            return False, "bad schema/template"
        if not m.sig_b64:
            return False, "unsigned"
        if not verify_bytes(self.pub_key, canonical(b), m.sig_b64):
            return False, "bad signature"
        if gen:
            # A scheduler written on this device: its files, its operator approval and its
            # kernel must all match what was signed. Imported lazily (genstore imports us).
            from .genstore import check_artifact_dir
            if b.get("ops_name") != GEN_OPS_NAME:
                return False, "bad ops name"
            ok, why = check_artifact_dir(m.artifact_dir, b, self.pub_key)
            if not ok:
                return False, why
            if b.get("kernel_release") != self.release:
                return False, f"generated for kernel {b.get('kernel_release')!r}, running {self.release!r}"
        elif b.get("template_sha256") != self.digest():
            return False, "bpf object digest mismatch"
        if b.get("platform") != platform:
            return False, f"manifest for platform {b.get('platform')!r}, device is {platform!r}"
        if b.get("arch") not in (_platform.machine(), "any"):
            return False, "arch mismatch"
        now = self.clock()
        if now > b["created"] + b["ttl_s"]:
            return False, "expired"
        if b["created"] > now + self.max_skew_s:
            return False, "created in the future"
        try:
            validate_params(Params.from_dict(b["params"]))
        except (ValueError, KeyError, TypeError) as e:
            return False, f"params invalid: {e}"
        return True, "ok"

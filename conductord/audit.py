"""Append-only, hash-chained audit log of every load / unload / rejection.

Shirudo parallel: a TPM-backed, verifiable record of protections loaded or
removed. Each entry's hash covers the previous hash, so truncation or edits are
detectable. If a TPM and tpm2-tools are present, each head hash is also extended
into a PCR (default 16, the resettable debug PCR, so it works in test VMs with
swtpm; production should pick a PCR policy deliberately - see docs/SAFETY.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from typing import Optional

GENESIS = "0" * 64


def _h(prev: str, entry: dict) -> str:
    payload = prev + json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str, tpm_pcr: Optional[int] = 16, use_tpm: bool = True, clock=time.time):
        self.path, self.clock = path, clock
        self.tpm_pcr = tpm_pcr
        self.use_tpm = use_tpm and shutil.which("tpm2_pcrextend") and os.path.exists("/dev/tpmrm0")
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.seq, self.head = self._recover()

    def _recover(self):
        seq, head = 0, GENESIS
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        e = json.loads(line)
                        seq, head = e["seq"], e["hash"]
        return seq, head

    def _tpm_extend(self, digest_hex: str) -> bool:
        if not self.use_tpm:
            return False
        r = subprocess.run(["tpm2_pcrextend", f"{self.tpm_pcr}:sha256={digest_hex}"],
                           capture_output=True)
        return r.returncode == 0

    def record(self, event: str, **data) -> dict:
        self.seq += 1
        entry = {"seq": self.seq, "ts": round(self.clock(), 3), "event": event, "data": data,
                 "prev": self.head}
        entry["hash"] = _h(self.head, {k: entry[k] for k in ("seq", "ts", "event", "data", "prev")})
        entry["tpm"] = self._tpm_extend(entry["hash"])
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.head = entry["hash"]
        return entry


def verify_chain(path: str) -> tuple:
    """Returns (ok, n_entries, error)."""
    prev, n = GENESIS, 0
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            core = {k: e[k] for k in ("seq", "ts", "event", "data", "prev")}
            if e["prev"] != prev or e["seq"] != n + 1 or _h(prev, core) != e["hash"]:
                return False, n, f"chain broken at line {i}"
            prev, n = e["hash"], n + 1
    return True, n, None

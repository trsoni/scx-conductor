"""Helpers for the generation tests: synthetic ELF objects, a fake toolchain, artifact factory."""
import hashlib
import json
import os
import struct

from conductord.genbackends import TemplateBackend, extract_c
from conductord.genbuild import BuildResult
from conductord.genstore import GenStore, source_id
from conductord.model import Workload
from conductord.policy import build_params
from tests.helpers import ROOT, profiles

TEMPLATE = os.path.join(ROOT, "bpf", "scx_conductor.bpf.c")
RELEASE = "6.99.0-test"
MACHINE = "x86_64"


def make_elf(sections, symbols=()):
    """Minimal little-endian ELF64. sections: [(name, type, size)]; symbols: [(name, section_name)]
    (adds .symtab/.strtab so extra_map_problems can see which symbols live in .maps)."""
    secs = [("", 0, 0)] + list(sections)
    strtab = b"\0"
    sym_entries = []
    names = [s[0] for s in secs]
    if symbols:
        secs += [(".symtab", 2, 0), (".strtab", 3, 0)]
        names = [s[0] for s in secs]
        sym_entries.append(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))
        for nm, sec in symbols:
            off = len(strtab)
            strtab += nm.encode() + b"\0"
            sym_entries.append(struct.pack("<IBBHQQ", off, 1, 0, names.index(sec), 0, 8))
    secs += [(".shstrtab", 3, 0)]
    names = [s[0] for s in secs]
    shstr, name_off = b"\0", {}
    for n in names:
        name_off[n] = len(shstr) if n else 0
        if n:
            shstr += n.encode() + b"\0"
    body, hdrs, off = b"", [], 64
    for i, (n, typ, size) in enumerate(secs):
        if n == ".symtab":
            data = b"".join(sym_entries)
        elif n == ".strtab":
            data = strtab
        elif n == ".shstrtab":
            data = shstr
        else:
            data = b"" if typ in (0, 8) else b"\0" * size
        shsize = size if typ == 8 else len(data) if n in (".symtab", ".strtab", ".shstrtab") else size
        link = names.index(".strtab") if n == ".symtab" else 0
        hdrs.append((name_off[n], typ, 0, 0, off if typ != 0 else 0, shsize, link, 0, 1,
                     24 if n == ".symtab" else 0))
        body += data
        off += len(data)
    shoff = 64 + len(body)
    shdrs = b"".join(struct.pack("<IIQQQQIIQQ", *h) for h in hdrs)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    hdr = ident + struct.pack("<HHIQQQIHHHHHH", 1, 247, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(secs),
                              names.index(".shstrtab"))
    return hdr + body + shdrs


GOOD_SECTIONS = [(".text", 1, 64), ("struct_ops/gen_enqueue", 1, 32), ("struct_ops.s/gen_init", 1, 16),
                 (".struct_ops.link", 1, 528), (".maps", 1, 128), (".bss", 8, 24), (".data", 1, 100),
                 (".rodata", 1, 80), ("license", 1, 4), (".BTF", 1, 200), (".BTF.ext", 1, 100),
                 ("fentry/bpf_scx_reg", 1, 40), (".rel.text", 9, 16), (".relstruct_ops/gen_enqueue", 9, 16)]


def good_source(workload=Workload.GAMING, platform="laptop", state="ac", tweak=0):
    """Gate-clean scheduler source: the reference scheduler with parameters baked in."""
    p = build_params(profiles(), workload, platform, state)
    p.slice_ns = [s + tweak * 1000 for s in p.slice_ns]
    return extract_c(TemplateBackend(TEMPLATE).complete("", "", {"params": p}))


def params(workload=Workload.GAMING, platform="laptop", state="ac"):
    return build_params(profiles(), workload, platform, state)


def reply(src):
    return "Here is the scheduler.\n```c\n" + src + "```\n"


class FakeToolchain:
    """Stands in for genbuild.Toolchain: writes plausible files, scripted failures."""
    machine, release = MACHINE, RELEASE

    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [])      # per build: None = ok, or (stage, log)
        self.calls = []

    def build(self, source, out_dir):
        self.calls.append(source)
        os.makedirs(out_dir, exist_ok=True)
        oc = self.outcomes.pop(0) if self.outcomes else None
        with open(os.path.join(out_dir, "source.bpf.c"), "w") as f:
            f.write(source)
        if oc:
            return BuildResult(False, oc[0], oc[1])
        files = {}
        for key, fname, payload in (("obj", "sched.bpf.o", b"OBJ" + source.encode()),
                                    ("loader", "gen_load", b"LOADER" + source.encode())):
            with open(os.path.join(out_dir, fname), "wb") as f:
                f.write(payload)
            files[key] = hashlib.sha256(payload).hexdigest()
        files["source"] = hashlib.sha256(source.encode()).hexdigest()
        return BuildResult(True, "ok", "", files, {"fake": True})


def make_artifact(store: GenStore, source=None, status="pending", workload="gaming", platform="laptop",
                  arch=MACHINE, release=RELEASE, verify_ok=True, canary_ok=None, created=1_700_000_000):
    """Write an artifact directory + meta as the generator would, without running any tool."""
    source = source or good_source()
    gid = source_id(source)
    d = store.begin(gid)
    files = {}
    with open(os.path.join(d, "source.bpf.c"), "w") as f:
        f.write(source)
    files["source"] = hashlib.sha256(source.encode()).hexdigest()
    for key, fname, payload in (("obj", "sched.bpf.o", b"OBJ" + source.encode()),
                                ("loader", "gen_load", b"LOADER" + source.encode())):
        with open(os.path.join(d, fname), "wb") as f:
            f.write(payload)
        files[key] = hashlib.sha256(payload).hexdigest()
    store.write_meta(gid, {"id": gid, "status": status, "workload": workload, "platform": platform,
                           "power_state": "ac", "arch": arch, "kernel_release": release, "created": created,
                           "backend": {"backend": "test"}, "attempts": 1, "gate": "pass",
                           "build": {"files": files, "tools": {}},
                           "verify": {"ok": verify_ok, "detail": "test"},
                           "canary": {"ok": canary_ok, "detail": "test"}})
    return gid

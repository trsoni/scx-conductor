"""Static gate for scheduler source written by an agent on the device.

This is *defence in depth*, not the security boundary. The boundaries are, in order:
the kernel verifier (memory safety, termination), the operator approval, the signed
manifest, the canary, and the kernel watchdog. The gate exists to (1) cut the C an
agent may write down to roughly what the reference scheduler already does, so review
is tractable, and (2) turn "the model wandered off" into a precise error message the
repair loop can feed back, before spending a compile.

What it enforces, on the source after comments are removed:

  * ASCII only, bounded size, no trigraph/digraph/token-pasting tricks;
  * only the two ABI includes; only simple preprocessor directives;
  * no inline asm, no ``extern``/``__ksym``/``__kptr``/``SEC()``/``__attribute__``,
    no function-pointer casts or integer-to-pointer casts (the helper-ID idiom);
  * every ``bpf_*`` / ``scx_bpf_*`` identifier is on an allowlist of helpers and
    kfuncs a scheduler legitimately needs; every ``BPF_*``/``UEI_*``/``SCX_OPS_*``
    macro likewise;
  * exactly the ops table shape the loader expects: ``SCX_OPS_DEFINE(gen_ops, ...)``
    with only allowed callbacks, ``.name = "conductor_gen"``, and *no* ``.flags`` /
    ``.timeout_ms`` (the loader forces those);
  * the telemetry contract: ``conductor_mark_enq`` / ``conductor_note_running`` /
    ``UEI_RECORD`` are used, and ``conductor_move_to_local`` instead of the raw kfunc.

``check()`` returns a list of human-readable problems; empty means pass.
``elf_problems()`` is the matching check on the compiled object.
"""
from __future__ import annotations

import re
import struct
from typing import Optional

MAX_SOURCE_BYTES = 48 * 1024
MAX_DATA_BYTES = 1 << 20          # .bss + .data + .rodata of the compiled object

GEN_OPS = "gen_ops"
GEN_NAME = "conductor_gen"
ALLOWED_INCLUDES = ("conductor_abi.bpf.h", "scx/common.bpf.h")
ALLOWED_DIRECTIVES = {"include", "define", "undef", "if", "ifdef", "ifndef", "elif", "else", "endif"}

# ---- API allowlists (also rendered into the generation prompt, so they cannot drift) ----
ALLOWED_BPF_HELPERS = [
    "bpf_ktime_get_ns", "bpf_map_lookup_elem", "bpf_task_storage_get",
    "bpf_get_smp_processor_id", "bpf_for", "bpf_repeat",
    "bpf_cpumask_test_cpu", "bpf_cpumask_weight", "bpf_cpumask_empty", "bpf_cpumask_first",
]
ALLOWED_SCX_KFUNCS = [
    "scx_bpf_select_cpu_dfl", "scx_bpf_dsq_insert", "scx_bpf_dsq_insert_vtime",
    "scx_bpf_create_dsq", "scx_bpf_task_cpu", "scx_bpf_cpuperf_set", "scx_bpf_cpuperf_cap",
    "scx_bpf_cpuperf_cur", "scx_bpf_kick_cpu", "scx_bpf_dsq_nr_queued", "scx_bpf_nr_cpu_ids",
    "scx_bpf_pick_idle_cpu", "scx_bpf_pick_any_cpu", "scx_bpf_test_and_clear_cpu_idle",
    "scx_bpf_get_idle_cpumask", "scx_bpf_put_idle_cpumask", "scx_bpf_error",
]
ALLOWED_OPS = ["select_cpu", "enqueue", "dequeue", "dispatch", "tick", "runnable", "running",
               "stopping", "quiescent", "set_weight", "update_idle", "enable", "init", "exit", "name"]
ALLOWED_BPF_MACROS = {"BPF_STRUCT_OPS", "BPF_STRUCT_OPS_SLEEPABLE"}
ALLOWED_DUNDER = {"__always_inline", "__noinline", "__sync_fetch_and_add", "__sync_add_and_fetch",
                  "__u8", "__u16", "__u32", "__u64", "__s8", "__s16", "__s32", "__s64"}
REQUIRED_CALLS = ("conductor_mark_enq", "conductor_note_running", "UEI_RECORD")

_FORBIDDEN_WORDS = {"asm", "_Pragma", "extern", "SEC", "typeof_unqual"}
_FORBIDDEN_PREFIXES = ("__kptr", "__arena", "__uptr", "__attribute", "__builtin", "__has_",
                       "__asm", "__ksym", "__weak", "__COMPAT")
# Names defined by conductor_abi.bpf.h (_license, uei, tgid_class, stats, lat_hist,
# task_ctx_stor) are *used* by schedulers, so the gate cannot ban them; redefining one
# is a compile error, which the repair loop reports.


def strip_comments(src: str) -> tuple:
    """Splice line continuations, then blank out comments (newlines kept).

    Returns (code, problems). String and char literals are respected, so ``"//"`` in a
    string is not a comment.
    """
    problems = []
    src = src.replace("\r\n", "\n").replace("\r", "\n")
    src = re.sub(r"\\\n", "", src)
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "/*":
            j = src.find("*/", i + 2)
            if j < 0:
                problems.append("unterminated /* comment")
                break
            out.append(" " + "\n" * src.count("\n", i, j))
            i = j + 2
        elif two == "//":
            j = src.find("\n", i)
            if j < 0:
                break
            out.append(" ")
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                if j < n and src[j] == "\n":
                    break
                j += 1
            if j >= n or src[j] != c:
                problems.append("unterminated string/char literal")
                out.append(src[i:j])
                i = j
                continue
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out), problems


def _blank_strings(code: str) -> str:
    """Replace string/char literal contents so identifiers inside them are not scanned."""
    return re.sub(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', '""', code)


def _matching_paren(s: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == "(":
            depth += 1
        elif s[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return -1


def check(src: str) -> list:
    problems: list = []
    if not isinstance(src, str) or not src.strip():
        return ["empty source"]
    raw = src.encode("utf-8", "replace")
    if len(raw) > MAX_SOURCE_BYTES:
        problems.append(f"source is {len(raw)} bytes, limit {MAX_SOURCE_BYTES}")
        return problems
    if any(ord(ch) > 126 or (ord(ch) < 32 and ch not in "\n\r\t") for ch in src):
        problems.append("non-ASCII or control characters are not allowed")
    if "??" in src:
        problems.append("trigraphs ('??') are not allowed")

    code, perr = strip_comments(src)
    problems += perr
    if perr:
        return problems
    plain = _blank_strings(code)

    # ---- preprocessor ----
    if "##" in plain:
        problems.append("token pasting '##' is not allowed")
    for dig in ("%:", "<%", "%>", "<:", ":>"):
        if dig in plain:
            problems.append(f"digraph {dig!r} is not allowed")
    for lineno, line in enumerate(code.split("\n"), 1):
        s = line.lstrip()
        if not s.startswith("#"):
            continue
        m = re.match(r"#\s*([A-Za-z_]\w*)", s)
        d = m.group(1) if m else ""
        if d not in ALLOWED_DIRECTIVES:
            problems.append(f"line {lineno}: preprocessor directive '#{d}' is not allowed")
            continue
        if d == "include":
            mi = re.match(r'#\s*include\s*[<"]([^>"]+)[>"]\s*$', s)
            if not mi or mi.group(1) not in ALLOWED_INCLUDES:
                problems.append(f"line {lineno}: only #include of {', '.join(ALLOWED_INCLUDES)} is allowed")

    # ---- constructs ----
    if re.search(r"\(\s*\*\s*\)\s*\(", plain):
        problems.append("function-pointer casts '(*)(...)' are not allowed")
    if re.search(r"\(\s*(?:const\s+)?(?:void|char|long|unsigned\s+long|u64|u32|s64|s32)\s*\*\s*\)\s*"
                 r"(?:0[xX][0-9a-fA-F]+|\d+)", plain):
        problems.append("casting an integer literal to a pointer is not allowed")
    if re.search(r"\b(?:goto)\b\s*\*", plain):
        problems.append("computed goto is not allowed")

    # ---- identifiers ----
    allowed_bpf = set(ALLOWED_BPF_HELPERS) | set(ALLOWED_SCX_KFUNCS)
    seen_bad: set = set()

    def bad(tok: str, why: str) -> None:
        if tok not in seen_bad:
            seen_bad.add(tok)
            problems.append(f"'{tok}': {why}")

    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", plain):
        if tok in _FORBIDDEN_WORDS:
            bad(tok, "not allowed in a generated scheduler")
        elif tok.startswith(_FORBIDDEN_PREFIXES):
            bad(tok, "not allowed in a generated scheduler")
        elif tok.startswith("__") and tok not in ALLOWED_DUNDER:
            bad(tok, "compiler/internal identifier not on the allowlist")
        elif tok == "scx_bpf_dsq_move_to_local":
            bad(tok, "use conductor_move_to_local(dsq): the kfunc's arity differs between kernel versions")
        elif (tok.startswith("bpf_") or tok.startswith("scx_bpf_")) and tok not in allowed_bpf:
            bad(tok, "helper/kfunc is not on the allowlist")
        elif tok.startswith("BPF_") and tok not in ALLOWED_BPF_MACROS:
            bad(tok, "BPF_* macro is not allowed (only BPF_STRUCT_OPS and BPF_STRUCT_OPS_SLEEPABLE)")
        elif tok.startswith("UEI_") and tok != "UEI_RECORD":
            bad(tok, "only UEI_RECORD may be used; the ABI header defines the rest")
        elif tok.startswith("SCX_OPS_") and tok != "SCX_OPS_DEFINE":
            bad(tok, "only SCX_OPS_DEFINE may be used")

    # ---- ops table ----
    k = plain.find("SCX_OPS_DEFINE")
    if k < 0:
        problems.append("missing SCX_OPS_DEFINE(gen_ops, ...)")
    else:
        po = plain.find("(", k)
        pc = _matching_paren(plain, po) if po >= 0 else -1
        if pc < 0:
            problems.append("malformed SCX_OPS_DEFINE")
        else:
            body = plain[po + 1:pc]
            first = body.split(",", 1)[0].strip()
            if first != GEN_OPS:
                problems.append(f"the ops table must be named {GEN_OPS}, found '{first}'")
            members = re.findall(r"\.\s*([A-Za-z_]\w*)\s*=", body)
            for mem in members:
                if mem in ("flags", "timeout_ms"):
                    problems.append(f".{mem} must not be set: the loader owns it")
                elif mem not in ALLOWED_OPS:
                    problems.append(f".{mem} is not an allowed ops member")
            if len(members) != len(set(members)):
                problems.append("duplicate ops member")
            raw_body = code[code.find("SCX_OPS_DEFINE"):]
            mname = re.search(r'\.\s*name\s*=\s*"([^"]*)"', raw_body)
            if not mname or mname.group(1) != GEN_NAME:
                problems.append(f'.name must be "{GEN_NAME}"')
            if "select_cpu" not in members and "enqueue" not in members:
                problems.append("a scheduler needs at least .enqueue or .select_cpu")
            if "exit" not in members:
                problems.append("missing .exit (it must call UEI_RECORD)")

    # ---- telemetry contract ----
    for call in REQUIRED_CALLS:
        if not re.search(r"\b" + re.escape(call) + r"\s*\(", plain):
            problems.append(f"{call}() is never called (required by the conductor ABI)")
    if "conductor_abi.bpf.h" not in code:
        problems.append('missing #include "conductor_abi.bpf.h"')
    return problems


# ---------------------------------------------------------------- compiled object
_ALLOWED_SECTION_RE = re.compile(
    r"^(?:"
    r"|\.text|\.bss|\.data|\.rodata|\.maps|license|\.struct_ops\.link|\.BTF|\.BTF\.ext"
    r"|\.symtab|\.strtab|\.shstrtab|\.llvm_addrsig|\.comment|\.eh_frame|\.data\.uei_dump"
    r"|\.(?:rodata|data|bss)\.[A-Za-z0-9_.]+"
    r"|\.debug_[a-z_]+"
    r"|\.rel[a]?(?:\..+|struct_ops.*|fentry/.*)"
    r"|struct_ops(?:\.s)?/[A-Za-z_][A-Za-z0-9_]*"
    r"|fentry/bpf_scx_reg(?:_cid)?"
    r")$")


def elf_sections(path: str) -> list:
    """[(name, size, type)] from a little-endian ELF64 file (no external tools)."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a little-endian ELF64 object")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(shnum):
        off = shoff + i * shentsize
        name, typ, _flags, _addr, soff, size = struct.unpack_from("<IIQQQQ", data, off)
        secs.append([name, typ, soff, size])
    stroff = secs[shstrndx][2]
    out = []
    for name, typ, soff, size in secs:
        end = data.index(b"\0", stroff + name)
        out.append((data[stroff + name:end].decode("ascii", "replace"), size, typ))
    return out


def elf_problems(path: str) -> list:
    """Reject compiled objects that carry anything but struct_ops programs and data."""
    try:
        secs = elf_sections(path)
    except (OSError, ValueError, struct.error) as e:
        return [f"cannot parse object: {e}"]
    problems, data_bytes = [], 0
    names = [n for n, _, _ in secs]
    for name, size, typ in secs:
        if not _ALLOWED_SECTION_RE.match(name):
            problems.append(f"unexpected section '{name}' (only struct_ops programs and data are allowed)")
        if name in (".bss", ".data", ".rodata") or name.startswith((".bss.", ".data.", ".rodata.")):
            data_bytes += size
    if data_bytes > MAX_DATA_BYTES:
        problems.append(f"static data is {data_bytes} bytes, limit {MAX_DATA_BYTES}")
    if ".struct_ops.link" not in names:
        problems.append("no .struct_ops.link section: SCX_OPS_DEFINE did not take effect")
    if ".maps" in names:
        pass  # the ABI header's maps live here; extra maps are blocked by the SEC() ban
    return problems


def extra_map_problems(path: str, allowed: Optional[set] = None) -> list:
    """Check the object defines no maps beyond the ABI ones (reads BTF-free: via symbols)."""
    if allowed is None:
        allowed = {"tgid_class", "stats", "lat_hist", "task_ctx_stor"}
    try:
        with open(path, "rb") as f:
            data = f.read()
        # symbol names of OBJECT type in .maps are hard to get without a full parser;
        # use the string table: map names are plain identifiers there.
        secs = {}
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        raw = []
        for i in range(shnum):
            raw.append(struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize))
        stroff = raw[shstrndx][4]
        for idx, sh in enumerate(raw):
            end = data.index(b"\0", stroff + sh[0])
            secs[data[stroff + sh[0]:end].decode()] = idx
        if ".maps" not in secs or ".symtab" not in secs:
            return []
        maps_idx = secs[".maps"]
        sym = raw[secs[".symtab"]]
        strtab = raw[sym[6]]            # sh_link
        found = []
        for off in range(sym[4], sym[4] + sym[5], 24):
            st_name, _info, _other, st_shndx = struct.unpack_from("<IBBH", data, off)
            if st_shndx == maps_idx:
                end = data.index(b"\0", strtab[4] + st_name)
                found.append(data[strtab[4] + st_name:end].decode())
        return [f"unexpected map '{m}' (maps other than the ABI maps are not allowed)"
                for m in found if m not in allowed]
    except (OSError, ValueError, struct.error, IndexError) as e:
        return [f"cannot inspect maps: {e}"]

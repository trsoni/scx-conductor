"""Model backends for on-device scheduler generation.

A backend turns (system prompt, user prompt) into text containing one C source file.
Four kinds:

  anthropic  the Anthropic Messages API over HTTPS (stdlib only, no SDK dependency).
             Key from $ANTHROPIC_API_KEY or /etc/conductor/anthropic.key (mode 0600).
             The prompt contains no process names, paths or user data (see
             generator.build_prompt); `conductord gen --print-prompt` shows it verbatim.
  command    pipes the prompt to a local command's stdin and reads stdout, e.g.
             ``claude -p`` or any local-model wrapper. Nothing leaves the device unless
             the command sends it.
  template   deterministic and offline: bakes the workload parameters into the
             reference scheduler. Used for CI, QEMU, and for exercising the whole
             pipeline (gate, build, verify, canary, approval) without a model.
  callable   a Python function; used by tests.

Backends never see or return anything but text: all trust decisions happen after.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import urllib.error
import urllib.request
from typing import Callable, Optional

DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_KEY_FILE = "/etc/conductor/anthropic.key"
ANTHROPIC_VERSION = "2023-06-01"


class GenError(Exception):
    """A backend could not produce text (network, auth, bad output). Never contains a key."""


# ----------------------------------------------------------------- output handling
_FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_+-]*)[^\n]*\n(.*?)```", re.S)


def extract_c(text: str) -> str:
    """Pull the scheduler source out of a model reply.

    Prefers a fenced block that contains SCX_OPS_DEFINE; falls back to the longest
    fenced block, then to the whole text if it looks like C. Raises GenError if there
    is nothing usable.
    """
    if not isinstance(text, str) or not text.strip():
        raise GenError("empty model output")
    blocks = [m.group(2) for m in _FENCE_RE.finditer(text)]
    for b in blocks:
        if "SCX_OPS_DEFINE" in b:
            return b.strip("\n") + "\n"
    if blocks:
        return max(blocks, key=len).strip("\n") + "\n"
    if "SCX_OPS_DEFINE" in text or "#include" in text:
        return text.strip("\n") + "\n"
    raise GenError("no C source found in model output")


# ----------------------------------------------------------------- backends
class Backend:
    name = "backend"
    model = ""

    def complete(self, system: str, user: str, ctx: Optional[dict] = None) -> str:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> dict:
        return {"backend": self.name, "model": self.model}


class AnthropicBackend(Backend):
    name = "anthropic"

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 key_file: str = DEFAULT_KEY_FILE, base_url: Optional[str] = None,
                 max_tokens: int = 8000, timeout: float = 180.0, opener: Optional[Callable] = None):
        self.model = model or os.environ.get("CONDUCTOR_GEN_MODEL") or DEFAULT_MODEL
        self.base_url = (base_url or os.environ.get("ANTHROPIC_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.max_tokens, self.timeout = max_tokens, timeout
        self._key, self._key_file = api_key, key_file
        self._open = opener or urllib.request.urlopen

    def have_key(self) -> bool:
        try:
            return bool(self._load_key())
        except GenError:
            return False

    def _load_key(self) -> str:
        if self._key:
            return self._key
        env = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if env:
            return env
        try:
            st = os.stat(self._key_file)
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise GenError(f"{self._key_file} must not be readable by group/others (chmod 600)")
            with open(self._key_file) as f:
                k = f.read().strip()
            if k:
                return k
        except OSError:
            pass
        raise GenError("no API key: set ANTHROPIC_API_KEY or create " + self._key_file)

    def complete(self, system: str, user: str, ctx: Optional[dict] = None) -> str:
        key = self._load_key()
        body = json.dumps({"model": self.model, "max_tokens": self.max_tokens, "system": system,
                           "messages": [{"role": "user", "content": user}]}).encode()
        req = urllib.request.Request(
            self.base_url + "/v1/messages", data=body, method="POST",
            headers={"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION,
                     "content-type": "application/json"})
        try:
            with self._open(req, timeout=self.timeout) as r:
                payload = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            raise GenError(f"API error {e.code}: {detail}") from None
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
            raise GenError(f"API request failed: {type(e).__name__}: {e}") from None
        parts = [b.get("text", "") for b in payload.get("content", []) if b.get("type") == "text"]
        if not parts:
            raise GenError("API returned no text content")
        if payload.get("stop_reason") == "max_tokens":
            raise GenError("model output was cut off (max_tokens); the source would be incomplete")
        return "".join(parts)


class CommandBackend(Backend):
    name = "command"

    def __init__(self, cmd, timeout: float = 300.0, runner=subprocess.run):
        self.argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        if not self.argv:
            raise GenError("empty command")
        self.model, self.timeout, self._run = self.argv[0], timeout, runner

    def complete(self, system: str, user: str, ctx: Optional[dict] = None) -> str:
        prompt = system + "\n\n" + user
        try:
            r = self._run(self.argv, input=prompt.encode(), capture_output=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise GenError(f"command backend failed: {type(e).__name__}: {e}") from None
        if r.returncode != 0:
            raise GenError(f"command exited {r.returncode}: {r.stderr.decode(errors='replace')[-300:]}")
        return r.stdout.decode(errors="replace")


class CallableBackend(Backend):
    name = "callable"

    def __init__(self, fn: Callable, model: str = "test"):
        self.fn, self.model = fn, model

    def complete(self, system: str, user: str, ctx: Optional[dict] = None) -> str:
        return self.fn(system, user, ctx)


def _fmt_arr(vals) -> str:
    return "{ " + ", ".join(str(int(v)) for v in vals) + " }"


class TemplateBackend(Backend):
    """Deterministic: the reference scheduler with the workload parameters baked in."""
    name = "template"
    model = "reference-template"

    def __init__(self, template_path: str):
        self.template_path = template_path

    def complete(self, system: str, user: str, ctx: Optional[dict] = None) -> str:
        if not ctx or "params" not in ctx:
            raise GenError("template backend needs ctx['params']")
        p = ctx["params"]
        with open(self.template_path) as f:
            src = f.read()

        def sub(pattern: str, repl: str) -> None:
            nonlocal src
            new, n = re.subn(pattern, repl, src, count=1, flags=re.S)
            if n != 1:
                raise GenError(f"template shape changed: cannot bake {pattern!r}")
            src = new

        sub(r"(const volatile u64 slice_ns\[NR_CLS\]\s*=\s*)\{[^}]*\}", r"\g<1>" + _fmt_arr(p.slice_ns))
        sub(r"(const volatile u64 credit_ns\[NR_CLS\]\s*=\s*)\{[^}]*\}", r"\g<1>" + _fmt_arr(p.credit_ns))
        sub(r"(const volatile u32 charge_pct\[NR_CLS\]\s*=\s*)\{[^}]*\}", r"\g<1>" + _fmt_arr(p.charge_pct))
        sub(r"(const volatile u32 perf_target\[NR_CLS\]\s*=\s*)\{[^}]*\}", r"\g<1>" + _fmt_arr(p.perf))
        sub(r"SCX_OPS_DEFINE\(conductor_ops,", "SCX_OPS_DEFINE(gen_ops,")
        sub(r"\n[ \t]*\.timeout_ms[ \t]*=[ \t]*\d+,", "")
        sub(r'\.name(\s*)=\s*"conductor"', r'.name\1= "conductor_gen"')
        banner = ("/* Generated by the conductor TEMPLATE backend: the reference scheduler with the\n"
                  " * workload parameters baked in. Deterministic; no model involved. */\n")
        return "```c\n" + banner + src + "```\n"


def make_backend(kind: str, *, cmd: Optional[str] = None, model: Optional[str] = None,
                 key_file: Optional[str] = None, base_url: Optional[str] = None,
                 template_path: Optional[str] = None) -> Optional[Backend]:
    if kind in (None, "", "none"):
        return None
    if kind == "anthropic":
        return AnthropicBackend(model=model, key_file=key_file or DEFAULT_KEY_FILE, base_url=base_url)
    if kind == "command":
        if not cmd:
            raise GenError("--gen-cmd is required for the command backend")
        return CommandBackend(cmd)
    if kind == "template":
        if not template_path:
            raise GenError("template backend needs the reference template path")
        return TemplateBackend(template_path)
    raise GenError(f"unknown backend {kind!r}")

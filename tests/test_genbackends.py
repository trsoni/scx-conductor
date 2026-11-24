import io
import json
import os
import stat
import sys
import tempfile
import unittest
import urllib.error

from conductord import genbackends as gb, genstatic
from tests.genhelpers import TEMPLATE, good_source, params


class FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def api_reply(text, stop="end_turn"):
    return FakeResp(json.dumps({"content": [{"type": "text", "text": text}], "stop_reason": stop}).encode())


class TestExtractC(unittest.TestCase):
    def test_prefers_block_with_ops(self):
        t = "```c\nint a;\n```\ntext\n```c\n#include \"x.h\"\nSCX_OPS_DEFINE(gen_ops);\n```"
        self.assertIn("SCX_OPS_DEFINE", gb.extract_c(t))

    def test_longest_block_when_none_has_ops(self):
        t = "```c\nint a;\n```\n```c\nint a; int b; int c;\n```"
        self.assertIn("int c", gb.extract_c(t))

    def test_fence_with_language_variants(self):
        for lang in ("c", "C", "bpf", "cpp", ""):
            t = f"```{lang}\nSCX_OPS_DEFINE(gen_ops);\n```"
            self.assertIn("SCX_OPS_DEFINE", gb.extract_c(t))

    def test_unfenced_source(self):
        self.assertIn("#include", gb.extract_c('#include "conductor_abi.bpf.h"\nint x;'))

    def test_nothing_usable(self):
        for bad in ("", "   ", "I cannot help with that."):
            with self.assertRaises(gb.GenError):
                gb.extract_c(bad)


class TestAnthropic(unittest.TestCase):
    def test_request_shape_and_text(self):
        seen = {}

        def opener(req, timeout):
            seen["url"], seen["hdr"], seen["body"] = req.full_url, dict(req.header_items()), json.loads(req.data)
            seen["timeout"] = timeout
            return api_reply("```c\nint x;\n```")
        b = gb.AnthropicBackend(model="m-1", api_key="sk-test", base_url="https://example.invalid/", opener=opener)
        out = b.complete("SYS", "USER")
        self.assertIn("int x", out)
        self.assertEqual(seen["url"], "https://example.invalid/v1/messages")
        self.assertEqual(seen["hdr"]["X-api-key"], "sk-test")
        self.assertEqual(seen["hdr"]["Anthropic-version"], gb.ANTHROPIC_VERSION)
        self.assertEqual(seen["body"]["model"], "m-1")
        self.assertEqual(seen["body"]["system"], "SYS")
        self.assertEqual(seen["body"]["messages"], [{"role": "user", "content": "USER"}])

    def test_http_error_does_not_leak_key(self):
        def opener(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"error":"bad key"}'))
        b = gb.AnthropicBackend(api_key="sk-secret-123", opener=opener)
        with self.assertRaises(gb.GenError) as cm:
            b.complete("s", "u")
        self.assertIn("401", str(cm.exception))
        self.assertNotIn("sk-secret-123", str(cm.exception))

    def test_network_error_and_truncated_output(self):
        def boom(req, timeout):
            raise urllib.error.URLError("no route")
        with self.assertRaises(gb.GenError):
            gb.AnthropicBackend(api_key="k", opener=boom).complete("s", "u")
        with self.assertRaises(gb.GenError) as cm:
            gb.AnthropicBackend(api_key="k", opener=lambda r, timeout: api_reply("x", "max_tokens")).complete("s", "u")
        self.assertIn("cut off", str(cm.exception))

    def test_no_text_blocks(self):
        op = lambda r, timeout: FakeResp(b'{"content": [], "stop_reason": "end_turn"}')
        with self.assertRaises(gb.GenError):
            gb.AnthropicBackend(api_key="k", opener=op).complete("s", "u")

    def test_key_sources(self):
        d = tempfile.mkdtemp()
        kf = os.path.join(d, "key")
        with open(kf, "w") as f:
            f.write("sk-from-file\n")
        os.chmod(kf, 0o644)
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            b = gb.AnthropicBackend(key_file=kf)
            self.assertFalse(b.have_key())                      # world-readable key file is refused
            os.chmod(kf, 0o600)
            self.assertTrue(b.have_key())
            self.assertEqual(b._load_key(), "sk-from-file")
            os.environ["ANTHROPIC_API_KEY"] = "sk-from-env"
            self.assertEqual(b._load_key(), "sk-from-env")      # env wins
            del os.environ["ANTHROPIC_API_KEY"]
            self.assertFalse(gb.AnthropicBackend(key_file=os.path.join(d, "missing")).have_key())
        finally:
            os.environ.pop("ANTHROPIC_API_KEY", None)
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old

    def test_model_default_and_env(self):
        old = os.environ.pop("CONDUCTOR_GEN_MODEL", None)
        try:
            self.assertEqual(gb.AnthropicBackend(api_key="k").model, gb.DEFAULT_MODEL)
            os.environ["CONDUCTOR_GEN_MODEL"] = "other"
            self.assertEqual(gb.AnthropicBackend(api_key="k").model, "other")
        finally:
            os.environ.pop("CONDUCTOR_GEN_MODEL", None)
            if old is not None:
                os.environ["CONDUCTOR_GEN_MODEL"] = old


class TestCommandBackend(unittest.TestCase):
    def test_prompt_on_stdin_text_on_stdout(self):
        b = gb.CommandBackend([sys.executable, "-c", "import sys; d=sys.stdin.read(); print('GOT:'+d.replace(chr(10),'|'))"])
        out = b.complete("S", "U")
        self.assertIn("GOT:S||U", out)

    def test_nonzero_exit_and_missing_binary(self):
        with self.assertRaises(gb.GenError) as cm:
            gb.CommandBackend([sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"]).complete("s", "u")
        self.assertIn("exited 3", str(cm.exception))
        with self.assertRaises(gb.GenError):
            gb.CommandBackend(["/nonexistent/bin/model"]).complete("s", "u")
        with self.assertRaises(gb.GenError):
            gb.CommandBackend("")

    def test_string_command_is_split(self):
        self.assertEqual(gb.CommandBackend("claude -p --foo 'a b'").argv, ["claude", "-p", "--foo", "a b"])


class TestTemplateBackend(unittest.TestCase):
    def test_bakes_parameters_and_passes_gate(self):
        p = params()
        src = gb.extract_c(gb.TemplateBackend(TEMPLATE).complete("", "", {"params": p}))
        self.assertEqual(genstatic.check(src), [])
        for arr in (p.slice_ns, p.credit_ns, p.charge_pct, p.perf):
            self.assertIn("{ " + ", ".join(str(v) for v in arr) + " }", src)
        self.assertNotIn(".timeout_ms", src)
        self.assertIn('"conductor_gen"', src)
        self.assertNotIn("conductor_ops", src)

    def test_different_params_different_source(self):
        a = gb.extract_c(gb.TemplateBackend(TEMPLATE).complete("", "", {"params": params()}))
        from conductord.model import Workload
        b = gb.extract_c(gb.TemplateBackend(TEMPLATE).complete("", "", {"params": params(Workload.VIDEO)}))
        self.assertNotEqual(a, b)

    def test_needs_params_and_detects_template_drift(self):
        t = gb.TemplateBackend(TEMPLATE)
        with self.assertRaises(gb.GenError):
            t.complete("", "", None)
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.c")
        with open(p, "w") as f:
            f.write("int nothing_to_bake;")
        with self.assertRaises(gb.GenError):
            gb.TemplateBackend(p).complete("", "", {"params": params()})


class TestMakeBackend(unittest.TestCase):
    def test_kinds(self):
        self.assertIsNone(gb.make_backend("none"))
        self.assertIsInstance(gb.make_backend("anthropic", model="m"), gb.AnthropicBackend)
        self.assertIsInstance(gb.make_backend("command", cmd="echo hi"), gb.CommandBackend)
        self.assertIsInstance(gb.make_backend("template", template_path=TEMPLATE), gb.TemplateBackend)
        for kw in ({"kind": "command"}, {"kind": "template"}, {"kind": "bogus"}):
            with self.assertRaises(gb.GenError):
                gb.make_backend(**kw)

    def test_describe(self):
        self.assertEqual(gb.make_backend("template", template_path=TEMPLATE).describe()["backend"], "template")


if __name__ == "__main__":
    unittest.main()

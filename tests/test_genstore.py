import json
import os
import shutil
import tempfile
import unittest

from conductord import forge
from conductord.forge import Verifier, keygen
from conductord.genstore import GenForge, GenStore, check_artifact_dir, source_id
from conductord.model import Workload
from tests.genhelpers import MACHINE, RELEASE, good_source, make_artifact, params
from tests.helpers import Env


def rtext(path):
    with open(path) as f:
        return f.read()


def rjson(path):
    with open(path) as f:
        return json.load(f)


def wjson(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.e = Env("laptop")
        self.root = os.path.join(self.e.d, "generated")
        self.now = [1_700_000_000.0]
        self.store = GenStore(self.root, clock=lambda: self.now[0])
        self.addCleanup(shutil.rmtree, self.e.d, ignore_errors=True)

    def verifier(self, release=RELEASE):
        return Verifier(self.e.pub, self.e.obj, release=release)


class TestIds(unittest.TestCase):
    def test_same_source_same_id_and_hex(self):
        a, b = source_id("int x;"), source_id("int x;")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 12)
        self.assertNotEqual(a, source_id("int y;"))

    def test_bad_ids_are_rejected_before_touching_the_filesystem(self):
        s = GenStore("/nonexistent-root")
        for bad in ("", "../etc", "ABC", "abc/def", "xyz", "0123456789ab/../x"):
            with self.assertRaises(ValueError):
                s.dir(bad)


class TestApprovalFlow(StoreCase):
    def test_pending_to_approved(self):
        gid = make_artifact(self.store)
        self.assertIsNone(self.store.approval(gid))
        m = self.store.approve(gid, self.e.priv, approver="alice")
        self.assertEqual((m["status"], m["approved_by"], m["approved_at"]), ("approved", "alice", 1_700_000_000))
        ap = self.store.approval(gid)
        self.assertEqual(ap["body"]["id"], gid)
        self.assertTrue(forge.verify_bytes(self.e.pub, forge.canonical(ap["body"]), ap["sig"]))
        self.assertEqual(self.store.approve(gid, self.e.priv)["status"], "approved")     # idempotent

    def test_refuses_unverified_or_canary_failed(self):
        g1 = make_artifact(self.store, verify_ok=False)
        with self.assertRaisesRegex(ValueError, "verifier"):
            self.store.approve(g1, self.e.priv)
        g2 = make_artifact(self.store, source=good_source(tweak=1), canary_ok=False)
        with self.assertRaisesRegex(ValueError, "canary"):
            self.store.approve(g2, self.e.priv)

    def test_refuses_rejected_failed_and_unknown(self):
        gid = make_artifact(self.store, status="rejected")
        with self.assertRaisesRegex(ValueError, "only pending"):
            self.store.approve(gid, self.e.priv)
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.store.approve("abcdef012345", self.e.priv)

    def test_refuses_when_files_changed_since_build(self):
        gid = make_artifact(self.store)
        with open(os.path.join(self.store.dir(gid), "sched.bpf.o"), "ab") as f:
            f.write(b"tamper")
        with self.assertRaisesRegex(ValueError, "changed since"):
            self.store.approve(gid, self.e.priv)
        self.assertIsNone(self.store.approval(gid))

    def test_reject_removes_approval(self):
        gid = make_artifact(self.store)
        self.store.approve(gid, self.e.priv)
        m = self.store.reject(gid, "does not look right")
        self.assertEqual((m["status"], m["reject_reason"]), ("rejected", "does not look right"))
        self.assertIsNone(self.store.approval(gid))
        self.assertIsNone(self.store.lookup("gaming", "laptop", MACHINE, RELEASE))


class TestLookup(StoreCase):
    def test_only_approved_for_matching_target(self):
        a = make_artifact(self.store, created=100)
        self.assertIsNone(self.store.lookup("gaming", "laptop", MACHINE, RELEASE))     # pending
        self.store.approve(a, self.e.priv)
        self.assertEqual(self.store.lookup("gaming", "laptop", MACHINE, RELEASE), a)
        for args in (("video", "laptop", MACHINE, RELEASE), ("gaming", "mobile", MACHINE, RELEASE),
                     ("gaming", "laptop", "aarch64", RELEASE), ("gaming", "laptop", MACHINE, "6.99.1-other")):
            self.assertIsNone(self.store.lookup(*args), args)

    def test_newest_approved_wins(self):
        a = make_artifact(self.store, created=100)
        b = make_artifact(self.store, source=good_source(tweak=2), created=200)
        for g in (a, b):
            self.store.approve(g, self.e.priv)
        self.assertEqual(self.store.lookup("gaming", "laptop", MACHINE, RELEASE), b)

    def test_list_hides_failed_and_prunes(self):
        ok = make_artifact(self.store)
        failed = [make_artifact(self.store, source=good_source(tweak=10 + i), status="failed", created=i)
                  for i in range(5)]
        self.assertEqual([m["id"] for m in self.store.list()], [ok])
        self.assertEqual(len(self.store.list(include_failed=True)), 6)
        self.assertEqual(self.store.prune_failed(keep=2), 3)
        self.assertEqual(len(self.store.list(include_failed=True)), 3)
        self.assertTrue(self.store.exists(ok))


class TestReview(StoreCase):
    def test_review_sheet_has_results_digests_and_diff(self):
        gid = make_artifact(self.store, canary_ok=True)
        from tests.genhelpers import TEMPLATE
        txt = rtext(self.store.write_review(gid, TEMPLATE))
        for needle in ("# Generated scheduler " + gid, "workload: **gaming**", "static gate: pass",
                       "Diff against the reference scheduler", "```diff", f"gen-approve {gid}", "source:"):
            self.assertIn(needle, txt)
        self.assertIn("-const volatile u64 slice_ns", txt)             # the diff is real, not empty


class TestManifestsAndVerifier(StoreCase):
    def approved(self, **kw):
        gid = make_artifact(self.store, **kw)
        self.store.approve(gid, self.e.priv)
        return gid

    def manifest(self, gid=None, wl=Workload.GAMING, state="ac", forge_=None):
        gid = gid or self.approved()
        return (forge_ or GenForge(self.store, self.e.priv, clock=lambda: self.now[0])).make(
            gid, wl, "laptop", state, params(wl))

    def test_happy_path(self):
        m = self.manifest()
        self.assertTrue(m.is_generated)
        self.assertEqual(m.ops_name, "conductor_gen")
        self.assertEqual(m.body["template_sha256"], forge.sha256_file(os.path.join(m.artifact_dir, "sched.bpf.o")))
        self.assertTrue(m.name.startswith("gen:") and m.name.endswith("gaming@laptop/ac"))
        v = Verifier(self.e.pub, self.e.obj, clock=lambda: self.now[0], release=RELEASE)
        self.assertEqual(v.verify(m, "laptop"), (True, "ok"))

    def test_no_manifest_without_approval(self):
        gid = make_artifact(self.store)
        self.assertIsNone(GenForge(self.store, self.e.priv).make(gid, Workload.GAMING, "laptop", "ac", params()))

    def test_manifest_is_cached_for_half_ttl_then_reminted(self):
        gf = GenForge(self.store, self.e.priv, clock=lambda: self.now[0])
        gid = self.approved()
        m1 = gf.make(gid, Workload.GAMING, "laptop", "ac", params())
        self.now[0] += 3600
        self.assertEqual(gf.make(gid, Workload.GAMING, "laptop", "ac", params()).hash, m1.hash)
        self.assertIs(gf.make(gid, Workload.GAMING, "laptop", "ac", params()), m1)
        self.now[0] += 12 * 3600
        self.assertNotEqual(gf.make(gid, Workload.GAMING, "laptop", "ac", params()).hash, m1.hash)

    def test_states_get_distinct_manifests(self):
        gid = self.approved()
        gf = GenForge(self.store, self.e.priv, clock=lambda: self.now[0])
        a = gf.make(gid, Workload.GAMING, "laptop", "ac", params())
        b = gf.make(gid, Workload.GAMING, "laptop", "battery", params(state="battery"))
        self.assertNotEqual(a.hash, b.hash)

    def check(self, m, release=RELEASE, platform="laptop", pub=None):
        v = Verifier(pub or self.e.pub, self.e.obj, clock=lambda: self.now[0], release=release)
        return v.verify(m, platform)

    def test_each_artifact_file_is_pinned(self):
        for fname, label in (("sched.bpf.o", "sched.bpf.o"), ("gen_load", "gen_load"), ("source.bpf.c", "source.bpf.c")):
            self.setUp()
            m = self.manifest()
            with open(os.path.join(m.artifact_dir, fname), "ab") as f:
                f.write(b"x")
            ok, why = self.check(m)
            self.assertFalse(ok)
            self.assertIn(label, why)

    def test_missing_file_and_missing_dir(self):
        m = self.manifest()
        os.unlink(os.path.join(m.artifact_dir, "gen_load"))
        self.assertEqual(self.check(m), (False, "gen_load missing"))
        m.artifact_dir = None
        self.assertEqual(self.check(m), (False, "generated artifact directory missing"))

    def test_approval_required_and_must_verify(self):
        m = self.manifest()
        ap = os.path.join(m.artifact_dir, "approval.json")
        saved = rtext(ap)
        os.unlink(ap)
        self.assertEqual(self.check(m), (False, "no operator approval"))
        # approval signed by someone else
        other_priv, other_pub = os.path.join(self.e.d, "o.key"), os.path.join(self.e.d, "o.pub")
        keygen(other_priv, other_pub)
        body = json.loads(saved)["body"]
        wjson(ap, {"body": body, "sig": forge.sign_bytes(other_priv, forge.canonical(body))})
        self.assertEqual(self.check(m), (False, "approval signature invalid"))

    def test_approval_for_other_digests_or_target(self):
        m = self.manifest()
        ap = os.path.join(m.artifact_dir, "approval.json")
        good = rjson(ap)
        # validly signed but describing a different loader
        body = dict(good["body"], loader_sha256="0" * 64)
        wjson(ap, {"body": body, "sig": forge.sign_bytes(self.e.priv, forge.canonical(body))})
        self.assertEqual(self.check(m), (False, "approval does not match artifact digests"))
        # validly signed, right digests, but for another kernel
        body = dict(good["body"], kernel_release="6.1.0-other")
        wjson(ap, {"body": body, "sig": forge.sign_bytes(self.e.priv, forge.canonical(body))})
        ok, why = self.check(m)
        self.assertFalse(ok)
        self.assertIn("approval digest mismatch", why)       # the manifest pinned the original approval's digest

    def test_swapped_approval_is_caught_by_digest_pin(self):
        m = self.manifest()
        ap = os.path.join(m.artifact_dir, "approval.json")
        body = dict(rjson(ap)["body"], approved_by="mallory")
        wjson(ap, {"body": body, "sig": forge.sign_bytes(self.e.priv, forge.canonical(body))})
        self.assertEqual(self.check(m), (False, "approval digest mismatch"))

    def test_wrong_kernel_wrong_platform_wrong_ops_name_unsigned_tampered_body(self):
        m = self.manifest()
        ok, why = self.check(m, release="6.99.1-other")
        self.assertFalse(ok)
        self.assertIn("generated for kernel", why)
        self.assertIn("platform", self.check(m, platform="mobile")[1])
        bad = forge.Manifest(dict(m.body, ops_name="conductor"), m.sig_b64, m.artifact_dir)
        self.assertEqual(self.check(bad), (False, "bad signature"))            # body changed after signing
        resigned = forge.Manifest(dict(m.body, ops_name="conductor"), None, m.artifact_dir)
        resigned.sig_b64 = forge.sign_bytes(self.e.priv, forge.canonical(resigned.body))
        self.assertEqual(self.check(resigned), (False, "bad ops name"))
        self.assertEqual(self.check(forge.Manifest(m.body, None, m.artifact_dir)), (False, "unsigned"))

    def test_expired_and_params_bounds_still_enforced(self):
        m = self.manifest()
        self.now[0] += 25 * 3600
        self.assertEqual(self.check(m), (False, "expired"))
        self.now[0] = 1_700_000_000.0
        p = params()
        p.slice_ns = [10, 10, 10, 10]
        gid = self.approved(source=good_source(tweak=3))
        m2 = GenForge(self.store, self.e.priv, clock=lambda: self.now[0]).make(gid, Workload.GAMING, "laptop", "ac", p)
        ok, why = self.check(m2)
        self.assertFalse(ok)
        self.assertIn("params invalid", why)

    def test_template_manifests_still_verify_and_artifact_dir_is_not_serialised(self):
        t = self.e.forge.make(Workload.GAMING, "laptop", "ac")
        self.assertEqual(Verifier(self.e.pub, self.e.obj).verify(t, "laptop"), (True, "ok"))
        self.assertFalse(t.is_generated)
        self.assertEqual(t.ops_name, "conductor")
        m = self.manifest()
        self.assertNotIn("artifact_dir", m.to_json())
        self.assertIsNone(forge.Manifest.from_json(m.to_json()).artifact_dir)

    def test_check_artifact_dir_is_fail_closed_on_garbage(self):
        m = self.manifest()
        with open(os.path.join(m.artifact_dir, "approval.json"), "w") as f:
            f.write("{not json")
        ok, why = check_artifact_dir(m.artifact_dir, m.body, self.e.pub)
        self.assertEqual((ok, why), (False, "no operator approval"))


if __name__ == "__main__":
    unittest.main()

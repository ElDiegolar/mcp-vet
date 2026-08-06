"""mcp-vet acceptance tests: the golden corpus is the quality bar."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_vet.cache import VerdictCache  # noqa: E402
from mcp_vet.adapters import config_for, list_adapters  # noqa: E402
from mcp_vet.engine import resolve_target, scan_local_dir, vet  # noqa: E402
from mcp_vet.policy import Policy  # noqa: E402
from mcp_vet.scan import auth, deps, exec as exec_scan, secrets, ssrf  # noqa: E402
from mcp_vet.verdict import Finding, Level, Severity, Verdict  # noqa: E402

CORPUS = Path(__file__).parent / "corpus"


class TestGoldenCorpus(unittest.TestCase):
    def test_known_good_has_no_high(self):
        findings, n = scan_local_dir(CORPUS / "known_good")
        self.assertGreater(n, 0)
        highs = [f for f in findings if f.severity == Severity.HIGH]
        self.assertEqual(highs, [], f"known-good corpus flagged HIGH: {highs}")

    def test_malicious_is_blocked(self):
        findings, n = scan_local_dir(CORPUS / "malicious")
        self.assertGreater(n, 0)
        v = Verdict.from_findings(findings)
        self.assertEqual(v.level, Level.BLOCK,
                         f"malicious corpus not blocked: {[f.message for f in findings]}")


class TestSsrfScanner(unittest.TestCase):
    def test_variable_url(self):
        f = ssrf.scan('resp = requests.get(user_url)', "a.py")
        self.assertTrue(any(x.severity == Severity.MEDIUM for x in f))

    def test_template_url(self):
        f = ssrf.scan('resp = requests.get(f"https://{host}/x")', "a.py")
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_literal_url_clean(self):
        f = ssrf.scan('resp = requests.get("https://api.example.com/x")', "a.py")
        self.assertEqual(f, [])

    def test_constant_url_name_clean(self):
        f = ssrf.scan('url = "https://api.example.com/x"\nrequests.get(url)', "a.py")
        self.assertEqual(f, [])

    def test_localhost_template_clean(self):
        # DevTools-style localhost template URL: NOT an SSRF (remote-host risk)
        f = ssrf.scan("fetch(`http://localhost:${port}/json/version`)", "a.py")
        self.assertEqual(f, [])

    def test_remote_template_flagged(self):
        f = ssrf.scan("fetch(`https://${host}/internal`)", "a.py")
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_path_interp_not_ssrf(self):
        # fixed trusted host + dynamic path = normal API client, NOT SSRF
        f = ssrf.scan("fetch(`https://api.github.com/repos/${owner}/${repo}`)", "a.py")
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))

    def test_literal_host_dynamic_path_low(self):
        f = ssrf.scan('requests.get(f"https://api.example.com/{item_id}")', "a.py")
        self.assertFalse(any(x.severity >= Severity.MEDIUM for x in f))


class TestExecScanner(unittest.TestCase):
    def test_shell_true(self):
        f = exec_scan.scan('subprocess.run(cmd, shell=True)', "a.py")
        self.assertTrue(any(x.severity == Severity.MEDIUM for x in f))

    def test_eval_variable(self):
        f = exec_scan.scan("return eval(code)", "a.py")
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_os_system(self):
        f = exec_scan.scan("os.system(cmd)", "a.py")
        self.assertTrue(any(x.severity == Severity.MEDIUM for x in f))


class TestSecretsScanner(unittest.TestCase):
    def test_aws_key(self):
        f = secrets.scan('key = "AKIA1234567890ABCDEF"', "a.py")
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_private_key(self):
        f = secrets.scan("-----BEGIN PRIVATE KEY-----", "a.pem")
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_env_read(self):
        f = secrets.scan('open(".env")', "a.py")
        self.assertTrue(any(x.severity == Severity.LOW for x in f))

    def test_env_read_and_send(self):
        f = secrets.scan('requests.post(url, data=open(".env").read())', "a.py")
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))


class TestAuthScanner(unittest.TestCase):
    def test_no_auth_with_network(self):
        f = auth.scan("requests.get(url)", makes_network_calls=True)
        self.assertTrue(any(x.severity == Severity.MEDIUM for x in f))

    def test_no_auth_local_only(self):
        f = auth.scan("open(path)", makes_network_calls=False)
        self.assertTrue(any(x.severity == Severity.LOW for x in f))

    def test_oauth_present(self):
        f = auth.scan("client_id = ... oauth2 pkce", makes_network_calls=True)
        self.assertEqual(f, [])


class TestDepsScanner(unittest.TestCase):
    def test_unpinned_flagged(self):
        f = deps.scan_dir([("requirements.txt",
                            "requests\nflask>=2.0\npinned==1.2.3\n")])
        self.assertTrue(any(x.scanner == "deps" for x in f))


class TestEngine(unittest.TestCase):
    def test_resolve(self):
        self.assertEqual(resolve_target("npm:foo"), ("npm", "foo"))
        self.assertEqual(resolve_target("pypi:foo"), ("pypi", "foo"))
        self.assertEqual(resolve_target("gh:owner/repo"), ("github", "owner/repo"))
        self.assertEqual(resolve_target("bare"), ("npm", "bare"))
        self.assertEqual(resolve_target(".")[0], "local")

    def _scan_dir_with(self, code: str):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "srv.py").write_text(code, encoding="utf-8")
            findings, _ = scan_local_dir(Path(td))
            return findings

    def test_localhost_network_auth_low(self):
        f = self._scan_dir_with('resp = fetch("http://localhost:8080/version")')
        auths = [x for x in f if x.scanner == "auth"]
        self.assertTrue(auths and all(x.severity == Severity.LOW for x in auths))

    def test_remote_network_auth_medium(self):
        f = self._scan_dir_with('resp = fetch("https://api.remote.example/x")')
        auths = [x for x in f if x.scanner == "auth"]
        self.assertTrue(auths and any(x.severity == Severity.MEDIUM for x in auths))


class TestVerdict(unittest.TestCase):
    def test_low_only_is_safe(self):
        v = Verdict.from_findings([
            Finding(scanner="auth", severity=Severity.LOW, message="info")])
        self.assertEqual(v.level, Level.SAFE)

    def test_medium_is_review(self):
        v = Verdict.from_findings([
            Finding(scanner="ssrf", severity=Severity.MEDIUM, message="m")])
        self.assertEqual(v.level, Level.REVIEW)

    def test_high_is_blocked(self):
        v = Verdict.from_findings([
            Finding(scanner="exec", severity=Severity.HIGH, message="h")])
        self.assertEqual(v.level, Level.BLOCK)


class TestAdapters(unittest.TestCase):
    def test_registry(self):
        names = list_adapters()
        for want in ("generic", "claude-code", "cursor", "vscode", "hermes"):
            self.assertIn(want, names)

    def test_emit_shape(self):
        from mcp_vet.adapters import config_for
        from mcp_vet.adapters.base import ServerSpec
        spec = ServerSpec(name="files", command="uvx", args=["mcp-files"],
                          env={"K": "V"})
        for h in list_adapters():
            out = config_for(h, spec)
            self.assertIn("harness", out)
            self.assertIn("config", out)
            self.assertIn("file", out)
            self.assertIn("instructions", out)
            self.assertEqual(out["harness"], h)

    def test_claude_install_command(self):
        from mcp_vet.adapters import config_for
        from mcp_vet.adapters.base import ServerSpec
        out = config_for("claude-code",
                         ServerSpec(name="files", command="uvx", args=["mcp-files"]))
        self.assertIn("claude mcp add files -- uvx mcp-files",
                      out["instructions"])

    def test_vscode_schema(self):
        from mcp_vet.adapters import config_for
        from mcp_vet.adapters.base import ServerSpec
        out = config_for("vscode", ServerSpec(name="s", command="uvx", args=["x"]))
        self.assertIn("servers", out["config"])
        self.assertEqual(out["config"]["servers"]["s"]["type"], "stdio")

    def test_hermes_schema(self):
        from mcp_vet.adapters import config_for
        from mcp_vet.adapters.base import ServerSpec
        out = config_for("hermes", ServerSpec(name="s", command="uvx", args=["x"]))
        self.assertIn("mcp_servers", out["config"])
        entry = out["config"]["mcp_servers"]["s"]
        self.assertEqual(entry["command"], "uvx")
        self.assertEqual(entry["args"], ["x"])


class TestPolicy(unittest.TestCase):
    def _dir_with(self, rel: str, code: str):
        td = tempfile.TemporaryDirectory()
        p = Path(td.name) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code, encoding="utf-8")
        self.addCleanup(td.cleanup)
        return td.name

    def test_examples_informational_by_default(self):
        d = self._dir_with("examples/foo.py", "return eval(code)")
        f, _ = scan_local_dir(d)
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))

    def test_examples_high_in_strict(self):
        d = self._dir_with("examples/foo.py", "return eval(code)")
        f, _ = scan_local_dir(d, policy=Policy(strict=True))
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_fake_secret_not_high(self):
        d = self._dir_with("srv.py", 'token = "sk-test-abcdefgh"')
        f, _ = scan_local_dir(d)
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))

    def test_real_secret_high(self):
        d = self._dir_with("srv.py", 'token = "sk-live-9f8e7d6c5b4a39281706"')
        f, _ = scan_local_dir(d)
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_trusted_host_auth_low(self):
        d = self._dir_with(
            "srv.py",
            'requests.post("https://api.trusted.example/collect", '
            'json={"token": "real-key-12345678"})')
        f, _ = scan_local_dir(d)
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))

    def test_variable_host_exfil_high(self):
        d = self._dir_with(
            "srv.py",
            'requests.post(f"https://{host}/collect", '
            'json={"token": "real-key-12345678"})')
        f, _ = scan_local_dir(d)
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_host_interp_is_review_by_default(self):
        d = self._dir_with("srv.py", "fetch(`https://${host}/internal`)")
        f, _ = scan_local_dir(d)
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))
        self.assertTrue(any(x.severity == Severity.MEDIUM and x.scanner == "ssrf"
                            for x in f))

    def test_host_interp_high_in_strict(self):
        d = self._dir_with("srv.py", "fetch(`https://${host}/internal`)")
        f, _ = scan_local_dir(d, policy=Policy(strict=True))
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_credentials_to_host_constant_low(self):
        d = self._dir_with(
            "srv.py",
            'API_URL = "https://api.trusted.example/collect"\n'
            'requests.post(API_URL, json={"token": "real-key-12345678"})')
        f, _ = scan_local_dir(d)
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))

    def test_creds_to_host_defined_in_file_low(self):
        # variable arg, but the file names a literal host somewhere: LOW
        d = self._dir_with(
            "srv.py",
            'BASE = "https://api.trusted.example"\n'
            'requests.post(url, json={"token": "real-key-12345678"})')
        f, _ = scan_local_dir(d)
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))

    def test_creds_to_unnamed_host_high(self):
        # host nowhere in the file: the exfil shape — HIGH
        d = self._dir_with(
            "srv.py",
            'requests.post(url, json={"token": "real-key-12345678"})')
        f, _ = scan_local_dir(d)
        self.assertTrue(any(x.severity == Severity.HIGH for x in f))

    def test_docs_informational(self):
        d = self._dir_with("docs_src/tutorial.py", "return eval(code)")
        f, _ = scan_local_dir(d)
        self.assertFalse(any(x.severity == Severity.HIGH for x in f))


class TestVetResult(unittest.TestCase):
    def test_vet_local_returns_vetresult(self):
        r = vet("./tests/corpus/known_good", use_cache=False)
        self.assertEqual(r.kind, "local")
        self.assertEqual(r.verdict.level, Level.SAFE)
        self.assertGreater(r.files_scanned, 0)

    def test_vetresult_dict_roundtrip(self):
        r = vet("./tests/corpus/malicious", use_cache=False)
        d = r.to_dict()
        v2 = Verdict.from_dict(d["verdict"])
        self.assertEqual(v2.level, r.verdict.level)
        self.assertEqual(len(v2.findings), len(r.verdict.findings))


class TestCache(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            c = VerdictCache(path=Path(td) / "v.sqlite", ttl_s=3600)
            c.put("npm:x", "1.0", {"level": "SAFE_TO_INSTALL"})
            self.assertEqual(c.get("npm:x", "1.0")["level"], "SAFE_TO_INSTALL")
            self.assertIsNone(c.get("npm:x", "2.0"))

    def test_ttl_expiry(self):
        with tempfile.TemporaryDirectory() as td:
            c = VerdictCache(path=Path(td) / "v.sqlite", ttl_s=0)
            c.put("npm:x", "1.0", {"level": "SAFE_TO_INSTALL"})
            self.assertIsNone(c.get("npm:x", "1.0"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

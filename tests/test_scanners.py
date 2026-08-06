"""mcp-vet acceptance tests: the golden corpus is the quality bar."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_vet.cache import VerdictCache  # noqa: E402
from mcp_vet.engine import resolve_target, scan_local_dir  # noqa: E402
from mcp_vet.scan import auth, deps, exec as exec_scan, secrets, ssrf  # noqa: E402
from mcp_vet.verdict import Level, Severity, Verdict  # noqa: E402

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
        self.assertTrue(any(x.severity == Severity.MEDIUM for x in f))


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

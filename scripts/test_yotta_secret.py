#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yotta-secret（元钥）单元测试。

运行（在技能目录内）：python scripts/test_yotta_secret.py
或（仓库根）：python yottaskills/yotta-secret/scripts/test_yotta_secret.py
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yotta_secret as ys

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yotta_secret.py")


def run_cli(*args, stdin=None):
    """以子进程方式运行 CLI（Windows 下也保证 UTF-8 输出）。"""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, SCRIPT] + list(args),
        input=stdin, capture_output=True, encoding="utf-8", errors="replace", env=env,
    )


def scan_text(text, show_secret=False, min_length=8):
    opts = types.SimpleNamespace(show_secret=show_secret, min_entropy=3.5, min_length=min_length)
    return ys.scan_text(text, "<test>", opts)


def rule_ids(text, show_secret=False):
    return [f["rule_id"] for f in scan_text(text, show_secret)]


def secrets_of(text, show_secret=False):
    return [f["secret"] for f in scan_text(text, show_secret)]


class TestEntropy(unittest.TestCase):
    def test_single_char_zero(self):
        self.assertAlmostEqual(ys.shannon_entropy("aaaa"), 0.0, places=4)
        self.assertAlmostEqual(ys.shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0, places=4)

    def test_two_chars_one_bit(self):
        self.assertAlmostEqual(ys.shannon_entropy("abababab"), 1.0, places=4)

    def test_four_chars_two_bits(self):
        self.assertAlmostEqual(ys.shannon_entropy("abcd"), 2.0, places=4)

    def test_hex_string_four_bits(self):
        self.assertAlmostEqual(ys.shannon_entropy("0123456789abcdef"), 4.0, places=4)

    def test_empty(self):
        self.assertEqual(ys.shannon_entropy(""), 0.0)


class TestPlaceholder(unittest.TestCase):
    def test_placeholders_true(self):
        for v in ("<your-password>", "your_password", "xxx", "***", "changeme",
                  "replace_me", "example", "example123", "dummy", "test", "demo",
                  "null", "none", "true", "false", "1234", "password", "secret",
                  "token", "api_key", "$DB_PASSWORD", "os.environ['X']",
                  "process.env.X", "getenv('X')", "todo"):
            self.assertTrue(ys.is_placeholder(v), v)

    def test_braced_env_placeholder(self):
        self.assertTrue(ys.is_placeholder("$" + "{DB_PASSWORD}"))

    def test_real_values_false(self):
        for v in ("Sup3rS3cret!123", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                  "ghp_abcdefghijklmnopqrstuvwxyz1234567890", "p@ssW0rd2024",
                  "abcdefghij1234567890!@#", "Tr0ub4dor&3"):
            self.assertFalse(ys.is_placeholder(v), v)


class TestMaskSecret(unittest.TestCase):
    def test_short(self):
        self.assertEqual(ys.mask_secret("abc"), "****")
        self.assertEqual(ys.mask_secret("abcdefgh"), "****")

    def test_long(self):
        v = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        m = ys.mask_secret(v)
        self.assertTrue(m.startswith("ghp_"))
        self.assertTrue(m.endswith("7890"))
        self.assertIn("****", m)
        self.assertNotIn("abcdefghijk", m)


class TestCloudRules(unittest.TestCase):
    def test_aws_access_key(self):
        self.assertIn("aws_access_key", rule_ids("AKIAIOSFODNN7EXAMPLE"))
        self.assertIn("aws_access_key", rule_ids("key = ASIAABCDEFGHIJKLMNOP"))
        self.assertNotIn("aws_access_key", rule_ids("AKIAIOSFODNN7"))  # 太短

    def test_aws_secret(self):
        ids = rule_ids("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        self.assertIn("aws_secret", ids)
        self.assertNotIn("aws_secret", rule_ids("aws_secret_access_key = x"))

    def test_google_api(self):
        self.assertIn("google_api", rule_ids("AIzaSyA1234567890abcdefghijklmnopqrstuv"))
        self.assertNotIn("google_api", rule_ids("AIzaSyA12345"))  # 太短

    def test_openai_not_anthropic(self):
        self.assertIn("openai", rule_ids("sk-abcdefghijklmnopqrstuvwxyz123456"))
        self.assertNotIn("anthropic", rule_ids("sk-abcdefghijklmnopqrstuvwxyz123456"))

    def test_anthropic(self):
        ids = rule_ids("sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456789")
        self.assertIn("anthropic", ids)
        self.assertNotIn("openai", ids)

    def test_stripe(self):
        self.assertIn("stripe", rule_ids("sk_live_abcdefghijklmnopqrstuvwx"))
        self.assertIn("stripe", rule_ids("pk_test_abcdefghijklmnopqrstuvwx"))

    def test_slack(self):
        self.assertIn("slack", rule_ids("xoxb-123456789012-123456789012-abcdefghijklmnop"))
        self.assertIn("slack", rule_ids("xoxp-1234567890-1234567890-1234567890-abcd"))

    def test_github(self):
        self.assertIn("github", rule_ids("ghp_abcdefghijklmnopqrstuvwxyz1234567890"))
        self.assertIn("github", rule_ids("github_pat_abcdefghijklmnopqrstuvwxyz1234567890"))
        self.assertNotIn("github", rule_ids("ghp_short"))

    def test_gitlab(self):
        self.assertIn("gitlab", rule_ids("glpat-abcdefghijklmnopqrstuvwx"))

    def test_npm(self):
        self.assertIn("npm_token", rule_ids("npm_abcdefghijklmnopqrstuvwxyz1234567890"))
        self.assertNotIn("npm_token", rule_ids("npm_short"))

    def test_pypi(self):
        tok = "pypi-AgEIcHlwaS5vcmc" + "x" * 60
        self.assertIn("pypi_token", rule_ids(tok))

    def test_telegram(self):
        self.assertIn("telegram_bot", rule_ids("123456789:AAH" + "q" * 32))

    def test_jwt(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        ids = rule_ids(jwt)
        self.assertIn("jwt", ids)
        # generic 不应重复报
        self.assertNotIn("generic", ids)

    def test_huggingface(self):
        self.assertIn("huggingface", rule_ids("hf_abcdefghijklmnopqrstuvwxyz1234567890"))

    def test_notion(self):
        self.assertIn("notion", rule_ids("secret_abcdefghijklmnopqrstuvwxyz1234567890123456"))
        self.assertIn("notion", rule_ids("ntn_abcdefghijklmnopqrstuvwxyz123456"))

    def test_shopify(self):
        self.assertIn("shopify", rule_ids("shpat_0123456789abcdef0123456789abcdef"))

    def test_sendgrid(self):
        key = "SG." + "a" * 22 + "." + "b" * 43
        self.assertIn("sendgrid", rule_ids(key))

    def test_twilio(self):
        self.assertIn("twilio", rule_ids("SK0123456789abcdef0123456789abcdef"))

    def test_mailgun(self):
        self.assertIn("mailgun", rule_ids("key-abcdefghijklmnopqrstuvwxyz123456"))

    def test_sendinblue(self):
        key = "xkeysib-" + "a" * 64 + "-" + "b" * 16
        self.assertIn("sendinblue", rule_ids(key))

    def test_digitalocean(self):
        self.assertIn("digitalocean", rule_ids("dop_v1_" + "a" * 64))

    def test_pagerduty(self):
        self.assertIn("pagerduty", rule_ids("pdus_abcdefghijklmnopqrstuvwxyz"))

    def test_azure_storage(self):
        key = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + "A" * 88
        self.assertIn("azure_storage", rule_ids(key))

    def test_bearer(self):
        self.assertIn("bearer", rule_ids("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"))

    def test_basic_auth(self):
        # base64("user:password")
        self.assertIn("basic_auth", rule_ids("Authorization: Basic dXNlcjpwYXNzd29yZA=="))
        # 非 user:pass 的 base64 不应命中
        self.assertNotIn("basic_auth", rule_ids("Authorization: Basic aGVsbG93b3JsZA=="))


class TestPrivateKey(unittest.TestCase):
    PEM_RSA = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1T7X8qQ0QmQ8nX0d4vY6QbG6sM0Wq1sH4nJq9hVZ7yK2z\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    PEM_OPENSSH = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAEAAAABAAAAMwAAAAtzc2gtZWQy\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    PGP = (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "lQOYBF4xyzAAAAD9uZGVzLmNvbSA8aGVscEBleGFtcGxlLmNvbT6JARwEEAECAAYFAl+M\n"
        "-----END PGP PRIVATE KEY BLOCK-----\n"
    )

    def test_pem_rsa(self):
        ids = rule_ids(self.PEM_RSA)
        self.assertIn("pem_private", ids)
        self.assertIn("private_key", {f["category"] for f in scan_text(self.PEM_RSA)})

    def test_pem_openssh(self):
        self.assertIn("pem_private", rule_ids(self.PEM_OPENSSH))

    def test_pem_masked_by_default(self):
        secs = secrets_of(self.PEM_RSA)
        self.assertTrue(all("REDACTED" in s or "****" in s for s in secs))

    def test_pgp(self):
        self.assertIn("pgp_private", rule_ids(self.PGP))

    def test_putty_ppk(self):
        ppk = ("PuTTY-User-Key-File-2: ssh-rsa\n"
               "Encryption: none\n"
               "Comment: test\n"
               "Public-Lines: 4\n"
               "AAAA...\n"
               "Private-Lines: 4\n"
               "MIIEowIBAAKCAQEA...\n")
        self.assertIn("putty_ppk", rule_ids(ppk))


class TestCredential(unittest.TestCase):
    def test_password_assignment(self):
        self.assertIn("credential", rule_ids("password = Sup3rS3cret!123"))

    def test_db_password(self):
        self.assertIn("credential", rule_ids("DB_PASSWORD='p@ssW0rd!2024x'"))

    def test_env_file(self):
        self.assertIn("credential", rule_ids("MYAPP_SECRET=abcdefghijklmnopqrstuvwxyz123"))

    def test_yaml_style(self):
        self.assertIn("credential", rule_ids("  client_secret: 'S0meSecretV4lue!!'"))

    def test_npmrc(self):
        self.assertIn("credential", rule_ids("//registry.npmjs.org/:_authToken=abcdefghijklmnopqrstuvwxyz123"))

    def test_short_value_ignored(self):
        self.assertNotIn("credential", rule_ids("password = ab"))

    def test_placeholder_ignored(self):
        self.assertNotIn("credential", rule_ids("password = <your-password>"))
        self.assertNotIn("credential", rule_ids("api_key = xxx"))
        self.assertNotIn("credential", rule_ids("token = changeme"))
        self.assertNotIn("credential", rule_ids("secret = $ENV_VAR"))

    def test_token_medium_confidence_short_low_entropy_ignored(self):
        self.assertNotIn("credential", rule_ids("token = abcdefgh"))  # 8 位低熵

    def test_token_long_flagged(self):
        self.assertIn("credential", rule_ids("token = abcdefghijklmnopqrstuvwxyz123456"))


class TestUrlUserinfo(unittest.TestCase):
    def test_http_basic(self):
        ids = rule_ids("https://admin:hunter2@example.com/db")
        self.assertIn("url_userinfo", ids)
        self.assertEqual(secrets_of("https://admin:hunter2@example.com/db", True)[0], "hunter2")

    def test_mongo(self):
        self.assertIn("url_userinfo", rule_ids("mongodb://app:secret123@db.internal:27017/app"))

    def test_jdbc(self):
        self.assertIn("url_userinfo",
                      rule_ids("jdbc:mysql://root:pw123456@localhost:3306/app"))

    def test_plain_url_no_match(self):
        self.assertNotIn("url_userinfo", rule_ids("https://example.com/path?q=1"))

    def test_placeholder_user_ignored(self):
        self.assertNotIn("url_userinfo", rule_ids("https://user:pass123@example.com/db"))


class TestGeneric(unittest.TestCase):
    def test_high_entropy_token(self):
        v = "Xj8mQp2Lw4Nv6Rz9Tb1Cd3Ef5Gh7Jk0Mn"
        self.assertIn("generic", rule_ids(v))

    def test_pure_hex_hash_ignored(self):
        self.assertNotIn("generic", rule_ids("a" * 64))
        self.assertNotIn("generic", rule_ids("0123456789abcdef" * 4))

    def test_uuid_ignored(self):
        self.assertNotIn("generic", rule_ids("123e4567-e89b-12d3-a456-426614174000"))

    def test_low_entropy_ignored(self):
        self.assertNotIn("generic", rule_ids("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

    def test_known_prefix_dedup(self):
        # github token 已由具体规则命中，generic 不重复
        ids = rule_ids("ghp_" + "a" * 40)
        self.assertIn("github", ids)
        self.assertNotIn("generic", ids)


class TestDedupe(unittest.TestCase):
    def test_same_secret_two_rules_one_finding(self):
        # api_key = <google key> 会同时命中 credential 与 google_api，只保留一条
        line = "api_key = AIzaSyA1234567890abcdefghijklmnopqrstuv"
        findings = scan_text(line)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "google_api")

    def test_two_secrets_same_line(self):
        line = "a=AKIAIOSFODNN7EXAMPLE b=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        findings = scan_text(line)
        ids = {f["rule_id"] for f in findings}
        self.assertIn("aws_access_key", ids)
        self.assertIn("github", ids)


class TestScanCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yotta-secret-test-")
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, content, binary=False):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        mode = "wb" if binary else "w"
        kwargs = {} if binary else {"encoding": "utf-8"}
        with open(p, mode, **kwargs) as f:
            f.write(content)
        return p

    def test_clean_dir_exit_zero(self):
        self.write("app.py", "print('hello')\n")
        r = run_cli("scan", "--path", self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("未发现疑似密钥", r.stdout)

    def test_find_env_secrets(self):
        self.write(".env", "DB_PASSWORD='Sup3rS3cret!123'\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n")
        r = run_cli("scan", "--path", self.root, "--show-secret", "--format", "json")
        self.assertEqual(r.returncode, 1, r.stderr)
        data = json.loads(r.stdout)
        self.assertGreaterEqual(data["summary"]["total"], 2)
        ids = {f["rule_id"] for f in data["findings"]}
        self.assertIn("credential", ids)
        self.assertIn("github", ids)

    def test_masked_by_default(self):
        self.write(".env", "DB_PASSWORD='Sup3rS3cret!123'\n")
        r = run_cli("scan", "--path", self.root, "--format", "json")
        data = json.loads(r.stdout)
        self.assertNotIn("Sup3rS3cret!123", data["findings"][0]["secret"])

    def test_show_secret(self):
        self.write(".env", "DB_PASSWORD='Sup3rS3cret!123'\n")
        r = run_cli("scan", "--path", self.root, "--show-secret", "--format", "json")
        data = json.loads(r.stdout)
        self.assertEqual(data["findings"][0]["secret"], "Sup3rS3cret!123")

    def test_types_filter(self):
        self.write(".env", "DB_PASSWORD='Sup3rS3cret!123'\n")
        self.write("key.txt", "AKIAIOSFODNN7EXAMPLE\n")
        r = run_cli("scan", "--path", self.root, "--types", "credential", "--format", "json")
        data = json.loads(r.stdout)
        cats = {f["category"] for f in data["findings"]}
        self.assertEqual(cats, {"credential"})

    def test_exclude_pattern(self):
        self.write("skip.env", "DB_PASSWORD='Sup3rS3cret!123'\n")
        r = run_cli("scan", "--path", self.root, "--exclude", "*.env")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_node_modules_skipped(self):
        self.write("node_modules/pkg/index.js", "DB_PASSWORD='Sup3rS3cret!123'\n")
        self.write("app.js", "console.log(1)\n")
        r = run_cli("scan", "--path", self.root)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_binary_skipped(self):
        self.write("img.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00secret=Sup3rS3cret!123", binary=True)
        r = run_cli("scan", "--path", self.root)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_stdin_mode(self):
        r = run_cli("scan", "--stdin", "--show-secret",
                    stdin="password = Sup3rS3cret!123\n")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("Sup3rS3cret!123", r.stdout)

    def test_csv_output(self):
        self.write(".env", "DB_PASSWORD='Sup3rS3cret!123'\n")
        r = run_cli("scan", "--path", self.root, "--format", "csv")
        self.assertEqual(r.returncode, 1, r.stderr)
        lines = r.stdout.strip().splitlines()
        self.assertEqual(lines[0].split(",")[0], "rule_id")
        self.assertGreaterEqual(len(lines), 2)

    def test_output_file(self):
        self.write(".env", "DB_PASSWORD='Sup3rS3cret!123'\n")
        out = os.path.join(self.root, "report.json")
        r = run_cli("scan", "--path", self.root, "--format", "json", "--output", out)
        self.assertEqual(r.returncode, 1, r.stderr)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["tool"], "yotta-secret")

    def test_no_input_exit_four(self):
        r = run_cli("scan")
        self.assertEqual(r.returncode, 4)
        self.assertIn("用法错误", r.stderr)

    def test_missing_path_warns(self):
        r = run_cli("scan", "--path", os.path.join(self.root, "nope"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("路径不存在", r.stderr)


class TestVerifyCLI(unittest.TestCase):
    def test_github_likely_secret(self):
        r = run_cli("verify", "--value", "ghp_" + "a" * 40)
        self.assertEqual(r.returncode, 1)
        self.assertIn("likely_secret", r.stdout)

    def test_clean_value(self):
        r = run_cli("verify", "--value", "hello")
        self.assertEqual(r.returncode, 0)
        self.assertIn("no_match", r.stdout)

    def test_json_output(self):
        r = run_cli("verify", "--value", "hello", "--format", "json")
        data = json.loads(r.stdout)
        self.assertEqual(data["results"][0]["verdict"], "no_match")

    def test_stdin_list(self):
        r = run_cli("verify", "--stdin", stdin="hello\nglpat-abcdefghijklmnopqrstuvwx\n")
        self.assertEqual(r.returncode, 1)
        lines = r.stdout.strip().splitlines()
        self.assertEqual(len(lines), 2)

    def test_no_value_exit_four(self):
        r = run_cli("verify")
        self.assertEqual(r.returncode, 4)


class TestMaskCLI(unittest.TestCase):
    def test_masks_secret(self):
        r = run_cli("mask", "--stdin",
                    stdin="key: sk-abcdefghijklmnopqrstuvwxyz123456\n")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", r.stdout)
        self.assertIn("***", r.stdout)

    def test_masks_credential_assignment(self):
        r = run_cli("mask", "--stdin", stdin="password = Sup3rS3cret!123\n")
        self.assertIn("password = ***", r.stdout)
        self.assertNotIn("Sup3rS3cret!123", r.stdout)

    def test_preserves_url(self):
        r = run_cli("mask", "--stdin",
                    stdin="see https://example.com/page?q=1 token=abcdefghijklmnopqrst\n")
        self.assertIn("https://example.com/page?q=1", r.stdout)

    def test_masks_pem(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n"
        r = run_cli("mask", "--stdin", stdin=pem)
        self.assertNotIn("MIIEow==", r.stdout)


class TestEntropyCLI(unittest.TestCase):
    def test_value(self):
        r = run_cli("entropy", "--value", "abcd")
        self.assertEqual(r.returncode, 0)
        self.assertAlmostEqual(float(r.stdout.strip()), 2.0, places=3)

    def test_stdin(self):
        r = run_cli("entropy", "--stdin", stdin="abcd\n0123456789abcdef\n")
        vals = [float(x) for x in r.stdout.strip().splitlines()]
        self.assertEqual(len(vals), 2)

    def test_no_value_exit_four(self):
        r = run_cli("entropy")
        self.assertEqual(r.returncode, 4)


    def test_suffixed_key_flagged(self):
        self.assertIn("credential", rule_ids("MYAPP_SECRET=abcdefghijklmnopqrstuvwxyz123"))
        self.assertIn("credential", rule_ids("GOOGLE_CLIENT_SECRET='S0meSecretV4lue!!'"))

    def test_value_equals_keyname_ignored(self):
        self.assertNotIn("credential", rule_ids("password = password"))
        self.assertNotIn("credential", rule_ids("secret = SECRET"))


class TestGitScanCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yotta-secret-git-")
        self.root = self.tmp.name
        env = dict(os.environ)
        env["GIT_AUTHOR_NAME"] = "t"
        env["GIT_AUTHOR_EMAIL"] = "t@example.com"
        env["GIT_COMMITTER_NAME"] = "t"
        env["GIT_COMMITTER_EMAIL"] = "t@example.com"
        self.env = env

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", self.root] + list(args),
                              capture_output=True, env=self.env)

    def test_git_history_finds_secret(self):
        self.git("init", "-q")
        with open(os.path.join(self.root, "app.py"), "w", encoding="utf-8") as f:
            f.write("DB_PASSWORD = 'Sup3rS3cret!123'\n")
        self.git("add", ".")
        r = self.git("commit", "-q", "-m", "init")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        r = run_cli("scan", "--git", "--path", self.root, "--format", "json", "--show-secret")
        self.assertEqual(r.returncode, 1, r.stderr)
        data = json.loads(r.stdout)
        self.assertGreaterEqual(data["summary"]["total"], 1)
        self.assertTrue(any(f["commit"] for f in data["findings"]))
        self.assertTrue(any(f["file"] == "app.py" and f["path_in_commit"] == "app.py"
                            for f in data["findings"]))

    def test_git_clean_history_exit_zero(self):
        self.git("init", "-q")
        with open(os.path.join(self.root, "app.py"), "w", encoding="utf-8") as f:
            f.write("print('hello')\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "init")
        r = run_cli("scan", "--git", "--path", self.root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_not_a_repo_exit_four(self):
        empty = tempfile.mkdtemp(prefix="yotta-secret-nogit-")
        try:
            r = run_cli("scan", "--git", "--path", empty)
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        finally:
            import shutil
            shutil.rmtree(empty, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

class TestMisc(unittest.TestCase):
    def test_version(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "yotta-secret 0.1.1")

    def test_no_command_exit_four(self):
        r = run_cli()
        self.assertEqual(r.returncode, 4)

    def test_read_text_gbk(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.txt")
            with open(p, "w", encoding="gbk") as f:
                f.write("password = 12345678abc")
            text = ys.read_text(p, 10 * 1024 * 1024)
            self.assertIsNotNone(text)
            self.assertIn("password", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)

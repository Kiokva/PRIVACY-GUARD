import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import privacy_guard as pg  # noqa: E402

# Everything below is fictional, and secret-shaped values are assembled at
# runtime so this file never contains a real-looking secret.
FAKE_NAME = "Jane Q Testperson"
FAKE_AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
FAKE_GH = "gh" + "p_" + "a1b2c3d4e5" * 4
FAKE_HOME = "/Us" + "ers/janetest/project"
FAKE_PASS = "Sup3r" + "S3cret" + "Value99"


def git(root, *args):
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.com", *args],
                   cwd=root, check=True, capture_output=True)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def scan(self, **kw):
        kw.setdefault("system", False)
        kw.setdefault("history", False)
        return pg.scan(self.root, **kw)

    def categories(self, result):
        return {f["category"] for f in result["findings"]}

    def test_clean_project(self):
        self.write("a.py", "print('hello world')\n")
        self.assertEqual(self.scan()["findings"], [])

    def test_custom_term_found_and_masked(self):
        self.write("notes.txt", f"written by {FAKE_NAME}\n")
        r = self.scan(extra_terms=[FAKE_NAME])
        self.assertEqual(r["findings"][0]["severity"], pg.HIGH)
        self.assertNotIn(FAKE_NAME, json.dumps(r))

    def test_term_match_is_case_insensitive_and_whole_word(self):
        self.write("a.txt", "Hello JANETEST here\nmachine and macro\n")
        r = self.scan(extra_terms=["janetest", "zed"])
        self.assertEqual(len(r["findings"]), 1)

    def test_short_term_is_medium(self):
        self.write("a.txt", "ask bob about it\n")
        self.assertEqual(self.scan(extra_terms=["bob"])["findings"][0]["severity"], pg.MEDIUM)

    def test_short_term_ignores_ordinary_capitalised_word(self):
        self.write("a.txt", "the ZED address and Bob's idea\n")
        self.assertEqual(self.scan(extra_terms=["zed", "bob"])["findings"], [])

    def test_placeholder_hardware_address_ignored_real_one_flagged(self):
        self.write("a.txt", "aa:bb:cc:dd:ee:ff and 00:11:22:33:44:55\nreal 3c:22:fb:7a:91:0d\n")
        found = [f for f in self.scan()["findings"] if f["category"] == "MAC address"]
        self.assertEqual(len(found), 1)

    def test_emails(self):
        lines = ["jane@realmail.net", "noreply@anthropic.com", "12345+jane@users.noreply.github.com", "x@example.com"]
        self.write("a.txt", "\n".join(lines) + "\n")
        found = [f for f in self.scan()["findings"] if f["category"] == "email address"]
        self.assertEqual(len(found), 1)

    def test_home_path_flagged_placeholder_not(self):
        self.write("a.txt", f"cd {FAKE_HOME}\ncd /Us" + "ers/<you>/x\ncd /home/user/x\n")
        found = [f for f in self.scan()["findings"] if f["category"] == "home folder path"]
        self.assertEqual(len(found), 1)

    def test_secrets(self):
        self.write("a.txt", f"key = {FAKE_AWS}\ntoken: {FAKE_GH}\nAPI_KEY='your-key-here-123'\n")
        cats = self.categories(self.scan())
        self.assertIn("secret: AWS access key", cats)
        self.assertIn("secret: GitHub token", cats)

    def test_hardcoded_password_flagged_placeholder_ignored(self):
        self.write("a.py", f"password = '{FAKE_PASS}'\npassword = 'changeme-please-12'\n")
        found = [f for f in self.scan()["findings"] if f["category"] == "secret: hard-coded credential"]
        self.assertEqual(len(found), 1)

    def test_ip_addresses(self):
        self.write("a.txt", "dns 8.8.8.8\ndoc 203.0.113.9\nlan 192.168.1.20\nwan 91.215.85.17\nlocal 127.0.0.1\n")
        cats = self.categories(self.scan())
        self.assertEqual(cats, {"private network address", "public IP address"})
        self.assertTrue(all(f["severity"] == pg.LOW for f in self.scan()["findings"]))

    def test_term_inside_base64_is_found(self):
        blob = base64.b64encode(f"owner: {FAKE_NAME}, please do not share".encode()).decode()
        self.write("hidden.txt", f"data = {blob}\n")
        r = self.scan(extra_terms=[FAKE_NAME])
        self.assertTrue(any("base64" in f["category"] for f in r["findings"]))

    def test_term_inside_multiline_base64_block(self):
        blob = base64.b64encode((f"padding line. " * 6 + FAKE_NAME).encode()).decode()
        wrapped = "\n".join(blob[i:i + 40] for i in range(0, len(blob), 40))
        self.write("mail.eml", f"Content-Transfer-Encoding: base64\n\n{wrapped}\n")
        r = self.scan(extra_terms=[FAKE_NAME])
        self.assertTrue(any("base64" in f["category"] for f in r["findings"]))

    def test_allow_list_hides_fictional_emails_only(self):
        self.write("a.txt", f"demo victim@fake-corp.test2.net\nreal {FAKE_AWS}\nme {FAKE_NAME}\n")
        r = self.scan(extra_terms=[FAKE_NAME], allow=["fake-corp", FAKE_AWS, FAKE_NAME])
        cats = self.categories(r)
        self.assertNotIn("email address", cats)
        self.assertIn("secret: AWS access key", cats)   # secrets can never be allowed
        self.assertIn("your custom term", cats)         # neither can your identity

    def test_allow_file_in_project(self):
        self.write("a.txt", "mail ops@fake-corp.test2.net\n")
        self.write(".privacyguard-allow", "# fictional demo data\nfake-corp\n")
        self.assertEqual(self.scan()["findings"], [])

    def test_binary_files_are_skipped(self):
        (self.root / "blob.bin").write_bytes(b"\0\1\2" + FAKE_NAME.encode())
        self.assertEqual(self.scan(extra_terms=[FAKE_NAME])["findings"], [])


class GitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        git(self.root, "init", "-q", "-b", "main")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, msg, author="t@example.com"):
        git(self.root, "add", "-A")
        git(self.root, "-c", f"user.email={author}", "commit", "-q", "-m", msg)

    def test_removed_secret_still_found_in_history(self):
        f = self.root / "a.txt"
        f.write_text(f"key = {FAKE_AWS}\n")
        self.commit("add")
        f.write_text("nothing here\n")
        self.commit("remove")
        now = pg.scan(self.root, system=False, history=False)
        past = pg.scan(self.root, system=False, history=True)
        self.assertEqual(now["findings"], [])
        self.assertTrue(any("history" in x["where"] for x in past["findings"]))

    def test_commit_author_email_flagged(self):
        (self.root / "a.txt").write_text("hi\n")
        self.commit("add", author="jane@realmail.net")
        r = pg.scan(self.root, system=False, history=True)
        self.assertIn("commit author email", {x["category"] for x in r["findings"]})

    def test_noreply_author_is_fine(self):
        (self.root / "a.txt").write_text("hi\n")
        self.commit("add", author="123+jane@users.noreply.github.com")
        self.assertEqual(pg.scan(self.root, system=False, history=True)["findings"][0:0], [])
        cats = {x["category"] for x in pg.scan(self.root, system=False, history=True)["findings"]}
        self.assertNotIn("commit author email", cats)

    def test_gitignored_files_are_not_scanned(self):
        (self.root / ".gitignore").write_text(".env\n")
        (self.root / ".env").write_text(f"key = {FAKE_AWS}\n")
        (self.root / "a.txt").write_text("hi\n")
        self.commit("add")
        self.assertEqual(pg.scan(self.root, system=False, history=True)["findings"], [])


class CliTests(unittest.TestCase):
    def setUp(self):
        import contextlib
        import io
        self._quiet = contextlib.redirect_stdout(io.StringIO())
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.txt").write_text("fine\n")
            self.assertEqual(pg.main([d, "--no-history"]), 0)
            (Path(d) / "b.txt").write_text(f"{FAKE_AWS}\n")
            self.assertEqual(pg.main([d, "--no-history"]), 1)

    def test_low_findings_only_block_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.txt").write_text("server 91.215.85.17\n")
            self.assertEqual(pg.main([d, "--no-history"]), 0)
            self.assertEqual(pg.main([d, "--no-history", "--strict"]), 1)


if __name__ == "__main__":
    unittest.main()

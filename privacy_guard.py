#!/usr/bin/env python3
"""privacy-guard - find your own private details before you publish a project.

It scans a folder (and its git history) for things that identify you: your
name, hostname, local IP, git identity, home-folder path, email addresses,
and leaked secrets such as API keys. Matches are masked in the report, so the
report itself is safe to share. Everything runs locally; nothing is uploaded.

    python3 privacy_guard.py .                 # scan this folder + git history
    python3 privacy_guard.py . --install-hook  # block `git push` when it finds something
"""
import argparse
import base64
import getpass
import ipaddress
import json
import os
import re
import socket
import string
import subprocess
import sys
from pathlib import Path

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}
MAX_BYTES = 2_000_000
TERMS_FILE = Path.home() / ".config" / "privacy-guard" / "terms.txt"

SAFE_EMAIL_DOMAINS = {"users.noreply.github.com", "noreply.github.com", "example.com",
                      "example.org", "example.net", "localhost"}
SAFE_EMAIL_SUFFIXES = (".test", ".invalid", ".example", ".localhost")
SAFE_EMAIL_LOCALS = {"noreply", "no-reply", "donotreply", "do-not-reply"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
KNOWN_PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}
PLACEHOLDER_USERS = {"user", "username", "you", "yourname", "name", "example", "shared", "public",
                     "runner", "ubuntu", "root", "default", "admin", "me", "foo", "bar", "test"}

EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
HOME_PATH = re.compile(r"(?:/Users|/home)/([A-Za-z0-9][\w.\-]*)|[A-Za-z]:\\Users\\([A-Za-z0-9][\w.\-]*)")
B64_INLINE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
B64_LINE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
B64_TAIL = re.compile(r"^[A-Za-z0-9+/]{2,}={0,2}$")

SECRETS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("API secret key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
]
SECRET_ASSIGN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|passwd|password|pwd)\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-+/=.]{12,})")
PLACEHOLDER_HINTS = ("example", "your", "xxx", "changeme", "placeholder", "dummy", "sample", "${", "<")


def mask(value: str) -> str:
    value = value.strip()
    return "***" if len(value) <= 4 else value[:2] + "*" * min(len(value) - 4, 12) + value[-2:]


def run(cmd, cwd=None) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd=cwd)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def term_regex(term: str):
    # short names are matched case-sensitively so a login like "bob" doesn't hit the word "BOB" or "Bob's"
    flags = 0 if len(term) < 5 else re.I
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", flags)


def is_placeholder_hw(addr: str) -> bool:
    """aa:bb:cc:dd:ee:ff, 00:11:22:33:44:55 and similar documentation values."""
    nums = [int(b, 16) for b in re.split(r"[:-]", addr)]
    steps = {nums[i + 1] - nums[i] for i in range(5)}
    return len(set(nums)) <= 2 or len(steps) == 1


def safe_email(addr: str) -> bool:
    local, _, domain = addr.lower().rpartition("@")
    return (domain in SAFE_EMAIL_DOMAINS or domain.endswith(SAFE_EMAIL_SUFFIXES)
            or local in SAFE_EMAIL_LOCALS or domain.endswith(".noreply.github.com"))


def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # UDP connect sends no packets
            return s.getsockname()[0]
    except OSError:
        return ""


def gather_identity(extra_terms=(), public_ip=False, system=True):
    """Return [(label, value)] of things that identify the person running this."""
    found, seen = [], set()

    def add(label, value):
        value = (value or "").strip()
        if len(value) >= 3 and value.lower() not in seen:
            seen.add(value.lower())
            found.append((label, value))

    if system:
        add("login name", getpass.getuser())
        add("home folder name", Path.home().name)
        host = socket.gethostname()
        add("computer hostname", host)
        add("computer hostname", host.split(".")[0])
        add("full name", run(["id", "-F"]))
        add("computer name", run(["scutil", "--get", "ComputerName"]))
        add("local hostname", run(["scutil", "--get", "LocalHostName"]))
        add("git name", run(["git", "config", "--global", "user.name"]))
        email = run(["git", "config", "--global", "user.email"])
        if email and not safe_email(email):
            add("git email", email)
        add("local IP address", local_ip())
        if public_ip:
            try:
                from urllib.request import urlopen
                add("public IP address", urlopen("https://api.ipify.org", timeout=5).read().decode())
            except Exception:
                print("note: could not look up your public IP", file=sys.stderr)
    if TERMS_FILE.is_file():
        for line in TERMS_FILE.read_text(errors="replace").splitlines():
            if line.strip() and not line.startswith("#"):
                add("custom term", line)
    for t in extra_terms:
        add("custom term", t)
    return found


ALLOWABLE = {"email address", "private network address", "public IP address", "MAC address"}
ALLOW_FILE = ".privacyguard-allow"


class Report:
    def __init__(self, allow=()):
        self.items, self._seen = [], set()
        self.allow = [a.lower() for a in allow]

    def add(self, severity, category, where, line, match, note="", premasked=False):
        # only generic look-alikes can be allowed; your identity and secrets never can
        if not premasked and category in ALLOWABLE and any(a in match.lower() for a in self.allow):
            return
        shown = match if premasked else mask(match)
        key = (category, where, line, shown)
        if key not in self._seen:
            self._seen.add(key)
            self.items.append({"severity": severity, "category": category, "where": where,
                               "line": line, "match": shown, "note": note})


def printable(text: str) -> bool:
    return bool(text) and sum(c in string.printable for c in text) / len(text) >= 0.85


def decoded_chunks(text: str):
    """Yield (line_number, decoded_text) for base64 hidden in the text."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if B64_LINE.match(lines[i].strip()):
            start, block = i, []
            while i < len(lines) and B64_LINE.match(lines[i].strip()):
                block.append(lines[i].strip())
                i += 1
            # wrapped base64 ends with a shorter final line, which is still part of the block
            if i < len(lines) and B64_TAIL.match(lines[i].strip()) and len(lines[i].strip()) <= len(block[-1]):
                block.append(lines[i].strip())
                i += 1
            blob = "".join(block)
            try:
                out = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "replace")
                if printable(out):
                    yield start + 1, out
            except Exception:
                pass
        else:
            for m in B64_INLINE.finditer(lines[i]):
                try:
                    out = base64.b64decode(m.group() + "=" * (-len(m.group()) % 4)).decode("utf-8", "replace")
                    if printable(out):
                        yield i + 1, out
                except Exception:
                    pass
            i += 1


def scan_text(text, where, ident, report, depth=0):
    for n, line in enumerate(text.splitlines(), 1):
        line = line[:20000]
        hits = [(m.span(), label, value, m.group()) for label, value, rx in ident for m in rx.finditer(line)]
        # when one term sits inside a longer one (short vs full hostname), report only the longer
        hits = [h for h in hits if not any(o is not h and o[0][0] <= h[0][0] and h[0][1] <= o[0][1]
                                           and (o[0][1] - o[0][0]) > (h[0][1] - h[0][0]) for o in hits)]
        spans = [h[0] for h in hits]
        for _, label, value, text_hit in hits:
            sev = HIGH if len(value) >= 5 else MEDIUM
            note = "" if sev == HIGH else "short term, may be a common word"
            report.add(sev, f"your {label}", where, n, text_hit, note)

        def covered(span):
            return any(s[0] < span[1] and span[0] < s[1] for s in spans)

        for m in EMAIL.finditer(line):
            if not covered(m.span()) and not safe_email(m.group()):
                report.add(MEDIUM, "email address", where, n, m.group(), "use a noreply address in public files")
        for m in HOME_PATH.finditer(line):
            user = m.group(1) or m.group(2)
            if user.lower() not in PLACEHOLDER_USERS:
                report.add(HIGH, "home folder path", where, n, m.group(), "reveals your computer username")
        for m in MAC.finditer(line):
            if not is_placeholder_hw(m.group()):
                report.add(MEDIUM, "MAC address", where, n, m.group(), "hardware identifier")
        for m in IPV4.finditer(line):
            try:
                ip = ipaddress.ip_address(m.group())
            except ValueError:
                continue
            if (any(ip in net for net in DOC_NETS) or m.group() in KNOWN_PUBLIC_DNS
                    or ip.is_loopback or ip.is_unspecified or ip.is_multicast or covered(m.span())):
                continue
            kind = "private network address" if ip.is_private else "public IP address"
            report.add(LOW, kind, where, n, m.group(), "review: is this yours?")
        known = set()
        for label, rx in SECRETS:
            for m in rx.finditer(line):
                known.add(m.group())
                report.add(HIGH, f"secret: {label}", where, n, m.group(), "revoke it, then remove it")
        for m in SECRET_ASSIGN.finditer(line):
            value = m.group(1)
            if (value in known or any(h in value.lower() for h in PLACEHOLDER_HINTS) or not re.search(r"\d", value)
                    or not re.search(r"[A-Za-z]", value)):
                continue
            report.add(HIGH, "secret: hard-coded credential", where, n, value, "move it to an environment variable")
    if depth == 0:
        for start, decoded in decoded_chunks(text):
            sub = Report(report.allow)
            scan_text(decoded, "", ident, sub, depth=1)
            for it in sub.items:
                report.add(it["severity"], it["category"] + " (hidden in base64)", where, start,
                           it["match"], it["note"], premasked=True)


def tracked_files(root: Path):
    """Files git would commit (honours .gitignore); falls back to walking the folder."""
    if run(["git", "rev-parse", "--is-inside-work-tree"], cwd=root) == "true":
        out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, cwd=root).stdout
        return [root / p.decode("utf-8", "replace") for p in out.split(b"\0") if p]
    found = []
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        found += [Path(folder) / f for f in files]
    return found


def scan_files(root: Path, ident, report):
    count = 0
    for path in tracked_files(root):
        try:
            if not path.is_file() or path.stat().st_size > MAX_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8000]:
            continue
        count += 1
        scan_text(data.decode("utf-8", "replace"), str(path.relative_to(root)), ident, report)
    return count


def scan_history(root: Path, ident, report):
    """Scan commit authors, commit messages, and every line ever added."""
    if run(["git", "rev-parse", "--is-inside-work-tree"], cwd=root) != "true" or not run(["git", "rev-parse", "HEAD"], cwd=root):
        return 0
    raw = run(["git", "log", "--all", "--format=%h%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e"], cwd=root)
    commits = 0
    for rec in raw.split("\x1e"):
        parts = rec.strip("\n").split("\x1f")
        if len(parts) < 6:
            continue
        commits += 1
        sha, an, ae, cn, ce, body = parts[0].strip(), *parts[1:5], parts[5]
        for who, email in (("author", ae), ("committer", ce)):
            if email and not safe_email(email):
                report.add(HIGH, f"commit {who} email", f"history @ {sha}", 0, email,
                           "publish with a noreply address instead")
        for who, name in (("author", an), ("committer", cn)):
            scan_text(name, f"history @ {sha} ({who} name)", ident, report)
        scan_text(body, f"history @ {sha} (message)", ident, report)
    proc = subprocess.Popen(["git", "log", "--all", "-p", "--no-color", "--format=@@COMMIT %h"],
                            cwd=root, stdout=subprocess.PIPE, text=True, errors="replace")
    sha, path, buf = "?", "?", []

    def flush():
        if buf:
            scan_text("\n".join(buf), f"{path} @ {sha} (history)", ident, report)
            buf.clear()

    with proc:
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line.startswith("@@COMMIT "):
                flush()
                sha = line[9:]
            elif line.startswith("+++ "):
                flush()
                path = line[6:] if line.startswith("+++ b/") else line[4:]
            elif line.startswith("+") and not line.startswith("+++"):
                buf.append(line[1:])
    flush()
    return commits


def scan(path=".", extra_terms=(), history=True, public_ip=False, system=True, allow=()):
    root = Path(path).resolve()
    ident_raw = gather_identity(extra_terms, public_ip, system)
    ident = [(label, value, term_regex(value)) for label, value in ident_raw]
    allow = list(allow)
    allow_file = root / ALLOW_FILE
    if allow_file.is_file():
        allow += [l.strip() for l in allow_file.read_text(errors="replace").splitlines()
                  if l.strip() and not l.startswith("#")]
    report = Report(allow)
    files = scan_files(root, ident, report)
    current = {(i["category"], i["match"]) for i in report.items}
    commits = scan_history(root, ident, report) if history else 0
    # a problem still present in the files is one problem, not two: hide its history copies
    report.items = [i for i in report.items
                    if "(history)" not in i["where"] or (i["category"], i["match"]) not in current]
    report.items.sort(key=lambda i: (ORDER[i["severity"]], i["category"], i["where"], i["line"]))
    return {"root": str(root), "files_scanned": files, "commits_scanned": commits,
            "checked": sorted({label for label, _ in ident_raw}), "findings": report.items}


def render(result, strict):
    f = result["findings"]
    counts = {s: sum(1 for i in f if i["severity"] == s) for s in (HIGH, MEDIUM, LOW)}
    out = [f"privacy-guard: scanned {result['files_scanned']} files and {result['commits_scanned']} commits",
           "checking for: " + ", ".join(result["checked"] + ["emails", "home paths", "MAC addresses", "IPs", "secrets"]), ""]
    if not f:
        out.append("CLEAN: no identifying details found.")
    for sev in (HIGH, MEDIUM, LOW):
        group = [i for i in f if i["severity"] == sev]
        if group:
            out.append(f"{sev} ({len(group)})" + ("" if sev != LOW else "   [review only, does not block]" if not strict else ""))
            for i in group:
                loc = i["where"] + (f":{i['line']}" if i["line"] else "")
                out.append(f"  {i['category']:<34} {loc}   {i['match']}" + (f"   ({i['note']})" if i["note"] else ""))
            out.append("")
    blocked = counts[HIGH] + counts[MEDIUM] + (counts[LOW] if strict else 0) > 0
    out.append("RESULT: " + ("DO NOT PUBLISH yet. Fix the items above." if blocked else "safe to publish."))
    out.append("Matches are masked above. Only you can see the full values on your machine.")
    return "\n".join(out), blocked


def install_hook(path: str, force: bool):
    root = run(["git", "rev-parse", "--show-toplevel"], cwd=path)
    if not root:
        sys.exit("not a git repository")
    hook = Path(root) / ".git" / "hooks" / "pre-push"
    if hook.exists() and not force:
        sys.exit(f"{hook} already exists (use --force to replace it)")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text('#!/bin/sh\n'
                    f'python3 "{Path(__file__).resolve()}" "$(git rev-parse --show-toplevel)" || {{\n'
                    '  echo "privacy-guard blocked this push. Fix the findings or push with --no-verify."\n'
                    '  exit 1\n}\n')
    hook.chmod(0o755)
    print(f"installed: {hook}\n(it lives in your local .git folder and is never published)")


def main(argv=None):
    p = argparse.ArgumentParser(description="Scan a project for your private details before publishing.")
    p.add_argument("path", nargs="?", default=".", help="folder to scan (default: current folder)")
    p.add_argument("--term", action="append", default=[], help="extra private word to look for (repeatable)")
    p.add_argument("--allow", action="append", default=[],
                   help="ignore emails/IPs containing this text, e.g. a fictional demo domain (repeatable; also read from .privacyguard-allow)")
    p.add_argument("--no-history", action="store_true", help="skip the git history scan")
    p.add_argument("--public-ip", action="store_true", help="also look for your public IP (makes one request to api.ipify.org)")
    p.add_argument("--strict", action="store_true", help="treat LOW findings (IP addresses) as blocking")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--install-hook", action="store_true", help="install a git pre-push hook that runs this scan")
    p.add_argument("--force", action="store_true", help="with --install-hook: replace an existing hook")
    args = p.parse_args(argv)
    if args.install_hook:
        return install_hook(args.path, args.force)
    result = scan(args.path, args.term, not args.no_history, args.public_ip, allow=args.allow)
    text, blocked = render(result, args.strict)
    print(json.dumps(result, indent=2) if args.json else text)
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())

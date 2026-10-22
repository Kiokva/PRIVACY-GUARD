# PRIVACY-GUARD

Find your own private details **before** you publish a project. PRIVACY-GUARD scans a folder and its full git history for things that identify you, such as your name, computer name, local IP, git email, home-folder path, and leaked secrets like API keys. It can also block `git push` until the problems are fixed.

It is one Python file with no dependencies. It runs entirely on your machine, and its report masks every match, so the report itself is safe to share.

## Why

Most leaks are accidental: a log path like `/Users/yourname/...`, a commit author email, a hostname in a comment, a key in a config file. Deleting the line is not enough, because the old version stays in git history. PRIVACY-GUARD checks both your current files and every past commit.

## What it checks

| Finding | Severity | Examples |
|---------|----------|----------|
| **Your identity** (found automatically) | HIGH | login name, full name, computer name, hostname, git name, git email, local IP |
| **Secrets** | HIGH | AWS keys, GitHub tokens, Slack tokens, `sk-...` keys, Google API keys, private key blocks, JWTs, hard-coded passwords |
| **Home-folder paths** | HIGH | `/Users/<name>/...`, `/home/<name>/...`, `C:\Users\<name>\...` |
| **Commit author or committer email** | HIGH | any email in git history that is not a noreply address |
| **Other email addresses** | MEDIUM | anything that is not a noreply, `example.com`, or `.test` address |
| **MAC addresses** | MEDIUM | `aa:bb:cc:dd:ee:ff` |
| **IP addresses** | LOW | private or public IPs, flagged for review (well-known DNS servers and documentation ranges are ignored) |

It also decodes **base64** (as used in email files and config blobs) and scans the hidden text, and it only scans files git would actually commit, so your `.gitignore` is respected.

## Requirements

Python 3.8 or newer and `git`. Nothing to install.

## Usage

Download `privacy_guard.py`, then scan a project:

```bash
python3 privacy_guard.py /path/to/your/project
```

Scan the current folder:

```bash
python3 privacy_guard.py .
```

### Example output

All names here are fictional.

```
privacy-guard: scanned 2 files and 1 commits
checking for: computer hostname, git email, git name, local IP address, login name, emails, home paths, MAC addresses, IPs, secrets

HIGH (4)
  commit author email                history @ 16ce20c   ja************om   (publish with a noreply address instead)
  home folder path                   app.py:3            /U******ne
  secret: AWS access key             app.py:5            AK************22   (revoke it, then remove it)
  your computer hostname             app.py:4            Ja************ro

RESULT: DO NOT PUBLISH yet. Fix the items above.
```

The exit code is `0` when safe and `1` when something blocks publishing, so scripts and CI can use it.

### Block risky pushes automatically

Run this once inside a repository:

```bash
python3 privacy_guard.py . --install-hook
```

From then on, `git push` runs the scan first and stops if anything is found. The hook lives in your local `.git` folder and is never published. To bypass it once, use `git push --no-verify`.

### Options

| Option | What it does |
|--------|--------------|
| `--term WORD` | Also look for this private word (repeatable), such as your real name or employer |
| `--allow TEXT` | Ignore emails and IPs containing this text. Use it only for fictional data (repeatable) |
| `--strict` | Treat LOW findings (IP addresses) as blocking too |
| `--no-history` | Skip the git history scan (faster) |
| `--public-ip` | Also look for your public IP. This is the only option that touches the network: one request to `api.ipify.org` |
| `--json` | Machine-readable output |
| `--install-hook` | Install the pre-push hook. Add `--force` to replace an existing one |

### Keep a list of private words

Put one word per line in `~/.config/privacy-guard/terms.txt`, such as your full name, phone number, or school. It lives outside any project, so it can never be committed by mistake. Lines starting with `#` are ignored.

### Fictional demo data

If your project includes made-up emails or IPs on purpose, list a piece of each (one per line) in a file named `.privacyguard-allow` at the project root, or pass `--allow`. Allow entries apply only to generic emails and IPs. They can never hide your own identity or a secret. Put only fictional values in that file, because the file itself is published with your project.

## If it finds something

1. **Remove it from the current files.**
2. **If it is in git history** (the location shows `history @ <commit>`), removing the line is not enough. For a new project, the simplest fix is to start a fresh repository from the cleaned files. Otherwise rewrite history with a tool such as `git filter-repo`.
3. **If it is a secret, revoke it first.** Treat any key that was ever public as compromised.
4. For commit emails, set a noreply address: `git config user.email "<id>+<username>@users.noreply.github.com"`.

## Privacy of the tool itself

- It makes **no network requests**, except the optional `--public-ip` lookup.
- It never writes your details anywhere. Matches are masked in all output (first and last two characters only).
- It reads your identity from your own machine at run time (login name, hostname, `git config`). None of that is stored in this repository.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Limitations

- It finds what it knows to look for. It cannot recognize details it was never told about (for example, a nickname), so add those with `--term` or the terms file.
- Short names (under 5 characters) are matched case-sensitively and reported as MEDIUM, because they can collide with ordinary words. They may need a manual look.
- It cannot see inside images, PDFs, or other binary files.
- A clean report lowers the risk of a leak but does not guarantee there is none. Read your diff before you publish.

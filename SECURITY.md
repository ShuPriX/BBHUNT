# Security

**This repository is public.** Everything committed here is world-readable, permanently, including anything later deleted — git history keeps it. Two things must never end up in a commit: **credentials** and **undisclosed vulnerability details**.

---

## 1. The API key

The Anthropic key is never stored in this repository, in any form, at any time.

| Where it runs | Where the key lives | How to set it |
|---|---|---|
| Local (`BBHUNT` in Claude Code) | `~/.config/bbhunt/env`, mode 600, outside the repo | `tools/bbenv.sh --set` |
| GitHub Actions | Repository secret, encrypted at rest | `gh secret set ANTHROPIC_API_KEY --repo ShuPriX/BBHUNT` |

Both methods read the key from a hidden prompt or stdin, so it never lands in `~/.zsh_history`, never appears in `ps` output, and never touches a tracked file.

Check status without revealing the key:

```bash
tools/bbenv.sh --check      # prints sk-ant-a…7f9c, never the whole key
```

### Reduce the blast radius before you create the key

1. Create it in a **dedicated Anthropic workspace**, not your default one.
2. Set a **monthly spend limit** on that workspace. A leaked key that can spend $20 is an annoyance; one with no cap is not.
3. Use a **separate key** for CI and for local work, so you can revoke one without breaking the other.
4. Rotate on any suspicion. Revocation is instant at console.anthropic.com.

### If a key is ever exposed

Rotate first, investigate second. Deleting the commit does **not** help — the value stays in history and in every clone and fork. Revoke it at console.anthropic.com, then create a new one.

---

## 2. Controls in place

| Layer | Control |
|---|---|
| Pre-commit hook | `tools/secret-scan.sh staged` — gitleaks with BBHUNT rules; blocks the commit |
| Pre-push hook | full working-tree scan before anything leaves the machine |
| `.gitleaks.toml` | custom rules for Anthropic, HackerOne, Bugcrowd, and recon-service keys — the **default gitleaks pack does not detect Anthropic keys**, which is why this file exists |
| `.gitignore` | `hunts/`, `loot/`, `.env*`, `*.pem`, `*.key`, `*.p12`, cookies, credentials |
| GitHub secret scanning | enabled |
| GitHub push protection | enabled — server-side block on known key formats |
| CI | same `secret-scan.sh` runs before every automated commit |

Enable the hooks (idempotent, safe to re-run):

```bash
tools/harden.sh          # applies everything
tools/harden.sh --audit  # reports status, changes nothing
```

`--no-verify` bypasses the local hooks. Don't. Server-side push protection is a last line, not a first.

---

## 3. Undisclosed vulnerability research

This is the risk specific to a **public** bug bounty repo, and it is easy to get wrong.

Committing details of an unfixed vulnerability to a public repository is a public 0-day disclosure. It typically:

- breaches the program's disclosure policy,
- voids the bounty,
- can get you banned from the platform,
- and puts real users at risk before a patch exists.

**The guard:** `tools/secret-scan.sh` blocks any commit under `research/` unless that finding's `metadata.json` contains:

```json
"public_disclosure_ok": true
```

Set that flag only when **all** of these are true:

1. The vendor has shipped a fix, **and**
2. the advisory/CVE is public, **and**
3. the program's policy permits disclosure (many require explicit written approval, and some require a waiting period after the fix ships).

Until then, keep the research local — it is git-ignored by default under `research/**/private/`, or simply leave it uncommitted.

If you would rather not manage this per-finding, make the repository private:

```bash
gh repo edit ShuPriX/BBHUNT --visibility private --accept-visibility-change-consequences
tools/harden.sh    # re-records visibility; relaxes the disclosure guard
```

---

## 4. CI/CD posture

The workflows are written against the standard ways Actions secrets leak:

- **Triggers are `schedule` and `workflow_dispatch` only.** No `pull_request_target`, no `issue_comment`, no `workflow_run` — those execute attacker-influenced content with access to secrets.
- **Fork guard:** `if: github.repository == 'ShuPriX/BBHUNT'`.
- **Actions pinned to commit SHAs**, not tags. A tag can be moved; a SHA cannot.
- **Least privilege:** top-level `permissions: contents: read`; write is granted only to the job that commits.
- **`persist-credentials: false`** on checkout, so no git credential sits in the workspace while the model step has shell access. The push token is injected into that one command only.
- **Key scoping:** `ANTHROPIC_API_KEY` is set on the single step that needs it, masked with `::add-mask::`, and that step deliberately does not use `set -x`.

### Known limitation, stated plainly

The analysis step runs a model with `Bash` access and the API key in its environment. Any process in that step can read its own credential — that is inherent, not a flaw in the configuration. The mitigations are the ones above: a spend-capped, workspace-scoped, rotatable key; no untrusted triggers; and log masking. Do not treat the CI key as more protected than that.

---

## 5. Testing conduct

BBHUNT performs active testing only against assets explicitly in scope for a bug bounty or VDP program, under that program's rules. It does not perform denial of service, destructive testing, data exfiltration, credential theft, persistence, or mass exploitation, and does not build tooling for them. Proof-of-concept code targets a local lab.

`bbhunt.sh` keeps its own interactive authorization gate; it is not bypassed automatically.

---

## Reporting a problem with BBHUNT itself

Open an issue, or contact the repository owner directly for anything sensitive. Do not open a public issue containing a live credential or an undisclosed vulnerability.

<div align="center">

```
██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   
██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   
██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
```

**Modular bug bounty recon + vulnerability pipeline — with an autonomous intelligence layer**

</div>

---

> ⚠️ **LEGAL NOTICE** — Only run `bbhunt` against targets you **own** or have **explicit written permission** to test. Unauthorized scanning is illegal in most jurisdictions. This tool is intended for use on your own assets or in-scope bug bounty programs only.

---

## Overview

BBHUNT is two layers that work together:

| Layer | What it is | Answers |
|---|---|---|
| **`bbhunt.sh`** | A single-file, fully modular bash pipeline chaining the best open-source recon and vuln-scanning tools into one clean workflow. Every phase is optional, skippable, and composable. Critical and high findings land in a dedicated `findings/` directory so you never have to dig through raw output. | *What is on this target?* |
| **`skill/`** | A persistent Claude Code skill — autonomous bug-bounty intelligence and vulnerability research. Triggered by the single word `BBHUNT`. | *Where is the highest-value legitimate opportunity right now, why is it worth researching, and how do I prove it safely?* |

Use the intelligence layer to decide **what deserves your time**, then point the pipeline at it.

---

# Layer 1 — The pipeline (`bbhunt.sh`)

## Features

- 🔍 **8-phase pipeline** — from subdomain enum to darkweb OSINT
- 📁 **Auto-triage** — critical/high/XSS hits saved to `findings/` automatically
- 🕵️ **Darkweb search** — Tor-proxied queries to onion indexes (opt-in)
- 🌐 **Deep OSINT** — WHOIS, DNS, crt.sh, Wayback, theHarvester, Shodan, Google dorks
- 🔑 **JS secret scanning** — crawls JS files for leaked API keys/tokens
- 🎨 **24-bit RGB banner** — because aesthetics matter
- ⚡ **Quick mode** — skip slow steps for fast initial recon
- 🔒 **Authorization gate** — forces target confirmation before any scanning

---

## Phases

| # | Phase | Tools |
|---|-------|-------|
| 1 | Subdomain Enumeration | `subfinder`, `amass` |
| 2 | DNS Resolution | `dnsx` |
| 3 | Live Host Probing | `httpx` |
| 4 | URL Harvesting | `gau`, `katana` |
| 5 | Vuln Scanning | `nuclei` |
| 6 | XSS Probing | `gf`, `dalfox` |
| 7 | OSINT & Deep Crawl | `whois`, `dig`, `curl` (crt.sh, Wayback), `theHarvester`, `shodan` |
| 8 | Darkweb Search *(opt-in)* | `torsocks`, Torch, Haystak, Ahmia, paste sites |

---

## Output Structure

Every run creates a timestamped directory:

```
~/hunts/
└── example.com/
    ├── latest -> 20240601-143022/     ← symlink to most recent run
    └── 20240601-143022/
        ├── findings/                  ← ⭐ START HERE
        │   ├── critical.txt           ← nuclei critical hits
        │   ├── high.txt               ← nuclei high hits
        │   ├── xss-confirmed.txt      ← dalfox confirmed XSS
        │   ├── osint-summary.txt      ← WHOIS, DNS, certs, emails, dorks
        │   └── darkweb.txt            ← onion index hits (--darkweb only)
        ├── subdomains.txt
        ├── resolved.txt
        ├── live.txt
        ├── live-detailed.txt
        ├── urls.txt
        ├── wayback-urls.txt
        ├── nuclei.txt
        ├── xss-candidates.txt
        ├── dalfox.txt
        ├── theharvester.txt
        └── js-secrets.txt
```

`hunts/` is git-ignored — hunt output is never committed.

---

## Installation

### 1. Clone

```bash
git clone https://github.com/ShuPriX/BBHUNT.git
cd BBHUNT
chmod +x bbhunt.sh
sudo cp bbhunt.sh /usr/local/bin/bbhunt
```

### 2. Install dependencies

Install what you need for the phases you use:

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/gf@latest

# Python tools
pip install theHarvester shodan

# Amass
go install github.com/owasp-amass/amass/v4/...@master

# Darkweb (optional)
sudo apt install tor torsocks
sudo systemctl enable --now tor

# Shodan API key (optional)
shodan init YOUR_API_KEY
```

### 3. Update nuclei templates

```bash
nuclei -update-templates
```

---

## Usage

```bash
# Full pipeline (phases 1-7)
bbhunt example.com

# Custom output directory
bbhunt -o ~/hunts example.com

# Recon only (phases 1-4)
bbhunt --phases recon example.com

# Vuln scan only (phases 5-6)
bbhunt --phases vuln example.com

# OSINT only (phase 7)
bbhunt --phases osint example.com

# All phases including darkweb (phases 1-8)
bbhunt --darkweb example.com

# Skip slow steps (no amass, critical/high nuclei only)
bbhunt --quick example.com

# Skip authorization prompt (CI/scripting)
bbhunt -y example.com

# Specific phases
bbhunt --phases 1,2,3,5 example.com

# Custom thread count
bbhunt -t 100 example.com
```

---

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `example.com` | Target domain (required) | — |
| `-o / --out` | Output root directory | `~/Desktop/Apps/bbhunt/hunts` |
| `--phases` | Comma-separated phases or alias | `1,2,3,4,5,6,7` |
| `--quick` | Skip amass + medium nuclei + dalfox | off |
| `-t / --threads` | Thread count for httpx/nuclei/gau | `50` |
| `-y / --yes` | Skip authorization confirmation | off |
| `--darkweb` | Enable phase 8 Tor/onion search | off |
| `-h / --help` | Show usage | — |

### Phase aliases

| Alias | Expands to |
|-------|-----------|
| `recon` | `1,2,3,4` |
| `vuln` | `5,6` |
| `osint` | `7` |
| `all` | `1,2,3,4,5,6,7,8` |

---

## Findings Triage

At the end of every run, the summary box shows what matters:

```
  ┌─────────────────────────────────────┐
  │  ⚑  FINDINGS TRIAGE                 │
  ├─────────────────────────────────────┤
  │  🔴 CRITICAL : 2                    │
  │  🟠 HIGH     : 7                    │
  │  🟡 XSS conf : 3                    │
  │  🔵 OSINT    : 142   lines          │
  │  🕵  DARKWEB  : 0    refs            │
  └─────────────────────────────────────┘

  → ~/hunts/example.com/20240601-143022
  → ~/hunts/example.com/20240601-143022/findings
```

Open `findings/` first — everything actionable is already extracted and waiting.

---

## Phase 7 — OSINT Details

Phase 7 runs automatically and collects:

| Source | What it gets |
|--------|-------------|
| `whois` | Registrar, registrant emails, name servers, expiry |
| `dig` | Full DNS dump — MX, TXT, NS, A, AAAA, SPF, DMARC |
| `crt.sh` | Certificate transparency — new subdomains fed back to pipeline |
| Wayback Machine | Up to 2,000 historical URLs fed back into `urls.txt` |
| `theHarvester` | Emails, IPs, hosts from all OSINT sources |
| `shodan` | Domain intel, open ports, services |
| Google Dorks | Pre-built dork queries written to `osint-summary.txt` for manual use |
| JS Secret Scanner | Crawls JS files, greps for leaked `api_key`, `token`, `secret`, `password` |

---

## Phase 8 — Darkweb (opt-in)

Requires `tor` + `torsocks` to be installed and Tor running on `127.0.0.1:9050`.

```bash
bbhunt --darkweb example.com
```

Queries:
- **Ahmia** — clearnet Tor search index
- **Torch** — `xmh57jr...onion` via Tor proxy
- **Haystak** — `haystak5...onion` via Tor proxy
- **Paste sites** — psbdmp.ws, pastebin.com via Tor

All hits saved to `findings/darkweb.txt`.

---

## Tool Dependencies

| Tool | Required | Phase | Install |
|------|----------|-------|---------|
| `subfinder` | Recommended | 1 | `go install ...subfinder@latest` |
| `amass` | Optional | 1 | `go install ...amass/v4/...@master` |
| `dnsx` | Recommended | 2 | `go install ...dnsx@latest` |
| `httpx` | Recommended | 3 | `go install ...httpx@latest` |
| `gau` | Recommended | 4 | `go install ...gau/v2/...@latest` |
| `katana` | Recommended | 4 | `go install ...katana@latest` |
| `nuclei` | Recommended | 5 | `go install ...nuclei/v3/...@latest` |
| `gf` | Recommended | 6 | `go install ...gf@latest` |
| `dalfox` | Optional | 6 | `go install ...dalfox/v2@latest` |
| `whois` | Recommended | 7 | `sudo apt install whois` |
| `dig` | Recommended | 7 | `sudo apt install dnsutils` |
| `curl` | Required | 7/8 | usually pre-installed |
| `theHarvester` | Optional | 7 | `pip install theHarvester` |
| `shodan` | Optional | 7 | `pip install shodan` |
| `tor` + `torsocks` | Optional | 8 | `sudo apt install tor torsocks` |

The script skips any phase gracefully if a tool is missing — you'll see a `[!]` warning and execution continues.

---

## Tips

- **First run on a new target?** Use `--quick` to get a fast lay of the land, then run full.
- **Large scope?** Increase threads: `-t 150`
- **CI/automation?** Add `-y` to skip the auth prompt.
- **Only care about OSINT?** `--phases osint` runs phase 7 only — no active scanning.
- **JS secrets finding false positives?** Check `js-secrets.txt` manually; the grep is intentionally broad.
- The `latest` symlink always points to your most recent run — use it in scripts: `cat ~/hunts/example.com/latest/findings/critical.txt`

---

# Layer 2 — The intelligence skill (`skill/`)

## Quick start

```bash
./skill/install.sh     # install the skill so the trigger word works anywhere
./tools/harden.sh      # enable secret-scanning hooks + verify repo security
./tools/bbenv.sh --set # store your Anthropic key OUTSIDE the repo (mode 600)

# then, in Claude Code:
BBHUNT
```

That single word runs the full workflow: read state → refresh stale sources → discover and verify programs → rank → pull new high-impact disclosures → correlate with scope → filter → pick the top 1-3 → analyze the patch → reproduce locally → write the artifacts → update state → report.

| Command | Does |
|---|---|
| `BBHUNT` | full daily run |
| `BBHUNT <program\|domain>` | skip discovery, hunt that program |
| `BBHUNT CVE-2026-1234` | research one vulnerability for bounty eligibility |
| `BBHUNT programs` | rank programs only |
| `BBHUNT report` | regenerate today's report from state |

---

## Principles

**Quality over quantity.** One deeply researched opportunity beats forty listed CVEs. A run that honestly reports `NO HIGH-CONFIDENCE HIGH-IMPACT OPPORTUNITY FOUND TODAY` is a correct run.

**Never fabricate.** Missing reward data is `REWARD_UNKNOWN`. Thin evidence is `INSUFFICIENT DATA`. There is no "80% payout chance" — the 80-point threshold is a ranking tier on a composite score, not a probability.

**Scope first, lab first.** Nothing is tested until the asset is verified in-scope against the current official policy. Everything is reproduced locally before a live asset is touched, and then only with the minimum non-destructive proof the policy permits.

**State, not repetition.** Processed CVEs, rejected programs, and unchanged scope are never re-analyzed. That is what makes a daily run cheap.

---

## Layout

```
bbhunt.sh                  recon + vuln pipeline (authorization-gated)
config/
  platforms.yaml           where to look — platforms, program indexes, vuln feeds
  scoring.yaml             both scoring models; single source of truth for weights
  exclusions.yaml          always-rejected classes, chain requirements, hard stops
skill/
  SKILL.md                 the compact core — loaded every run
  modules/                 loaded on demand, one per target type or phase
  templates/               artifact + report skeletons
  state/                   repository-backed memory (current/programs/vulns/history)
  install.sh               installs the skill into ~/.claude/skills
tools/
  bbstate.py               state: seen / record / reject / queue / validate / stats
  bbscore.py               reproducible scoring from config/scoring.yaml
  bbreport.py              scaffold daily/weekly reports and research dirs
  bbenv.sh                 load the API key from outside the repo
  secret-scan.sh           the one gate: staged / tree / history
  harden.sh                apply and audit the repo security controls
.githooks/                 pre-commit + pre-push secret scanning
.gitleaks.toml             custom rules (Anthropic keys, H1/Bugcrowd, recon keys)
SECURITY.md                key handling, disclosure policy, CI posture
intelligence/              verified program intel, platform digests, rankings
opportunities/             daily candidate lists and the running top list
research/<year>/<program>/<vuln-id>/
                           README.md report.md poc.md changes.diff nuclei.yaml metadata.json
reports/daily/ reports/weekly/
.github/workflows/         daily intel + weekly summary
```

### Modules

Loaded one at a time — never all twelve.

| Module | Loaded when |
|---|---|
| `programs` | discovering and verifying programs, scope, rewards |
| `vulnerability-intel` | source catalog, correlation chain, freshness, duplicates |
| `scoring` | both score models, confidence bands |
| `patch-analysis` | any candidate with public source or a fix commit |
| `poc` | building the local lab and the reproduction |
| `reporting` | artifacts, daily and weekly reports |
| `wordpress` `web` `api` `cloud` `mobile` `ai` | one per candidate, by target type |

---

## Tools

```bash
python3 tools/bbstate.py status                    # start every run here
python3 tools/bbstate.py seen vuln CVE-2026-1234   # NEW, or SEEN:<status> (exit 1)
python3 tools/bbstate.py reject CVE-2026-9999 --reason "excluded class"
python3 tools/bbstate.py stale --days 7            # programs due for re-verification
python3 tools/bbstate.py validate research/2026/acme/CVE-2026-1234
python3 tools/bbstate.py stats

python3 tools/bbscore.py weights
python3 tools/bbscore.py opportunity --impact 27 --payout 16 --acceptance 11 \
        --exploitability 13 --scope 8 --freshness 4 --dupres 4
python3 tools/bbscore.py confidence --score 72 --items 4

python3 tools/bbreport.py daily
python3 tools/bbreport.py new acme CVE-2026-1234   # artifact dir from templates
```

Sub-scores are entered out of each component's own weight cap; the tool rejects out-of-range input so a score is always reproducible from `config/scoring.yaml`.

---

## Scoring

**PROGRAM OPPORTUNITY SCORE** /100 — reward potential 25 · acceptance evidence 20 · scope quality 15 · attack surface 15 · activity 10 · duplicate resistance 10 · feasibility 5.

**OPPORTUNITY SCORE** /100 — technical impact 30 · payout potential 20 · acceptance evidence 15 · exploitability 15 · scope quality 10 · freshness 5 · duplicate resistance 5.

CVSS is not an input and is not a tie-breaker. A 9.8 in a deployment nobody runs loses to a 6.5 that reaches real user data.

---

## Automation

`.github/workflows/daily-intel.yml` runs the deterministic half daily — state check, source reachability, scope-delta digests from the public bulk dump, scaffolded report. The analysis half runs **Claude Opus 5 at `xhigh` effort**, and only when `ANTHROPIC_API_KEY` is set as a repository secret; without it the workflow still produces the deltas a local `BBHUNT` run consumes.

`.github/workflows/weekly-summary.yml` aggregates the week on Mondays.

Set the CI key (reads stdin — never hits disk or shell history):

```bash
gh secret set ANTHROPIC_API_KEY --repo ShuPriX/BBHUNT
```

---

## Security

This repository is **public**. Two things must never reach a commit: credentials, and undisclosed vulnerability details. Full policy in [`SECURITY.md`](SECURITY.md).

| Control | Where |
|---|---|
| Key storage | `~/.config/bbhunt/env` (mode 600, outside the repo) or a GitHub Actions secret — never a tracked file |
| Pre-commit / pre-push hooks | gitleaks with BBHUNT rules; blocks the commit |
| Custom gitleaks rules | the default pack does **not** detect Anthropic keys — `.gitleaks.toml` adds them, plus H1/Bugcrowd/recon-service keys |
| Disclosure guard | blocks committing `research/` artifacts without `"public_disclosure_ok": true` |
| CI posture | schedule/manual triggers only, SHA-pinned actions, `contents: read` by default, `persist-credentials: false`, key scoped to one masked step |
| GitHub | secret scanning + push protection enabled |

```bash
tools/harden.sh --audit        # status only
tools/secret-scan.sh history   # audit all past commits
tools/bbenv.sh --check         # masked key status
```

Before creating the API key: put it in a **dedicated Anthropic workspace with a monthly spend limit**, and use separate keys for CI and local. A leaked key with a cap is an annoyance; one without is not.

---

## Safety

Active testing is restricted to explicitly authorized bug-bounty/VDP scope and the program's own rules. BBHUNT will not perform denial of service, destructive testing, data exfiltration, credential theft, persistence, evasion, or mass exploitation, and will not build tooling for them. Proof-of-concept code targets a local lab, not an arbitrary host.

`bbhunt.sh` keeps its own interactive authorization gate — you type the target domain to confirm before it runs. That gate is not bypassed on your behalf.

If authorization cannot be established: `RESEARCH-ONLY / NO ACTIVE TESTING`.

---

## Requirements

**Intelligence layer:** Python 3.9+ with `pyyaml`, plus `git`, `curl`, `jq`. `gitleaks` and `gh` recommended. Docker or Podman for local reproduction.

**Pipeline:** see [Tool Dependencies](#tool-dependencies) above — every tool is optional and skipped gracefully.

---

## License

MIT — use freely, hack responsibly.

---

<div align="center">
<sub>Built for authorized security research and bug bounty hunting only.</sub>
</div>

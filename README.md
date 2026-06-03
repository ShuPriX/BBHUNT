<div align="center">

```
██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   
██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   
██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
```

**Modular bug bounty recon + vulnerability pipeline**

</div>

---

> ⚠️ **LEGAL NOTICE** — Only run `bbhunt` against targets you **own** or have **explicit written permission** to test. Unauthorized scanning is illegal in most jurisdictions. This tool is intended for use on your own assets or in-scope bug bounty programs only.

---

## Overview

`bbhunt` is a single-file, fully modular bash pipeline that chains together the best open-source recon and vuln-scanning tools into one clean workflow. Every phase is optional, skippable, and composable. Results are automatically triaged — critical and high findings land in a dedicated `findings/` directory so you never have to dig through raw output.

---

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

---

## Installation

### 1. Clone

```bash
git clone https://github.com/yourusername/bbhunt.git
cd bbhunt
chmod +x bbhunt
sudo mv bbhunt /usr/local/bin/
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

## License

MIT — use freely, hack responsibly.

---

<div align="center">
<sub>Built for authorized security research and bug bounty hunting only.</sub>
</div>

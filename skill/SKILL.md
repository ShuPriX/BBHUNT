---
name: bbhunt
description: Autonomous high-impact bug bounty intelligence and vulnerability research. Trigger word BBHUNT runs the full daily pipeline — program discovery, vulnerability correlation, scope verification, opportunity scoring, patch analysis, lab-safe reproduction, report/PoC generation, and repo state update. Use when the user says BBHUNT, asks for the daily hunt, asks "what is worth researching right now", asks to rank bug bounty programs by payout/acceptance evidence, or asks to research a specific CVE/GHSA for bounty eligibility.
---

# BBHUNT — Bug Bounty Intelligence & Vulnerability Research

**Repo root:** `/home/ShubroOmi/Desktop/Apps/bbhunt` (override with `$BBHUNT_ROOT`)

**Operating identity:** senior bug-bounty researcher + vulnerability intelligence analyst + security engineer.
**Not:** a mass scanner, a CVE scraper, a vuln feed mirror, a report generator.

**The question every run answers:**
> Where is the highest-value legitimate opportunity right now, why is it worth researching, what evidence supports it, and how can it be safely reproduced and documented?

Quality over quantity. A run that produces **one** deeply researched opportunity beats a run that lists forty.

---

## 0. HARD RULES (never override)

| Rule | Meaning |
|---|---|
| Scope first | No active testing until the asset is verified in-scope against the **current official policy page**. Unverified → `RESEARCH-ONLY / NO ACTIVE TESTING`. |
| Lab first | Reproduce locally (Docker/VM/test install) before ever touching a live asset. |
| Non-destructive only | No DoS, no data deletion/modification, no exfiltration, no credential theft, no persistence, no malware, no mass exploitation, no scope circumvention. |
| Minimum validation | On live in-scope assets, only the smallest non-destructive proof the policy permits. |
| Never fabricate | No invented CVEs, payouts, stats, or acceptance rates. Missing data → `REWARD_UNKNOWN` / `INSUFFICIENT DATA`. |
| Never commit secrets | No keys, tokens, cookies, credentials, private program data, or user data in the repo. |
| Public repo = public disclosure | This repo is public. A `research/` artifact may be committed only when its `metadata.json` has `"public_disclosure_ok": true` — fix shipped, advisory public, program permits it. Otherwise leave it uncommitted. Never bypass the pre-commit hook. See `SECURITY.md`. |
| Honest empty result | If nothing clears the gate: `NO HIGH-CONFIDENCE HIGH-IMPACT OPPORTUNITY FOUND TODAY`. That is a valid, correct run. |

Evidence labels are mandatory on every claim: `VERIFIED` / `INFERRED` / `UNKNOWN`.

---

## 1. RUN PROTOCOL

On trigger `BBHUNT` (no args) — do not ask what to hunt. Execute:

```
S1  State      python3 tools/bbstate.py status          # last run, queue, deltas
S2  Refresh    only sources stale per config/platforms.yaml refresh_days
S3  Programs   discover + verify active programs        → module: programs
S4  Rank       PROGRAM OPPORTUNITY SCORE                → module: scoring
S5  Vulns      new high-impact disclosures since last run → module: vulnerability-intel
S6  Correlate  vuln × program (tech stack ∩ scope)
S7  Funnel     drop excluded / low-impact / dup-heavy   → config/exclusions.yaml
S8  Select     top 1-3 candidates only
S9  Analyze    patch + root cause                       → module: patch-analysis
S10 Reproduce  local lab                                → module: poc
S11 Generate   artifacts                                → module: reporting
S12 Score      OPPORTUNITY SCORE                        → module: scoring
S13 Persist    bbstate.py record-* ; write daily report
S14 Summarize  BBHUNT STATUS block (§6)
```

**Argument forms:** `BBHUNT <domain|program>` → skip S3-S7, hunt that program. `BBHUNT <CVE|GHSA>` → skip to S6. `BBHUNT report` → S13-S14 only. `BBHUNT programs` → S3-S4 only.

**Funnel aggressively before spending tokens.** Filter order is cheapest-first:
```
all programs → active → high-value → tech matches a fresh vuln → in scope
→ not excluded → low duplicate risk → payout/acceptance evidence → researchable
```
Never run deep analysis on a candidate that a later gate would reject. Kill early, kill cheap.

---

## 2. MODULE ROUTING (load only what the target needs)

| Load | When |
|---|---|
| `modules/programs.md` | S3-S4 — discovering/verifying programs, scope, rewards, acceptance evidence |
| `modules/vulnerability-intel.md` | S5 — source catalog, correlation chain, enrichment fields, freshness |
| `modules/scoring.md` | S4, S12 — both score models, confidence bands, duplicate classification |
| `modules/patch-analysis.md` | S9 — any candidate with public source or a fix commit |
| `modules/poc.md` | S10 — building the local lab and the reproduction |
| `modules/reporting.md` | S11 — artifact set, report structure, daily/weekly reports |
| `modules/wordpress.md` | target is a WP plugin/theme/core |
| `modules/web.md` | target is a web app / SaaS |
| `modules/api.md` | target is a REST/GraphQL/gRPC API |
| `modules/cloud.md` | target is cloud/IaC/CI-CD/container |
| `modules/mobile.md` | target is Android/iOS |
| `modules/ai.md` | target is an LLM/agent/AI app |

Load **one** ecosystem module per candidate. Do not preload the rest. Do not restate a module you already loaded this run.

---

## 3. STATE (repo-backed memory)

All dedupe goes through `tools/bbstate.py` — never re-derive by reading old reports.

```bash
python3 tools/bbstate.py status                       # start of every run
python3 tools/bbstate.py seen vuln CVE-2026-1234      # → NEW | SEEN:<status>
python3 tools/bbstate.py seen program acme-h1
python3 tools/bbstate.py record-program <id> --platform h1 --score 84 --status active \
        --scope-hash <sha> --payout-max 10000
python3 tools/bbstate.py record-vuln CVE-2026-1234 --status researched --score 91 \
        --program acme-h1 --path research/2026/acme/CVE-2026-1234
python3 tools/bbstate.py reject CVE-2026-9999 --reason "excluded class: self-XSS"
python3 tools/bbstate.py record-run --evaluated 42 --researched 2 --artifacts 6
```

Before any expensive work ask: *already processed? program changed? new evidence? new patch?* Re-research only on material change (new version, new commit, scope delta, reward delta, new public research).

`scope_hash` / `source_fingerprint` are how change is detected — store them, compare them, skip when equal.

State files: `skill/state/{current,programs,vulnerabilities,history}.json`.

---

## 4. SELECTION BAR

Prioritize only meaningful impact — RCE, authn bypass, ATO, privesc, cross-tenant/authz bypass, SSRF with reachable internals, SQLi, command injection, arbitrary file read/write, dangerous upload, deserialization, cloud-credential or CI/CD compromise, supply chain, critical business logic, payment impact, high-impact stored XSS, sensitive token disclosure.

Strongest candidate shape:
```
unauthenticated + remote + critical + explicitly in scope + published high reward
+ active program + fresh + low public coverage + patch available + easy local repro
```

CVSS alone never qualifies a candidate. Deprioritized/rejected classes live in `config/exclusions.yaml` — check it before, not after, research.

---

## 5. QUALITY GATE (all must pass to publish as CONFIRMED)

```
[ ] scope verified        [ ] asset explicitly in scope   [ ] meaningful high impact
[ ] evidence exists       [ ] root cause identified       [ ] exploitability assessed
[ ] impact assessed       [ ] duplicate research done     [ ] confidence assigned
[ ] local repro attempted [ ] PoC reproducible            [ ] PoC non-destructive
[ ] report complete       [ ] references recorded         [ ] payout info verified
[ ] acceptance evidence evaluated
```
Any miss → classify `RESEARCH CANDIDATE`, never `CONFIRMED`.

Failure vocabulary (use verbatim): `RESEARCH-ONLY / NO ACTIVE TESTING`, `UNREPRODUCED`, `INSUFFICIENT EVIDENCE`, `INSUFFICIENT HISTORICAL DATA — DO NOT INFER`, `REWARD_UNKNOWN`, `NO HIGH-CONFIDENCE HIGH-IMPACT OPPORTUNITY FOUND TODAY`.

A source that fails: record it in the run, continue with others, never substitute a guess.

---

## 6. OUTPUT CONTRACT

Artifacts per researched candidate → `research/<year>/<program>/<vuln-id>/`:
`README.md` `report.md` `poc.md` `changes.diff` `nuclei.yaml` (only if safe) `metadata.json`
Templates: `skill/templates/`. Structure: `modules/reporting.md`.

Daily → `reports/daily/YYYY-MM-DD.md`. Weekly → `reports/weekly/YYYY-WXX.md`.
Rankings → `intelligence/rankings/`. Program intel → `intelligence/programs/<program>.json`.

Every run ends with exactly this block:

```
BBHUNT STATUS

Run:
Programs evaluated:
High-value programs:
High-impact opportunities:
Top opportunity:
Research performed:
Artifacts generated:
Repository updated:
Next priority:
```

---

## 7. EXISTING TOOLING (do not replace)

`bbhunt.sh` is the authorized recon/vuln pipeline — subdomain enum → DNS → live probe → URL harvest → nuclei → XSS → OSINT → darkweb. It keeps its own authorization gate and writes to `hunts/<target>/<stamp>/`.

Use it only for **S10 live validation of an in-scope asset after scope is VERIFIED**:
```bash
./bbhunt.sh --phases recon <in-scope-domain>     # passive, safe default
./bbhunt.sh --phases 1,2,3,4,5 <in-scope-domain> # adds nuclei; confirm policy allows scanning
```
Never run it against an unverified target. Never pass `-y` on behalf of the user. BBHUNT intelligence work is offline/OSINT and does not require it.

---

## 8. TOKEN DISCIPLINE

Fetch only what changed. Prefer IDs, hashes, and summaries over re-reading documents. Prefer incremental state over historical re-analysis. Load one module, not twelve. Filter before reasoning. Do not re-ingest processed CVEs, rejected programs, or unchanged intel — that is what state is for.

# Module: Program Discovery & Intelligence

Loaded for S3-S4. Goal: a short list of **currently active** programs with verified scope, verified rewards, and evidence-backed acceptance likelihood.

---

## 1. Discovery sources

Seed catalog: `https://github.com/disclose/bug-bounty-platforms` — a list of *platforms*, not proof any program is live.

Public program dumps (cheap, refresh per `config/platforms.yaml`):
- `https://github.com/arkadiyt/bounty-targets-data` — `data/*.json` for h1/bugcrowd/intigriti/yeswehack/hackenproof, updated hourly. Best single source for bulk scope.

Per-platform program indexes and vendor VDPs are listed in `config/platforms.yaml`. Treat that file as the catalog and extend it when you find a reputable new source — the list is never exhaustive.

**Catalog data is a lead, never a verdict.** Every serious candidate gets re-verified against its own official policy page before research.

---

## 2. Verification (mandatory before any research)

For each candidate, fetch the current official policy page and extract:

```
status          active | paused | private | retired | unknown
last_updated    from the page if shown
scope           domains, wildcards, APIs, mobile apps, desktop, cloud assets,
                repos, packages, plugins, firmware — verbatim asset strings
out_of_scope    verbatim
rewards         min / max, and per-severity table if published
rules           rate limits, required auth/test accounts, prohibited techniques,
                automated-scanning policy, disclosure policy, safe harbor
```

Record `scope_hash` = sha256 of the normalized in-scope asset list. Unchanged hash on a later run ⇒ skip re-verification, skip re-ranking.

If the policy page cannot be fetched or is ambiguous → `RESEARCH-ONLY / NO ACTIVE TESTING`. Do not infer scope from a third-party mirror.

Asset-in-scope test — all three must hold:
1. The asset matches an explicitly listed in-scope entry (wildcards expand only as the policy words them).
2. It matches nothing in out-of-scope.
3. It is actually owned/operated by the program's organization (verify ownership: WHOIS/RDAP, cert SAN, ASN, or a documented vendor relationship — not just a similar name).

---

## 3. Intelligence record

Write `intelligence/programs/<program-id>.json`:

```json
{
  "program_id": "", "org": "", "platform": "", "program_url": "",
  "status": "", "verified_at": "", "scope_hash": "",
  "scope": {"domains": [], "wildcards": [], "apis": [], "mobile": [],
            "cloud": [], "repos": [], "packages": [], "other": []},
  "out_of_scope": [],
  "rules": {"rate_limit": "", "auth_required": "", "prohibited": [],
            "disclosure": "", "safe_harbor": "", "automation_allowed": null},
  "rewards": {"min": null, "max": null, "low": null, "medium": null,
              "high": null, "critical": null, "bonuses": "",
              "currency": "USD", "source_url": ""},
  "payout_confidence_score": null, "acceptance_confidence_score": null,
  "program_opportunity_score": null,
  "tech_stack": [], "evidence_urls": [], "notes": ""
}
```

Any reward field with no published figure is `null` and reported as `REWARD_UNKNOWN`. Never interpolate a missing tier from neighbouring tiers.

---

## 4. Payout & acceptance evidence

Compute the two confidence scores in `modules/scoring.md` from observable evidence only:

| Evidence | Where |
|---|---|
| Published reward table | policy page |
| Disclosed reports + amounts | h1 hacktivity, program disclosure feed, Bugcrowd/Intigriti public reports |
| Resolution/response stats | platform program stats block (response efficiency, mean time to bounty) |
| Program activity | last-report date, recent scope changes, thanks/leaderboard updates |
| Duplicate pressure | volume of public reports on the same asset class |
| Researcher-reported experience | only from named, dated, non-anonymous sources; Tier 3 weight |

Bands: `VERY HIGH | HIGH | MEDIUM | LOW | INSUFFICIENT DATA`.

**Forbidden phrasing:** "80% chance of payout" and anything like it, unless you hold real per-report statistics that support that exact figure. `>= 80/100` is a *ranking threshold* on a composite score — it is not a probability. When evidence is thin, write `INSUFFICIENT HISTORICAL DATA — DO NOT INFER`.

---

## 5. Tech-stack fingerprinting (feeds S6 correlation)

For high-ranked programs, capture the stack cheaply — it is what lets a fresh CVE match a program:
- public job posts, engineering blog, GitHub org, `package.json`/`go.mod`/`requirements.txt` in public repos
- HTTP response headers, cookie names, favicon hash, JS bundle vendor chunks
- CMS/framework markers, cloud provider hints (bucket URLs, IdP endpoints, CDN)

Store as `tech_stack` tags (e.g. `wordpress`, `nextjs`, `django`, `k8s`, `graphql`, `aws`, `okta`). Correlation in S6 = `vuln.product ∈ program.tech_stack ∧ asset ∈ scope`.

Passive only. Fingerprinting an out-of-scope host is still traffic to a host you are not authorized to touch — use public artifacts.

---

## 6. Output of S3-S4

`intelligence/rankings/YYYY-MM-DD-programs.md` — top 10 by PROGRAM OPPORTUNITY SCORE:

| # | Program | Platform | Score | Max reward | Payout conf. | Accept. conf. | Scope highlights | Why |
|---|---|---|---|---|---|---|---|---|

Then `bbstate.py record-program` for each, so the next run skips unchanged ones.

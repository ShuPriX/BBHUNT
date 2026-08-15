# Module: Artifacts & Reporting

Loaded for S11 and S13. Templates in `skill/templates/` — copy, then fill. Never ship a template with placeholders left in.

---

## 1. Research artifact set

`research/<year>/<program>/<vuln-id>/`

| File | Required | Contents |
|---|---|---|
| `README.md` | yes | the at-a-glance card (§2) |
| `report.md` | yes | the submittable write-up (§3) |
| `poc.md` | yes | lab-safe reproduction — `modules/poc.md` |
| `changes.diff` | when public source exists | trimmed security-relevant patch |
| `metadata.json` | yes | machine-readable record (§4) |
| `nuclei.yaml` | only when safe | detection template (§5) |

Slug: `<CVE>` when one exists, else `<GHSA>`, else `<product>-<class>-<YYYYMMDD>`.

---

## 2. `README.md`

Summary · product · vulnerability class · affected/fixed versions · CVE/GHSA · CVSS (+ who scored it) · CWE · severity · prerequisites · root cause · source → sink · impact · patch analysis · detection · references · **confidence** · **program eligibility**.

Lead with the one sentence that says what an attacker gets. Every factual line carries `VERIFIED` / `INFERRED` / `UNKNOWN`.

---

## 3. `report.md` — submission grade

```
Title        <Impact> via <vuln class> in <component> (<auth level>)
Summary      3-4 sentences: what, where, who can trigger, what they get
Asset        exact in-scope asset + the policy line that covers it (quoted)
Scope        program, URL, verified date
Preconditions  privileges, config, non-default settings — stated honestly
Technical details  the flow, with file:line or request/response
Root cause   the missing control, named
Reproduction  numbered, copy-pasteable, deterministic
Impact       concrete and demonstrated, tied to the business
Severity     CVSS 3.1 vector + score, and why the vector is justified
Evidence     requests, responses, versions, timestamps, screenshots list
Remediation  the specific fix, not "validate input"
References   advisories, commits, docs — all T1/T2 links
```

Writing rules: state what you proved, in plain declarative sentences. No "could potentially", no "an attacker may be able to" — prove it or cut it. No filler severity inflation; triagers downgrade padded reports and remember who sends them. Redact real user data even in evidence. Keep the tone human — a competent colleague explaining a bug, not a scanner's output.

If a stronger local skill is installed for this step (`report-writing`, `triage-validation`), use it — this module is the fallback contract, not a competing standard.

---

## 4. `metadata.json`

```json
{
  "candidate": "", "program": "", "platform": "", "asset": "",
  "cve": "", "ghsa": "", "severity": "", "cvss": null, "cwe": "", "epss": null,
  "vulnerability_class": "", "authentication": "", "privilege_requirement": "",
  "impact": "", "payout_min": null, "payout_max": null,
  "payout_confidence_score": null, "acceptance_confidence_score": null,
  "duplicate_risk": "", "program_eligibility": "", "research_confidence": "",
  "source_urls": [], "verified_at": ""
}
```
Unknown numeric → `null`, never `0`. Unknown string → `"UNKNOWN"`, never `""` guessed.

`public_disclosure_ok` defaults to `false` and gates committing the finding — see §8.

Validate before commit: `python3 tools/bbstate.py validate research/<year>/<program>/<id>`

---

## 5. `nuclei.yaml`

Write one only when detection is possible **without** exploitation. Skip it entirely for anything where detection implies impact — write "detection template omitted: cannot detect without exploiting" instead.

Rules: version/fingerprint-based matchers preferred · single request where possible · no destructive method · no writes · no payload that alters state · deterministic matchers (not `status == 200` alone) · `severity` matching the real severity · `tags` including the CVE.

```yaml
id: <cve-or-slug>
info:
  name: <product> <class>
  author: bbhunt
  severity: <critical|high|medium>
  description: <one line>
  reference: [<advisory>, <commit>]
  classification: {cve-id: <CVE>, cwe-id: <CWE>}
  tags: [<cve>,<product>,<class>]
http:
  - method: GET
    path: ["{{BaseURL}}/<safe-fingerprint-path>"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["<version marker>"]
      - type: status
        status: [200]
```

---

## 6. Daily report — `reports/daily/YYYY-MM-DD.md`

```markdown
# BBHUNT — YYYY-MM-DD
## Best programs            (top 10, table from intelligence/rankings/)
## Best opportunities       (vuln × program, ranked, with OPPORTUNITY SCORE)
## Research completed       (candidate | result | research confidence | artifact path)
## Rejected candidates      (candidate | reason | evidence)
## Source failures          (source | error | impact on this run)
## Statistics
Programs discovered / verified / high-value:
Vulnerability candidates / researched / rejected:
Reports / PoCs / detection templates generated:
## Next priority
```

Rejections are first-class content — they are why tomorrow's run is cheap.

## 7. Weekly report — `reports/weekly/YYYY-WXX.md`

Highest-value programs · new programs · scope changes (diff of `scope_hash`) · notable new vulns · high-value classes this week · top attack surfaces · duplicate trends · reward trends · research results · false-positive trends · quality metrics (gate pass rate, repro rate).

Trends come from `skill/state/history.json` only. Do not invent payout statistics; a trend needs at least 3 data points, otherwise write `INSUFFICIENT DATA`.

---

## 8. Commit

**The BBHUNT repo is public.** Committing an unfixed vulnerability's details there is a public 0-day disclosure — it breaches most program policies, voids the bounty, and risks a platform ban.

A `research/` artifact may be committed only when its `metadata.json` has:
```json
"public_disclosure_ok": true
```
Set that only when the fix has shipped **and** the advisory is public **and** the program's policy permits disclosure. Until then leave the finding uncommitted, or under `research/**/private/` (git-ignored). The pre-commit hook enforces this; do not bypass it with `--no-verify`.

```bash
git add intelligence/ opportunities/ reports/ skill/state/
git add research/<year>/<program>/<id>    # only if cleared per above
git commit -m "bbhunt: YYYY-MM-DD — <n> programs, <n> opportunities, <n> researched"
```
Never commit: credentials, cookies, tokens, private program details, real user data, live exploit artifacts, `hunts/` output. Full policy: `SECURITY.md`.

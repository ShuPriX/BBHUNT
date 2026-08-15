# Module: Scoring

Loaded for S4 and S12. Weights live in `config/scoring.yaml`; `tools/bbscore.py` does the arithmetic so scores stay reproducible.

```bash
python3 tools/bbscore.py program --reward 20 --acceptance 15 --scope 12 \
        --surface 11 --activity 8 --dupres 7 --feasibility 4
python3 tools/bbscore.py opportunity --impact 27 --payout 16 --acceptance 11 \
        --exploitability 13 --scope 8 --freshness 4 --dupres 4
```
Each sub-score is entered **out of its own weight cap**. The tool validates caps and refuses out-of-range input.

---

## 1. PROGRAM OPPORTUNITY SCORE /100

| Weight | Component | 0 → full marks |
|---|---|---|
| 25 | Reward potential | no published figures (`REWARD_UNKNOWN`) → published table with strong critical/high tiers |
| 20 | Acceptance evidence | no data → many resolved+bountied public reports, fast response stats |
| 15 | Scope quality | one host → broad, explicit, wildcard-rich, multi-asset-type scope |
| 15 | High-impact attack surface | static marketing site → auth, payments, multi-tenant, API, cloud, admin |
| 10 | Program activity | dormant → reports resolved and scope updated recently |
| 10 | Duplicate resistance | saturated, heavily hunted → fresh scope, niche stack, low public report volume |
| 5 | Research feasibility | no access, closed source, hard signup → free/test account, public source, easy lab |

Rank the top 10. `>= 80` = **STRONG EVIDENCE** tier (a ranking threshold, not a probability of payout).

---

## 2. OPPORTUNITY SCORE /100 (vuln × program)

| Weight | Component | Anchor |
|---|---|---|
| 30 | Technical impact | RCE/ATO/cross-tenant = full; info leak of non-sensitive data = near zero |
| 20 | Payout potential | published max for this severity on this program; `REWARD_UNKNOWN` caps this at 8 |
| 15 | Acceptance evidence | this program's history with this bug class |
| 15 | Exploitability | unauth+remote+reliable = full; needs admin + user interaction + race = low |
| 10 | Scope quality | asset explicitly named = full; wildcard-inferred = half; unverified = 0 (and stop) |
| 5 | Freshness | disclosed since last run = full; year-old = ~0 |
| 5 | Duplicate resistance | `LOW DUPLICATE RISK`=5, `UNKNOWN`=3, `POSSIBLE`=2, `LIKELY`=1, `KNOWN`=0 |

Report only candidates that clear the bar you can defend. **CVSS alone is never sufficient** — a 9.8 requiring a non-existent deployment beats nothing.

---

## 3. Confidence scores

`PAYOUT_CONFIDENCE_SCORE` and `ACCEPTANCE_CONFIDENCE_SCORE`, each /100, each from evidence you can cite:

| Points | Payout confidence | Acceptance confidence |
|---|---|---|
| 0-20 | published reward table exists | program is active and accepting |
| 0-25 | disclosed reports with actual amounts | resolved reports for this bug class |
| 0-20 | amounts recent (< 12 months) | response/triage stats published |
| 0-20 | multiple independent researchers report payment | policy explicitly qualifies this class |
| 0-15 | reward tiers match the severity you'd file | low duplicate pressure on this asset |

Band the total: `VERY HIGH >=85 · HIGH 70-84 · MEDIUM 50-69 · LOW 25-49 · INSUFFICIENT DATA <25 or <3 evidence items`.

Fewer than 3 independent evidence items ⇒ always `INSUFFICIENT DATA`, whatever the arithmetic says.

Every confidence score carries its `evidence_urls`. A score without citations is not a score.

---

## 4. Research confidence

Separate axis — how sure are you the bug is real and works as described?

| Level | Requires |
|---|---|
| `CONFIRMED` | reproduced locally, root cause traced to code, full quality gate passed |
| `HIGH` | patch diff clearly shows the flaw, repro attempted, minor gaps documented |
| `MEDIUM` | patch/advisory consistent, not yet reproduced (`UNREPRODUCED`) |
| `LOW` | single-source claim, no patch visible, no repro |
| `INSUFFICIENT EVIDENCE` | conflicting or absent primary sources |

`CONFIRMED` is reserved for the full §5 quality gate in SKILL.md. Everything else publishes as `RESEARCH CANDIDATE`.

---

## 5. Tie-breaking

Equal scores resolve in this order:
1. Lower duplicate risk
2. Lower privilege requirement (unauth wins)
3. Published reward > `REWARD_UNKNOWN`
4. Local reproduction feasible today
5. Fresher disclosure

Never break a tie with CVSS.

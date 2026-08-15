# <Impact> via <vulnerability class> in <component> (<auth level>)

## Summary

<3-4 sentences. What the flaw is, where it lives, who can trigger it, and what
they get. Written as fact, not possibility. No "could potentially".>

## Affected asset

- Asset: `<exact in-scope asset>`
- Program scope line covering it: "<quoted verbatim from the policy>"
- Policy URL: <url>
- Scope verified: <YYYY-MM-DD>
- Version observed: <version> (<how you determined it — non-intrusively>)

## Preconditions

<Privileges, configuration, feature flags, plugin combinations. State the
unusual ones plainly — a hidden precondition found at triage costs the report.>

## Technical details

<The flow, with file:line for source-available targets or request/response
pairs for hosted ones. Explain the mechanism, not just the symptom.>

### Root cause

<The missing control, named precisely, at the line where it should have been.>

## Reproduction

1. <numbered, copy-pasteable, deterministic>
2. <each step's expected output stated>
3. <ends with the observable proof>

Reproduced on: <local lab / in-scope live asset, within policy>
Lab detail: `poc.md`

## Impact

<What the attacker actually obtains, demonstrated. Tie it to the business:
whose data, how many records, what actions, what money. State demonstrated
impact separately from theoretical escalation, and label the latter INFERRED.>

## Severity

CVSS 3.1: <score> — `<vector>`

<Justify the vector components that a triager would push back on — especially
AV, PR, UI, and S. If the vendor published a different score, note the delta
and why.>

## Evidence

- Request/response pairs: <inline or attached>
- Versions and timestamps: <>
- Screenshots: <list — no real user data visible>

## Remediation

<The specific fix: the check to add, at which line, or the upgrade target.
Not "validate input".>

## References

- <vendor advisory>
- <fix commit>
- <CVE/GHSA record>

---
Tested within program policy. No data was accessed, modified, or exfiltrated
beyond what is shown above. Test accounts used: <A, B — both mine>.

# <VULN-ID> — <Product> <Vulnerability Class>

> One sentence: what an attacker gets, and at what privilege level.

| Field | Value |
|---|---|
| Product | <vendor> / <product> |
| Ecosystem | <wordpress \| npm \| saas \| cloud \| mobile \| ai \| ...> |
| Affected versions | <range> |
| Fixed version | <version> |
| CVE | <CVE-YYYY-NNNNN \| none> |
| GHSA | <GHSA-xxxx \| none> |
| CVSS 3.1 | <score> `<vector>` (<published by vendor \| self-scored INFERRED>) |
| CWE | CWE-<n> |
| EPSS | <value \| UNKNOWN> |
| CISA KEV | <yes \| no> |
| Severity | <critical \| high \| medium> |
| Authentication | <none \| user \| role> |
| Privilege required | <none \| low \| high> |
| Attack vector | <network \| adjacent \| local> |
| User interaction | <none \| required> |

## Prerequisites
<config, plugin combination, feature flag, non-default settings — stated honestly>

## Root cause
<one sentence naming the missing control>

## Source → sink
```
entry point       <route/handler>       file:line
source            <parameter/header>    file:line
missing control   <what the patch added> file:line (fixed)
sink              <dangerous call>      file:line
```

## Impact
- Confidentiality: <>
- Integrity: <>
- Availability: <>
- Account / tenant / business: <>

## Patch analysis
Fix commit: <sha> — <url>
What the fix changed: <>
Fix complete? <yes | no — variant described below>
Variants found: <yes: ... | none found | not assessed>

## Detection
<nuclei template path, log signature, or "detection omitted: cannot detect without exploiting">

## Program eligibility
| Program | Platform | Asset in scope | Reward range | Payout conf. | Acceptance conf. |
|---|---|---|---|---|---|

## Duplicate assessment
Classification: <LOW DUPLICATE RISK \| UNKNOWN \| POSSIBLE \| LIKELY \| KNOWN>
Searched: <where you looked>
Evidence: <what you found>

## Confidence
Research confidence: <CONFIRMED \| HIGH \| MEDIUM \| LOW \| INSUFFICIENT EVIDENCE>
Reproduced locally: <yes \| UNREPRODUCED — reason>
Every claim above is labeled VERIFIED / INFERRED / UNKNOWN in the report.

## References
- <T1 vendor advisory>
- <T1 fix commit>
- <T2 database entry>

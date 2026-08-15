# Module: Local Lab & Proof of Concept

Loaded for S10. Reproduce locally first, always. A live asset is the last resort, never the first.

---

## 1. Lab rules

- Isolated container/VM, throwaway data, no network path to anything real.
- Pin the **vulnerable** version exactly; keep the **fixed** version alongside to prove the delta.
- Local-only bind (`127.0.0.1`), no public exposure of a knowingly vulnerable instance.
- Seed synthetic users/data — never a copy of real production data.
- Tear down after; keep only text output, redacted transcripts, and the compose file.

---

## 2. Patterns

**Generic web/API**
```yaml
# docker-compose.yml
services:
  app:
    image: <product>:<VULNERABLE_VERSION>
    ports: ["127.0.0.1:8080:80"]
    environment: [ "APP_ENV=development" ]
  db:
    image: mysql:8
    environment: [ "MYSQL_ROOT_PASSWORD=labonly", "MYSQL_DATABASE=app" ]
```

**WordPress plugin/theme** → `modules/wordpress.md` §lab.

**Language package**
```bash
python3 -m venv .venv && .venv/bin/pip install "<pkg>==<VULNERABLE>"
npm init -y && npm i <pkg>@<VULNERABLE>
```
Drive the vulnerable API directly from a 20-line harness — no full app needed.

**Cloud/IaC/CI** → reproduce the misconfiguration in a personal sandbox account or with `localstack`/`act`; never in the target's tenant.

Record the exact image digest / commit / package hash so the lab is rebuildable months later.

---

## 3. Reproduction discipline

Run each step against **both** versions:

```
1. baseline    normal request → normal response (proves the lab works)
2. trigger     minimal payload on vulnerable version → security behavior observed
3. control     same payload on fixed version → blocked/sanitized/denied
4. boundary    what is the least privilege that still works?
5. evidence    capture request + response, timestamps, versions
```

Step 3 is what separates a real finding from a misread. If the "fixed" version behaves identically, you have not found the bug — go back to the diff.

Minimal payload only: prove the *mechanism*, not the maximum blast radius. Read `/etc/hostname`, not `/etc/shadow`. `id`, not a reverse shell. One record you created, not a table dump.

---

## 4. Never build

Internet-wide scanners or target-list exploiters · mass exploitation automation · credential harvesting/stuffing · persistence, backdoors, implants · destructive payloads (delete/encrypt/overwrite) · evasion tooling for real defenses · anything runnable against an arbitrary host with one flag.

A PoC targets **one lab instance you control**, with the target hardcoded to localhost and a required explicit confirmation flag if it does anything at all beyond a request.

---

## 5. `poc.md` structure

```markdown
# PoC — <vuln id> <product> <version>

⚠️ Lab-only. Authorized in-scope testing only. Never run against a system you do not own.

## Environment
Product / vulnerable version / fixed version / image digest / OS / config deltas

## Preconditions
Privilege level, plugins/features enabled, non-default settings, seeded state

## Setup
<copy-pasteable commands that stand up the lab from nothing>

## Step 1 — Baseline
<request> → <response>

## Step 2 — Trigger (vulnerable)
<minimal request> → <observed security-relevant response>

## Step 3 — Control (patched)
<same request> → <blocked/sanitized response>

## Observed impact
Exactly what the attacker obtained. No speculation, no "could potentially".

## Root cause
One sentence + file:line.

## Cleanup
docker compose down -v
```

---

## 6. Live validation (only if S3 verified scope AND policy permits)

Minimum non-destructive proof, nothing more:
- one request, benign marker payload, your own test account, your own data
- respect rate limits and any required identifying header (`X-Bug-Bounty: <handle>`)
- stop at first proof — no enumeration, no pivoting, no second host
- if the program forbids automated scanning, that includes nuclei

`bbhunt.sh --phases recon <verified-domain>` is the passive default. Escalating beyond recon needs an explicit policy statement allowing it, quoted in the report.

Cannot verify authorization → `RESEARCH-ONLY / NO ACTIVE TESTING`, and the finding stands on the local lab alone.

Could not reproduce → `UNREPRODUCED`, and say what blocked it. That is a legitimate, useful result.

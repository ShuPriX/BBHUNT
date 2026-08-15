# PoC — <VULN-ID> <Product> <vulnerable version>

> ⚠️ Lab-only. Run against the local instance built below, or against an asset
> explicitly in scope for a program that permits this technique. Never against
> a system you do not own or are not authorized to test.

## Environment

| | |
|---|---|
| Product | <product> |
| Vulnerable version | <version> |
| Fixed version | <version> |
| Image / package digest | <sha256:...> |
| Host OS | <> |
| Config deltas from default | <none \| listed below> |

## Preconditions

- Privilege level: <unauthenticated \| subscriber \| user \| role X>
- Enabled features/plugins: <>
- Seeded state: <synthetic users/objects created in setup>

## Setup

```bash
# stands the lab up from nothing — copy-pasteable
```

## Step 1 — Baseline (proves the lab works)

```http
<request>
```
Expected: `<normal response>`

## Step 2 — Trigger (vulnerable version)

```http
<minimal request — prove the mechanism, not the blast radius>
```
Observed: `<security-relevant response>`

## Step 3 — Control (patched version)

Swap to the fixed version and repeat Step 2 unchanged.

```bash
# version swap command
```
Observed: `<blocked / sanitized / denied>`

> If Step 3 behaves identically to Step 2, the finding is not confirmed —
> return to the patch diff.

## Step 4 — Minimum privilege

Lowest privilege at which Step 2 still succeeds: <>

## Observed impact

<Exactly what was obtained. Facts only. No speculation.>

## Root cause

<One sentence + file:line.>

## Cleanup

```bash
docker compose down -v
```

## Safety notes

- No data was accessed beyond synthetic records created in setup.
- Payload is inert: <describe the benign marker used>.
- This PoC targets `127.0.0.1` only and has no target parameter.

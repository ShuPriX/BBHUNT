# Module: APIs (REST / GraphQL / gRPC)

APIs pay because authorization is per-endpoint and the surface is larger than the UI implies. Schema first, then boundaries.

---

## 1. Get the schema

OpenAPI/Swagger at `/openapi.json`, `/swagger.json`, `/v*/api-docs`, `/docs`, `/redoc` · Postman collections in public workspaces · JS bundles (every endpoint the SPA calls) · mobile app strings/network logs · public API docs and SDK repos.

Compare documented vs. observed: endpoints the SDK calls but the docs omit are the ones with weaker review.

---

## 2. Authorization matrix (the core test)

Build it once per API, fill it deliberately:

```
rows    = every state-changing endpoint
columns = unauth | user A | user B | different tenant | lower role | revoked token | expired token
cells   = expected vs. actual
```

Findings live in the cells where actual ≠ expected. Specifically test:
- object IDs from A replayed by B (and any tenant/org header swapped)
- role-restricted endpoints called directly, bypassing the UI that hides them
- the same object through a *different* endpoint (v1 vs v2, bulk vs single, export vs read, GraphQL vs REST) — old versions frequently miss the newer check
- HTTP method swap (`GET`→`PUT`/`PATCH`/`DELETE`) and override headers (`X-HTTP-Method-Override`)
- mass assignment: post `role`, `is_admin`, `owner_id`, `tenant_id`, `verified`, `credits` into a normal update

---

## 3. GraphQL

```
introspection      is it enabled in production? (schema = full map)
field authz        is authz on the resolver or only on the parent query?
nested traversal   user { organization { members { email } } } — cross-boundary via nesting
aliases            same mutation aliased N times = rate-limit / one-time-use bypass
batching           array-of-queries bypasses per-request throttles
mutations          the state-changing ones are usually less reviewed than queries
error text         verbose resolver errors leak internals and field names
depth/complexity   unbounded nesting is DoS — report as design, never demonstrate at scale
```
Disabled introspection is not protection: recover the schema from the client bundle, error-message suggestions, and known field-name conventions.

---

## 4. Tokens

JWT: `alg:none`, algorithm confusion (RS→HS with the public key), `kid` path traversal / SQLi, unverified `jku`/`x5u`, missing `exp`, missing audience/issuer check, secret guessable, claim trust (`is_admin` in an unsigned segment).
Sessions: does logout revoke server-side? does password change invalidate other sessions? is the refresh token single-use? does an API key inherit more scope than the user who created it?

---

## 5. Rate limiting & keys

Per-account limits that are actually per-IP (or vice versa) · limits reset by case-changing the path, adding a trailing slash, or switching API version · limits absent on the bulk/batch endpoint that exists alongside the throttled single endpoint.

Report rate-limit gaps only when they enable something real (brute force of a token, OTP, coupon, invite). A bare "no rate limit" is in `config/exclusions.yaml` for a reason.

---

## 6. Safety

Read endpoints over write endpoints. Your own objects only. Never enumerate a real ID range — one adjacent ID you own proves the check is missing. Never load-test. Never call a payment, provisioning, or notification endpoint in a way that reaches real people (no invites, no SMS, no email blasts).

# Module: Web Applications & SaaS

For hosted targets where you cannot read the source. Everything here is scope-gated: verify first, then test the minimum.

---

## 1. Surface mapping (passive first)

Public artifacts before any traffic: JS bundles and source maps, `/.well-known/`, OpenAPI/GraphQL schema files, mobile app API strings, public GitHub org, job posts, status page, docs site, changelog.

JS bundles are the highest-yield passive source: undocumented endpoints, feature flags, role names, internal hostnames, client-side authorization logic, tenant identifiers, third-party keys.

Then, in scope only: subdomain and path discovery, tech fingerprint, auth flows, roles. `bbhunt.sh --phases recon <domain>` covers the passive sweep.

---

## 2. What actually pays

| Class | The question that finds it |
|---|---|
| Broken object-level authz (IDOR) | does the server re-check ownership, or trust the ID? Test with two accounts, always. |
| Broken function-level authz | can a low role call the high role's endpoint directly? |
| Cross-tenant leakage | does swapping the tenant/org header or ID cross the boundary? |
| Authn bypass | password reset token entropy/reuse, email-change race, OAuth `state`/`redirect_uri`, SSO account linking on unverified email, JWT `alg`/`kid`/key confusion |
| Business logic | negative quantities, currency/rounding, coupon stacking, quota reset, plan downgrade retaining entitlements, step-skipping in a multi-stage flow |
| Race conditions | limited-use action fired concurrently (invite, coupon, withdrawal, vote) |
| SSRF | any server-side fetch: webhooks, importers, PDF/screenshot renderers, SVG/image processing, URL previews, SSO metadata URLs |
| Stored XSS with reach | does it fire in another user's or admin's session? Self-XSS is nothing. |
| File upload | extension/content-type/magic-byte handling, storage location, is it served executable, is it served same-origin |
| Cache poisoning / smuggling | unkeyed headers reflected in cached responses; CL.TE / TE.CL / H2.CL desync |

---

## 3. The two-account rule

Every authorization test needs two accounts you control (and, for tenancy, two orgs). Testing an IDOR against a stranger's object is testing against a real user — do not. Create account A, create account B, act as A on B's identifiers.

If the program does not allow multiple accounts, ask for a test account or drop the class.

---

## 4. Discipline on live targets

- Identify yourself if the policy asks (`X-Bug-Bounty:` / `X-HackerOne:` header, or the required UA).
- Respect rate limits. Automated scanning only if the policy allows it in writing.
- Never test destructive flows (delete account, cancel subscription, wipe workspace) on anything but your own objects.
- Stop at proof. One request that demonstrates the boundary crossing, then write it up.
- Never touch: other users' data, production admin panels you got into, payment rails with real money.

Anything that would degrade service for real users is out — including "just a quick" concurrency test at volume.

---

## 5. Correlation angle (why this module is in an intel pipeline)

The highest-value web findings here come from **known CVEs in a stack you fingerprinted**, not from blind poking:
`program tech_stack` says `nextjs`/`rails`/`confluence`/`gitlab` → a fresh advisory for that stack drops → check version exposure passively → verify the version is actually vulnerable → local lab repro → then, in scope, the minimum live confirmation.

That path beats untargeted fuzzing on both duplicate risk and time-to-report.

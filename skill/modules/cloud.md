# Module: Cloud, CI/CD & Supply Chain

Highest-severity category in the pipeline — a leaked cloud credential or a compromised build path is usually the top-tier payout. Also the easiest place to cause real damage, so the safety line is drawn tighter here than anywhere else.

---

## 1. Public exposure (passive, safe)

| Surface | What to look for |
|---|---|
| Object storage | public S3/GCS/Azure buckets named after the org, product, or environment; `ListBucket` permitted; write-permitted buckets (critical) |
| Registries | public ECR/GCR/Docker Hub images containing `.env`, keys, internal source |
| Source | public repos, forks, gists, and **git history** — deleted secrets stay in old commits |
| Artifacts | published npm/PyPI packages, mobile app bundles, source maps, sourcemaps in prod |
| DNS | dangling CNAMEs to deprovisioned cloud resources → subdomain takeover |
| Metadata leaks | Terraform state files, `.tfstate`, `kubeconfig`, `docker-compose` with credentials, CI logs |

Never write to a writable bucket to "prove" it — list one object name, or write to a uniquely-named key **only** if the policy permits and you delete it, and say so. Prefer the read-only proof.

---

## 2. Credentials

Verify a discovered credential is live only when the policy allows it, and only with the most benign identity call:
`aws sts get-caller-identity` · `gcloud auth list` / token introspection · `az account show` · GitHub `GET /user` · Slack `auth.test` · Stripe `GET /v1/account`.

Then **stop**. Do not enumerate permissions, do not list resources, do not read data, do not create anything. The identity call is the proof; scope of access is described from the token's documented capabilities, labeled `INFERRED`.

Report immediately — a live key is a live key for attackers too. Rotate-first courtesy note in the report.

---

## 3. SSRF → metadata

The classic chain: any server-side fetch → `169.254.169.254` → instance role credentials → cloud account access.

Check IMDSv2 enforcement (v1 still enabled = the bug), and the equivalents: GCP `metadata.google.internal` with `Metadata-Flavor: Google`, Azure IMDS with `Metadata: true`, Kubernetes `kubernetes.default.svc` + mounted service account token, Docker socket exposure.

Proof = retrieving the role name or a token *prefix*. Never use the retrieved credential.

---

## 4. CI/CD

| Weakness | Impact |
|---|---|
| `pull_request_target` + checkout of PR head | attacker code runs with repo secrets — critical |
| Untrusted input into `run:` (`github.event.*` interpolation) | script injection in the runner |
| Overly broad `GITHUB_TOKEN` permissions | write to repo/packages from a workflow |
| Unpinned third-party actions (`@main`) | supply-chain takeover path |
| Self-hosted runners on public repos | code execution on their infrastructure |
| Secrets echoed in logs / artifacts | credential disclosure |
| Missing OIDC subject conditions in the cloud trust policy | any repo can assume the role |

Read the workflow YAML — this is source-level analysis, no testing required. It is one of the highest signal-to-noise sources in the whole pipeline.

---

## 5. Supply chain

Dependency confusion (internal package names unclaimed on public registries — **claim nothing**; report the unclaimed name), typosquat-adjacent naming, unmaintained direct dependencies with known CVEs, install scripts pulling from mutable URLs, missing lockfile integrity, package repo write access left broad.

Never publish a package, never register the name, never push to a registry to demonstrate. Publishing *is* the attack.

---

## 6. Kubernetes / containers

Exposed API server or kubelet (`:10250`), unauthenticated dashboards, permissive RBAC (`cluster-admin` to a service account), privileged pods / `hostPath` mounts, secrets in env vars or ConfigMaps, exposed etcd, image `latest` with no digest pinning, container escape primitives.

---

## 7. Hard limits

No resource creation, deletion, or modification. No data reads beyond the single identity proof. No lateral movement. No persistence. No pivoting into the network. No load. If a proof requires any of these, the correct output is a description of the exposure with `INFERRED` impact — a triager will accept that; an incident will not be forgiven.

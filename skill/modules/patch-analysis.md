# Module: Patch & Root-Cause Analysis

Loaded for S9. Goal: turn "there is a CVE" into "here is the exact line, the exact input, and the exact missing control."

---

## 1. Acquire both versions

Prefer the official distribution channel, verify integrity where published.

```bash
mkdir -p /tmp/bbhunt-diff/{vuln,fixed} && cd /tmp/bbhunt-diff

# git-hosted
git clone --quiet <repo> src && cd src
git log --oneline <fixed_tag> -20
git show <fix_commit> > ../changes.diff
git diff <vuln_tag> <fixed_tag> -- <path> > ../full.diff

# release tarballs / packaged artifacts
curl -sSLo vuln.zip  <vulnerable_release_url>
curl -sSLo fixed.zip <fixed_release_url>
unzip -q vuln.zip -d vuln/ && unzip -q fixed.zip -d fixed/
diff -ruN vuln/ fixed/ > changes.diff

# ecosystem packages
npm pack <pkg>@<vuln> && npm pack <pkg>@<fixed>
pip download <pkg>==<vuln> --no-deps -d vuln/
```

If the fix is only in a binary release with no source, say `INSUFFICIENT EVIDENCE` for root cause and score exploitability as `INFERRED` — do not guess at decompiled intent and present it as fact.

Record: repo URL, both refs/versions, fix commit SHA, diff size. These are the `source_fingerprint` for state.

---

## 2. Narrow the diff

Real fixes are usually small and hide inside release noise. Strip the noise first:

```bash
# ignore vendored deps, lockfiles, minified bundles, changelogs, i18n
diff -ruN --exclude=node_modules --exclude=vendor --exclude='*.min.*' \
     --exclude='*.po' --exclude='*.map' vuln/ fixed/ > changes.diff
grep -c '^[+-]' changes.diff
git show --stat <fix_commit>
```

Then rank the changed hunks by security relevance:

| Signal | Look for |
|---|---|
| authn | session, login, token verify, jwt, signature, `verify_*`, `authenticate` |
| authz | capability/permission/role checks, `current_user`, ownership comparison, tenant id |
| CSRF/nonce | nonce creation+check, `SameSite`, state parameter, referer checks |
| injection | new escaping/parameterization, `prepare`, `quote`, allowlists, regex tightening |
| path | `realpath`, `basename`, traversal filters, canonicalization, `..` handling |
| SSRF | URL parsing, host/IP allowlists, redirect following, scheme checks |
| deser | `unserialize`, `pickle`, `yaml.load`, `ObjectInputStream`, gadget guards |
| template | autoescape flags, sandbox settings, user-controlled template strings |
| upload | extension/MIME/magic checks, storage path, execution prevention |
| crypto | comparison made constant-time, randomness source, key handling |

A one-line diff adding a permission check *is* the whole vulnerability. Do not skim past it looking for something bigger.

---

## 3. Root-cause trace

Answer these, in order, with file:line for each:

```
1. Entry point         which route/handler/hook/endpoint is reachable?
2. Reachability        who can reach it — unauth / any user / role X?
3. Source              which attacker-controlled input arrives there?
4. Path                how does it flow — variables, calls, storage?
5. Missing control     what did the patch add, and where was its absence?
6. Sink                which dangerous operation consumes the input?
7. Class + CWE         name the class, map the CWE
8. Preconditions       config, plugin combination, feature flag, non-default setting?
9. Impact              what does the attacker actually get?
10. Reliability        deterministic, or race/heap/timing dependent?
```

Note honestly when a precondition is unusual — "requires a non-default setting enabled by ~nobody" is the difference between a paid critical and a wasted week. Preconditions belong in the report, not buried.

---

## 4. Variant hunting (highest-value step)

The patched bug is public and duplicate-heavy. The *variant* usually is not.

- Same sink, other call sites: `grep -rn "<sink_function>" fixed/`
- Same missing check across sibling handlers — did they fix one endpoint and miss three?
- Is the fix complete? Try the original payload with encoding, alternate parameter, alternate HTTP method, array-vs-string type, unicode, double encoding.
- Did the fix introduce a new reachable path?
- Do other products vendor this same code?

An incomplete-fix finding is often worth more than the original CVE and carries far lower duplicate risk. Route it to the vendor's program as a new issue with its own root cause.

---

## 5. Output

`changes.diff` (trimmed to the security-relevant hunks, with a header noting what was excluded) plus this block in `README.md`:

```
Root cause:      <one sentence, names the missing control>
Entry point:     <route/handler>          file:line
Source:          <parameter/header/field> file:line
Sink:            <dangerous call>         file:line
Missing control: <what the patch added>   file:line (fixed)
Fix commit:      <sha> <url>
Class / CWE:     <class> / CWE-<n>
Preconditions:   <config, privilege, non-default settings>
Reliability:     <deterministic | conditional | racy>
Variants found:  <yes: ... | none found | not assessed>
Confidence:      VERIFIED | INFERRED | UNKNOWN
```

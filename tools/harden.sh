#!/usr/bin/env bash
# harden — apply BBHUNT's repository security controls. Idempotent.
#
#   tools/harden.sh            apply everything
#   tools/harden.sh --audit    report status, change nothing
#
# What it does:
#   1. enables the local git hooks (pre-commit / pre-push secret scanning)
#   2. records repo visibility so the disclosure guard knows how to behave
#   3. verifies GitHub secret scanning + push protection are on
#   4. confirms no key is committed and none is in git history
#   5. confirms the local key file lives outside the repo with mode 600

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1
AUDIT=0; [[ "${1:-}" == "--audit" ]] && AUDIT=1

C_G='\033[1;32m'; C_Y='\033[1;33m'; C_R='\033[1;31m'; C_B='\033[1;34m'; C_0='\033[0m'
ok()   { printf "${C_G}[+]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!]${C_0} %s\n" "$*"; }
err()  { printf "${C_R}[x]${C_0} %s\n" "$*"; }
sec()  { printf "\n${C_B}── %s${C_0}\n" "$*"; }

ISSUES=0

sec "1. git hooks"
if [[ "$AUDIT" -eq 0 ]]; then
  chmod +x .githooks/* tools/*.sh 2>/dev/null
  git config core.hooksPath .githooks
  ok "core.hooksPath = .githooks (pre-commit + pre-push secret scanning active)"
else
  HP="$(git config --get core.hooksPath || echo unset)"
  [[ "$HP" == ".githooks" ]] && ok "hooks enabled" || { warn "hooks NOT enabled (core.hooksPath=$HP)"; ISSUES=$((ISSUES+1)); }
fi

sec "2. repository visibility"
VIS="unknown"
if command -v gh >/dev/null 2>&1; then
  VIS="$(gh repo view --json visibility --jq '.visibility' 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo unknown)"
fi
case "$VIS" in
  public)
    warn "repository is PUBLIC"
    warn "  → committed research is world-readable; the disclosure guard is ACTIVE"
    warn "  → research/*/metadata.json needs \"public_disclosure_ok\": true to commit"
    [[ "$AUDIT" -eq 0 ]] && git config bbhunt.visibility public
    ;;
  private)
    ok "repository is private"
    [[ "$AUDIT" -eq 0 ]] && git config bbhunt.visibility private
    ;;
  *)
    warn "could not determine visibility (gh not authenticated?) — assuming public"
    [[ "$AUDIT" -eq 0 ]] && git config bbhunt.visibility public
    ;;
esac

sec "3. GitHub secret scanning"
if command -v gh >/dev/null 2>&1; then
  SS="$(gh api "repos/$(gh repo view --json nameWithOwner --jq .nameWithOwner)" \
        --jq '"\(.security_and_analysis.secret_scanning.status // "n/a") \(.security_and_analysis.secret_scanning_push_protection.status // "n/a")"' 2>/dev/null)"
  read -r SCAN PUSH <<< "$SS"
  [[ "$SCAN" == "enabled" ]] && ok "secret scanning: enabled" || { warn "secret scanning: $SCAN"; ISSUES=$((ISSUES+1)); }
  [[ "$PUSH" == "enabled" ]] && ok "push protection: enabled (server blocks known key formats)" \
                             || { warn "push protection: $PUSH"; ISSUES=$((ISSUES+1)); }
else
  warn "gh not installed — cannot verify server-side scanning"
fi

sec "4. secret scan"
if ./tools/secret-scan.sh tree >/dev/null 2>&1; then
  ok "working tree: clean"
else
  err "working tree: FINDINGS — run tools/secret-scan.sh tree"; ISSUES=$((ISSUES+1))
fi
if ./tools/secret-scan.sh history >/dev/null 2>&1; then
  ok "git history: clean"
else
  err "git history: FINDINGS — run tools/secret-scan.sh history"
  err "  a secret in history stays exposed after deletion from HEAD — ROTATE IT"
  ISSUES=$((ISSUES+1))
fi

sec "5. local key file"
KEYFILE="${BBHUNT_ENV_FILE:-${HOME}/.config/bbhunt/env}"
if [[ -f "$KEYFILE" ]]; then
  PERMS="$(stat -c '%a' "$KEYFILE" 2>/dev/null || stat -f '%Lp' "$KEYFILE" 2>/dev/null)"
  if [[ "$PERMS" == "600" ]]; then ok "key file present, mode 600, outside the repo"
  else
    warn "key file mode $PERMS"
    [[ "$AUDIT" -eq 0 ]] && { chmod 600 "$KEYFILE"; ok "tightened to 600"; } || ISSUES=$((ISSUES+1))
  fi
else
  warn "no local key file — run: tools/bbenv.sh --set"
fi
case "$KEYFILE" in
  "$REPO_ROOT"*) err "KEY FILE IS INSIDE THE REPOSITORY — move it out immediately"; ISSUES=$((ISSUES+1)) ;;
esac

sec "6. tracked-file sanity"
if git ls-files | grep -qE '^(hunts/|loot/)|(^|/)\.env$|\.pem$|\.p12$'; then
  err "sensitive paths are TRACKED:"; git ls-files | grep -E '^(hunts/|loot/)|(^|/)\.env$|\.pem$|\.p12$'
  ISSUES=$((ISSUES+1))
else
  ok "no hunt output, .env, or key material tracked"
fi

echo
if [[ "$ISSUES" -eq 0 ]]; then
  ok "hardening complete — no issues"
else
  warn "hardening complete — ${ISSUES} issue(s) above need attention"
fi
exit 0

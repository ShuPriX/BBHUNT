#!/usr/bin/env bash
# secret-scan — the one place BBHUNT decides whether something is safe to commit.
#
# Used by the pre-commit hook, the pre-push hook, and CI, so all three enforce
# exactly the same rules.
#
#   tools/secret-scan.sh staged     scan the staged diff        (pre-commit)
#   tools/secret-scan.sh tree       scan the working tree       (pre-push / CI)
#   tools/secret-scan.sh history    scan all git history        (audit)
#
# Exit 0 = clean, 1 = blocked. Findings are redacted — this script never
# prints a secret it finds.

set -uo pipefail

MODE="${1:-staged}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${REPO_ROOT}/.gitleaks.toml"

C_G='\033[1;32m'; C_Y='\033[1;33m'; C_R='\033[1;31m'; C_0='\033[0m'
ok()   { printf "${C_G}[+]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!]${C_0} %s\n" "$*"; }
err()  { printf "${C_R}[x]${C_0} %s\n" "$*" >&2; }

cd "$REPO_ROOT" || exit 1
FAILED=0

# ── 1. never commit hunt output or local env files ──────────────────
case "$MODE" in
  staged) FILES="$(git diff --cached --name-only --diff-filter=ACM)" ;;
  *)      FILES="$(git ls-files)" ;;
esac

if [[ -n "$FILES" ]]; then
  BLOCKED="$(printf '%s\n' "$FILES" | grep -E '^(hunts/|loot/)|(^|/)\.env$|(^|/)\.env\.[^e]|\.pem$|\.p12$|(^|/)cookies\.txt$|(^|/)credentials\.json$' || true)"
  if [[ -n "$BLOCKED" ]]; then
    err "these paths must never be committed:"
    printf '      %s\n' $BLOCKED
    FAILED=1
  fi
fi

# ── 2. gitleaks ─────────────────────────────────────────────────────
if command -v gitleaks >/dev/null 2>&1; then
  case "$MODE" in
    staged)
      gitleaks git --staged --no-banner --redact -c "$CONFIG" . >/dev/null 2>&1 || {
        err "gitleaks found a secret in the STAGED changes"
        gitleaks git --staged --no-banner --redact -c "$CONFIG" . 2>&1 | grep -E 'Finding|RuleID|File|Line' | head -20
        FAILED=1
      }
      ;;
    tree)
      gitleaks dir --no-banner --redact -c "$CONFIG" . >/dev/null 2>&1 || {
        err "gitleaks found a secret in the working tree"
        gitleaks dir --no-banner --redact -c "$CONFIG" . 2>&1 | grep -E 'Finding|RuleID|File|Line' | head -20
        FAILED=1
      }
      ;;
    history)
      gitleaks git --no-banner --redact -c "$CONFIG" . >/dev/null 2>&1 || {
        err "gitleaks found a secret in git HISTORY"
        err "a secret in history is still exposed even if deleted from HEAD — rotate it"
        gitleaks git --no-banner --redact -c "$CONFIG" . 2>&1 | grep -E 'Finding|RuleID|File|Commit' | head -20
        FAILED=1
      }
      ;;
  esac
else
  warn "gitleaks not installed — falling back to regex scan (weaker)"
  CONTENT=""
  case "$MODE" in
    staged) CONTENT="$(git diff --cached -U0)" ;;
    *)      CONTENT="$(git ls-files -z | xargs -0 cat 2>/dev/null)" ;;
  esac
  if printf '%s' "$CONTENT" \
     | grep -qE 'sk-ant-[A-Za-z0-9_-]{16,}|(?i)BEGIN [A-Z ]*PRIVATE KEY'; then
    err "possible credential detected (regex fallback)"
    FAILED=1
  fi
fi

# ── 3. public-repo disclosure guard ─────────────────────────────────
# This repo may be public. Vulnerability research committed before the vendor
# has shipped a fix is a public 0-day disclosure — it breaches most program
# policies and can void the bounty.
RESEARCH="$(printf '%s\n' "$FILES" | grep -E '^research/' || true)"
if [[ -n "$RESEARCH" ]]; then
  VISIBILITY="$(git config --get bbhunt.visibility || echo unknown)"
  if [[ "$VISIBILITY" != "private" ]]; then
    UNSAFE=0
    while IFS= read -r meta; do
      [[ "$meta" == */metadata.json ]] || continue
      [[ -f "$meta" ]] || continue
      if ! grep -q '"public_disclosure_ok"[[:space:]]*:[[:space:]]*true' "$meta"; then
        warn "not cleared for public disclosure: $(dirname "$meta")"
        UNSAFE=1
      fi
    done <<< "$RESEARCH"
    if [[ "$UNSAFE" -eq 1 ]]; then
      err "research artifacts staged for a PUBLIC repo without disclosure clearance"
      err "set \"public_disclosure_ok\": true in metadata.json only after the fix"
      err "is public and the program permits disclosure. See SECURITY.md."
      FAILED=1
    fi
  fi
fi

if [[ "$FAILED" -eq 0 ]]; then
  ok "secret-scan (${MODE}): clean"
  exit 0
fi
err "secret-scan (${MODE}): BLOCKED"
exit 1

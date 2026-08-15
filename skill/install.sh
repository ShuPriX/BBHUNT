#!/usr/bin/env bash
# Install the BBHUNT skill so the trigger word works in any Claude Code session.
#
# The canonical skill lives in this repo (skill/SKILL.md + modules/ + state/).
# This writes a small pointer skill into ~/.claude/skills/bbhunt/ that loads it,
# so the repo stays the single source of truth and edits take effect immediately
# with no re-install.
#
#   ./skill/install.sh              install for the current user
#   ./skill/install.sh --uninstall  remove the pointer
#   ./skill/install.sh --check      show install status

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_DIR="${HOME}/.claude/skills/bbhunt"
TARGET="${SKILL_DIR}/SKILL.md"

C_G='\033[1;32m'; C_Y='\033[1;33m'; C_R='\033[1;31m'; C_0='\033[0m'
ok()   { printf "${C_G}[+]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!]${C_0} %s\n" "$*"; }
err()  { printf "${C_R}[x]${C_0} %s\n" "$*" >&2; }

case "${1:-}" in
  --uninstall)
    if [[ -e "$TARGET" ]]; then
      rm -rf "$SKILL_DIR"; ok "removed $SKILL_DIR"
    else
      warn "not installed"
    fi
    exit 0
    ;;
  --check)
    if [[ -f "$TARGET" ]]; then
      ok "installed: $TARGET"
      grep -m1 'BBHUNT_ROOT:' "$TARGET" || true
    else
      warn "not installed — run ./skill/install.sh"
    fi
    exit 0
    ;;
  -h|--help)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

[[ -f "${REPO_ROOT}/skill/SKILL.md" ]] || { err "canonical skill missing at ${REPO_ROOT}/skill/SKILL.md"; exit 1; }

mkdir -p "$SKILL_DIR"

cat > "$TARGET" <<EOF
---
name: bbhunt
description: Autonomous high-impact bug bounty intelligence and vulnerability research. Trigger word BBHUNT runs the full daily pipeline — program discovery, vulnerability correlation, scope verification, opportunity scoring, patch analysis, lab-safe reproduction, report/PoC generation, and repo state update. Use when the user says BBHUNT, asks for the daily hunt, asks "what is worth researching right now", asks to rank bug bounty programs by payout/acceptance evidence, or asks to research a specific CVE/GHSA for bounty eligibility.
---

# BBHUNT

BBHUNT_ROOT: \`${REPO_ROOT}\`

**Read \`${REPO_ROOT}/skill/SKILL.md\` now and follow it.** That file is the
canonical skill — run protocol, module routing, state contract, quality gate,
and output contract. Load modules from \`${REPO_ROOT}/skill/modules/\` only as
the routing table calls for them.

These rules hold regardless of what else loads:

- No active testing until the asset is verified in scope against the current
  official program policy. Unverified → \`RESEARCH-ONLY / NO ACTIVE TESTING\`.
- Reproduce locally before touching any live asset; then only the minimum
  non-destructive proof the policy permits.
- Never: DoS, destructive testing, data exfiltration, credential theft,
  persistence, malware, evasion, or mass exploitation.
- Never fabricate CVEs, rewards, payout rates, or acceptance statistics.
  Missing data is \`REWARD_UNKNOWN\` / \`INSUFFICIENT DATA\`.
- Never commit secrets or hunt output to the repository.
- Finding nothing is a valid result:
  \`NO HIGH-CONFIDENCE HIGH-IMPACT OPPORTUNITY FOUND TODAY\`.
EOF

ok "installed pointer skill → $TARGET"
ok "canonical skill        → ${REPO_ROOT}/skill/SKILL.md"
echo
echo "  Start a new Claude Code session and type:  BBHUNT"
echo
warn "Edits to ${REPO_ROOT}/skill/ take effect immediately — no re-install needed."
warn "Re-run this script only if you move the repository."

#!/usr/bin/env bash
# bbhunt — modular bug bounty recon + vuln pipeline
#
# Phases:
#   1. subdomain enumeration   (subfinder, amass)
#   2. dns resolution          (dnsx)
#   3. live host probing       (httpx)
#   4. url harvesting          (gau, katana)
#   5. vuln scanning           (nuclei)
#   6. xss probing             (gf + dalfox)
#
# ⚠️  ONLY run against targets you are explicitly authorized to test
#     (your own assets, or in-scope assets of a bug bounty program).
#
# Usage:
#   bbhunt example.com
#   bbhunt -o ~/hunts example.com
#   bbhunt --phases recon example.com         # recon only (phases 1-4)
#   bbhunt --phases 1,2,3 example.com          # specific phases
#   bbhunt --quick example.com                 # skip slow steps (amass, full nuclei)
#   bbhunt -y example.com                      # skip the authorization prompt
#   bbhunt --darkweb example.com               # also search Tor onion indexes (needs tor)
#   bbhunt --phases osint example.com          # OSINT + crawl only (phase 7)
#
# Extra phases added (append to existing 1-6):
#   7. osint & deep crawl  (whois, theHarvester, crt.sh, wayback, shodan-cli)
#   8. darkweb search      (onion indexes via torsocks+curl — requires --darkweb flag)
#
# findings/ directory (inside each run):
#   critical.txt        ← nuclei critical severity hits
#   high.txt            ← nuclei high severity hits
#   xss-confirmed.txt   ← dalfox confirmed XSS
#   osint-summary.txt   ← WHOIS, emails, ASN, cert transparency
#   darkweb.txt         ← darkweb index hits (only with --darkweb)

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────
TARGET=""
OUTROOT="${HOME}/Desktop/Apps/bbhunt/hunts"
PHASES="1,2,3,4,5,6,7"
QUICK=0
ASSUME_YES=0
THREADS=50
DARKWEB=0

C_RESET='\033[0m'; C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'; C_RED='\033[1;31m'; C_DIM='\033[2m'

log()  { printf "${C_BLUE}[*]${C_RESET} %s\n" "$*"; }
ok()   { printf "${C_GREEN}[+]${C_RESET} %s\n" "$*"; }
warn() { printf "${C_YELLOW}[!]${C_RESET} %s\n" "$*"; }
err()  { printf "${C_RED}[x]${C_RESET} %s\n" "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Print the leading comment header (skip shebang, stop at first non-# line).
usage() {
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
  exit "${1:-0}"
}

# ── BBHUNT BANNER ────────────────────────────────────────────────────
print_banner() {
  echo ""
  echo -e "\033[38;2;232;255;26m█\033[38;2;147;255;26m█\033[38;2;63;255;26m█\033[38;2;26;255;73m█\033[38;2;26;255;158m█\033[38;2;26;255;243m█\033[38;2;26;183;255m╗ \033[38;2;38;26;255m█\033[38;2;123;26;255m█\033[38;2;207;26;255m█\033[38;2;255;26;218m█\033[38;2;255;26;133m█\033[38;2;255;26;48m█\033[38;2;255;87;26m╗ \033[38;2;253;255;26m█\033[38;2;168;255;26m█\033[38;2;84;255;26m╗  \033[38;2;26;255;221m█\033[38;2;26;204;255m█\033[38;2;26;119;255m╗\033[38;2;26;34;255m█\033[38;2;101;26;255m█\033[38;2;186;26;255m╗   \033[38;2;255;66;26m█\033[38;2;255;151;26m█\033[38;2;255;236;26m╗\033[38;2;190;255;26m█\033[38;2;105;255;26m█\033[38;2;26;255;31m█\033[38;2;26;255;116m╗   \033[38;2;26;56;255m█\033[38;2;80;26;255m█\033[38;2;165;26;255m╗\033[38;2;250;26;255m█\033[38;2;255;26;176m█\033[38;2;255;26;91m█\033[38;2;255;45;26m█\033[38;2;255;130;26m█\033[38;2;255;214;26m█\033[38;2;211;255;26m█\033[38;2;126;255;26m█\033[38;2;41;255;26m╗"
  echo -e "\033[38;2;232;255;26m█\033[38;2;147;255;26m█\033[38;2;63;255;26m╔\033[38;2;26;255;73m═\033[38;2;26;255;158m═\033[38;2;26;255;243m█\033[38;2;26;183;255m█\033[38;2;26;98;255m╗\033[38;2;38;26;255m█\033[38;2;123;26;255m█\033[38;2;207;26;255m╔\033[38;2;255;26;218m═\033[38;2;255;26;133m═\033[38;2;255;26;48m█\033[38;2;255;87;26m█\033[38;2;255;172;26m╗\033[38;2;253;255;26m█\033[38;2;168;255;26m█\033[38;2;84;255;26m║  \033[38;2;26;255;221m█\033[38;2;26;204;255m█\033[38;2;26;119;255m║\033[38;2;26;34;255m█\033[38;2;101;26;255m█\033[38;2;186;26;255m║   \033[38;2;255;66;26m█\033[38;2;255;151;26m█\033[38;2;255;236;26m║\033[38;2;190;255;26m█\033[38;2;105;255;26m█\033[38;2;26;255;31m█\033[38;2;26;255;116m█\033[38;2;26;255;200m╗  \033[38;2;26;56;255m█\033[38;2;80;26;255m█\033[38;2;165;26;255m║\033[38;2;250;26;255m╚\033[38;2;255;26;176m═\033[38;2;255;26;91m═\033[38;2;255;45;26m█\033[38;2;255;130;26m█\033[38;2;255;214;26m╔\033[38;2;211;255;26m═\033[38;2;126;255;26m═\033[38;2;41;255;26m╝"
  echo -e "\033[38;2;232;255;26m█\033[38;2;147;255;26m█\033[38;2;63;255;26m█\033[38;2;26;255;73m█\033[38;2;26;255;158m█\033[38;2;26;255;243m█\033[38;2;26;183;255m╔\033[38;2;26;98;255m╝\033[38;2;38;26;255m█\033[38;2;123;26;255m█\033[38;2;207;26;255m█\033[38;2;255;26;218m█\033[38;2;255;26;133m█\033[38;2;255;26;48m█\033[38;2;255;87;26m╔\033[38;2;255;172;26m╝\033[38;2;253;255;26m█\033[38;2;168;255;26m█\033[38;2;84;255;26m█\033[38;2;26;255;52m█\033[38;2;26;255;137m█\033[38;2;26;255;221m█\033[38;2;26;204;255m█\033[38;2;26;119;255m║\033[38;2;26;34;255m█\033[38;2;101;26;255m█\033[38;2;186;26;255m║   \033[38;2;255;66;26m█\033[38;2;255;151;26m█\033[38;2;255;236;26m║\033[38;2;190;255;26m█\033[38;2;105;255;26m█\033[38;2;26;255;31m╔\033[38;2;26;255;116m█\033[38;2;26;255;200m█\033[38;2;26;225;255m╗ \033[38;2;26;56;255m█\033[38;2;80;26;255m█\033[38;2;165;26;255m║   \033[38;2;255;45;26m█\033[38;2;255;130;26m█\033[38;2;255;214;26m║   "
  echo -e "\033[38;2;232;255;26m█\033[38;2;147;255;26m█\033[38;2;63;255;26m╔\033[38;2;26;255;73m═\033[38;2;26;255;158m═\033[38;2;26;255;243m█\033[38;2;26;183;255m█\033[38;2;26;98;255m╗\033[38;2;38;26;255m█\033[38;2;123;26;255m█\033[38;2;207;26;255m╔\033[38;2;255;26;218m═\033[38;2;255;26;133m═\033[38;2;255;26;48m█\033[38;2;255;87;26m█\033[38;2;255;172;26m╗\033[38;2;253;255;26m█\033[38;2;168;255;26m█\033[38;2;84;255;26m╔\033[38;2;26;255;52m═\033[38;2;26;255;137m═\033[38;2;26;255;221m█\033[38;2;26;204;255m█\033[38;2;26;119;255m║\033[38;2;26;34;255m█\033[38;2;101;26;255m█\033[38;2;186;26;255m║   \033[38;2;255;66;26m█\033[38;2;255;151;26m█\033[38;2;255;236;26m║\033[38;2;190;255;26m█\033[38;2;105;255;26m█\033[38;2;26;255;31m║\033[38;2;26;255;116m╚\033[38;2;26;255;200m█\033[38;2;26;225;255m█\033[38;2;26;140;255m╗\033[38;2;26;56;255m█\033[38;2;80;26;255m█\033[38;2;165;26;255m║   \033[38;2;255;45;26m█\033[38;2;255;130;26m█\033[38;2;255;214;26m║   "
  echo -e "\033[38;2;232;255;26m█\033[38;2;147;255;26m█\033[38;2;63;255;26m█\033[38;2;26;255;73m█\033[38;2;26;255;158m█\033[38;2;26;255;243m█\033[38;2;26;183;255m╔\033[38;2;26;98;255m╝\033[38;2;38;26;255m█\033[38;2;123;26;255m█\033[38;2;207;26;255m█\033[38;2;255;26;218m█\033[38;2;255;26;133m█\033[38;2;255;26;48m█\033[38;2;255;87;26m╔\033[38;2;255;172;26m╝\033[38;2;253;255;26m█\033[38;2;168;255;26m█\033[38;2;84;255;26m║  \033[38;2;26;255;221m█\033[38;2;26;204;255m█\033[38;2;26;119;255m║\033[38;2;26;34;255m╚\033[38;2;101;26;255m█\033[38;2;186;26;255m█\033[38;2;255;26;239m█\033[38;2;255;26;154m█\033[38;2;255;26;70m█\033[38;2;255;66;26m█\033[38;2;255;151;26m╔\033[38;2;255;236;26m╝\033[38;2;190;255;26m█\033[38;2;105;255;26m█\033[38;2;26;255;31m║ \033[38;2;26;255;200m╚\033[38;2;26;225;255m█\033[38;2;26;140;255m█\033[38;2;26;56;255m█\033[38;2;80;26;255m█\033[38;2;165;26;255m║   \033[38;2;255;45;26m█\033[38;2;255;130;26m█\033[38;2;255;214;26m║   "
  echo -e "\033[38;2;232;255;26m╚\033[38;2;147;255;26m═\033[38;2;63;255;26m═\033[38;2;26;255;73m═\033[38;2;26;255;158m═\033[38;2;26;255;243m═\033[38;2;26;183;255m╝ \033[38;2;38;26;255m╚\033[38;2;123;26;255m═\033[38;2;207;26;255m═\033[38;2;255;26;218m═\033[38;2;255;26;133m═\033[38;2;255;26;48m═\033[38;2;255;87;26m╝ \033[38;2;253;255;26m╚\033[38;2;168;255;26m═\033[38;2;84;255;26m╝  \033[38;2;26;255;221m╚\033[38;2;26;204;255m═\033[38;2;26;119;255m╝ \033[38;2;101;26;255m╚\033[38;2;186;26;255m═\033[38;2;255;26;239m═\033[38;2;255;26;154m═\033[38;2;255;26;70m═\033[38;2;255;66;26m═\033[38;2;255;151;26m╝ \033[38;2;190;255;26m╚\033[38;2;105;255;26m═\033[38;2;26;255;31m╝  \033[38;2;26;225;255m╚\033[38;2;26;140;255m═\033[38;2;26;56;255m═\033[38;2;80;26;255m═\033[38;2;165;26;255m╝   \033[38;2;255;45;26m╚\033[38;2;255;130;26m═\033[38;2;255;214;26m╝   \033[0m"
  echo ""
  printf "  \033[38;2;26;225;255m┌─────────────────────────────────────────────────────────┐\033[0m\n"
  printf "  \033[38;2;26;225;255m│\033[0m  \033[38;2;255;236;26m⚡\033[0m  \033[1;37mBug Bounty Recon + Vuln Pipeline\033[0m                    \033[38;2;26;225;255m│\033[0m\n"
  printf "  \033[38;2;26;225;255m│\033[0m  \033[38;2;26;255;116m▸\033[0m  \033[2;37mPhases: Enum → DNS → Probe → Harvest → Scan → XSS\033[0m  \033[38;2;26;225;255m│\033[0m\n"
  printf "  \033[38;2;26;225;255m│\033[0m  \033[38;2;255;26;48m⚠\033[0m   \033[2;37mAuthorized targets only. Unauthorized use is illegal.\033[0m \033[38;2;26;225;255m│\033[0m\n"
  printf "  \033[38;2;26;225;255m└─────────────────────────────────────────────────────────┘\033[0m\n"
  echo ""
}

print_banner

# ── arg parsing ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out)     OUTROOT="$2"; shift 2 ;;
    --phases)     PHASES="$2"; shift 2 ;;
    --quick)      QUICK=1; shift ;;
    -t|--threads) THREADS="$2"; shift 2 ;;
    -y|--yes)     ASSUME_YES=1; shift ;;
    --darkweb)    DARKWEB=1; shift ;;
    -h|--help)    usage 0 ;;
    -*)           err "unknown flag: $1"; usage 1 ;;
    *)            TARGET="$1"; shift ;;
  esac
done

[[ -z "$TARGET" ]] && { err "no target given"; usage 1; }

# Expand phase aliases.
[[ "$PHASES" == "recon" ]] && PHASES="1,2,3,4"
[[ "$PHASES" == "vuln"  ]] && PHASES="5,6"
[[ "$PHASES" == "osint" ]] && PHASES="7"
[[ "$PHASES" == "all"   ]] && PHASES="1,2,3,4,5,6,7,8"
# Append phase 8 automatically if --darkweb was passed
[[ "$DARKWEB" -eq 1 ]] && [[ ",$PHASES," != *",8,"* ]] && PHASES="${PHASES},8"

want() { [[ ",$PHASES," == *",$1,"* ]]; }

# ── basic target sanity check ───────────────────────────────────────
if ! [[ "$TARGET" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
  warn "Target '$TARGET' doesn't look like a bare domain (e.g. example.com)."
fi

# ── authorization gate ──────────────────────────────────────────────
if [[ "$ASSUME_YES" -ne 1 ]]; then
  printf "${C_YELLOW}"
  cat <<EOF

  ┌────────────────────────────────────────────────────────────┐
  │  AUTHORIZATION CHECK                                         │
  │                                                              │
  │  Target: ${TARGET}
  │                                                              │
  │  Active scanning without permission may be illegal.          │
  │  Only proceed if this asset is YOURS or explicitly           │
  │  in-scope for a program you're enrolled in.                  │
  └────────────────────────────────────────────────────────────┘
EOF
  printf "${C_RESET}"
  read -r -p "  Type the target domain to confirm authorization: " confirm
  if [[ "$confirm" != "$TARGET" ]]; then
    err "Confirmation did not match. Aborting."
    exit 1
  fi
fi

# ── output layout ───────────────────────────────────────────────────
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${OUTROOT}/${TARGET}/${STAMP}"
mkdir -p "$OUTDIR"
ln -sfn "$OUTDIR" "${OUTROOT}/${TARGET}/latest"
log "Output: $OUTDIR"
echo

SUBS="${OUTDIR}/subdomains.txt"
RESOLVED="${OUTDIR}/resolved.txt"
LIVE="${OUTDIR}/live.txt"
URLS="${OUTDIR}/urls.txt"

# ── findings triage directory ────────────────────────────────────────
FINDINGS="${OUTDIR}/findings"
mkdir -p "$FINDINGS"
CRIT="${FINDINGS}/critical.txt"
HIGH="${FINDINGS}/high.txt"
XSS_CONF="${FINDINGS}/xss-confirmed.txt"
OSINT_SUM="${FINDINGS}/osint-summary.txt"
DARKWEB_OUT="${FINDINGS}/darkweb.txt"
: > "$CRIT"; : > "$HIGH"; : > "$XSS_CONF"
log "Findings triage dir: $FINDINGS"
echo

# ── phase 1: subdomain enumeration ──────────────────────────────────
if want 1; then
  log "Phase 1 — subdomain enumeration"
  : > "$SUBS"
  if have subfinder; then
    subfinder -d "$TARGET" -all -silent 2>/dev/null >> "$SUBS" || true
    ok "subfinder done"
  else warn "subfinder not found, skipping"; fi

  if [[ "$QUICK" -ne 1 ]] && have amass; then
    log "running amass passive (slower)..."
    amass enum -passive -d "$TARGET" 2>/dev/null >> "$SUBS" || true
    ok "amass done"
  elif [[ "$QUICK" -eq 1 ]]; then
    log "quick mode: skipping amass"
  fi

  # always include the apex
  echo "$TARGET" >> "$SUBS"
  sort -u -o "$SUBS" "$SUBS"
  ok "$(wc -l < "$SUBS") unique subdomains -> $(basename "$SUBS")"
  echo
fi

# ── phase 2: dns resolution ─────────────────────────────────────────
if want 2; then
  log "Phase 2 — dns resolution"
  if have dnsx && [[ -s "$SUBS" ]]; then
    dnsx -l "$SUBS" -silent -r 1.1.1.1,8.8.8.8 2>/dev/null > "$RESOLVED" || true
    ok "$(wc -l < "$RESOLVED") resolve -> $(basename "$RESOLVED")"
  else
    warn "dnsx missing or no subdomains; using raw list"
    cp -f "$SUBS" "$RESOLVED" 2>/dev/null || true
  fi
  echo
fi

# ── phase 3: live host probing ──────────────────────────────────────
if want 3; then
  log "Phase 3 — live host probing"
  SRC="$RESOLVED"; [[ -s "$SRC" ]] || SRC="$SUBS"
  if have httpx && [[ -s "$SRC" ]]; then
    httpx -l "$SRC" -silent -threads "$THREADS" \
          -title -tech-detect -status-code -no-color \
          -o "${OUTDIR}/live-detailed.txt" 2>/dev/null || true
    # bare URL list for downstream tools
    awk '{print $1}' "${OUTDIR}/live-detailed.txt" 2>/dev/null | sort -u > "$LIVE" || true
    ok "$(wc -l < "$LIVE") live hosts -> $(basename "$LIVE")"
  else
    warn "httpx missing or no input; skipping"
  fi
  echo
fi

# ── phase 4: url harvesting ─────────────────────────────────────────
if want 4; then
  log "Phase 4 — url harvesting"
  : > "$URLS"
  if have gau; then
    echo "$TARGET" | gau --threads "$THREADS" 2>/dev/null >> "$URLS" || true
    ok "gau done"
  else warn "gau not found"; fi

  if have katana && [[ -s "$LIVE" ]]; then
    katana -list "$LIVE" -silent -d 2 -jc 2>/dev/null >> "$URLS" || true
    ok "katana done"
  else warn "katana skipped (missing or no live hosts)"; fi

  sort -u -o "$URLS" "$URLS"
  ok "$(wc -l < "$URLS") unique urls -> $(basename "$URLS")"
  echo
fi

# ── phase 5: vuln scanning ──────────────────────────────────────────
if want 5; then
  log "Phase 5 — nuclei vuln scan"
  SRC="$LIVE"; [[ -s "$SRC" ]] || SRC="$RESOLVED"
  if have nuclei && [[ -s "$SRC" ]]; then
    SEV="critical,high,medium"
    [[ "$QUICK" -eq 1 ]] && SEV="critical,high"
    nuclei -l "$SRC" -severity "$SEV" \
           -rl 150 -c "$THREADS" -stats -no-color \
           -o "${OUTDIR}/nuclei.txt" 2>/dev/null || true
    ok "nuclei findings -> nuclei.txt ($(wc -l < "${OUTDIR}/nuclei.txt" 2>/dev/null || echo 0) lines)"
    # ── triage into findings/ ─────────────────────────────────────
    if [[ -s "${OUTDIR}/nuclei.txt" ]]; then
      grep -i '^\[critical\]' "${OUTDIR}/nuclei.txt" >> "$CRIT" 2>/dev/null || true
      grep -i '^\[high\]'     "${OUTDIR}/nuclei.txt" >> "$HIGH" 2>/dev/null || true
      local_crit=$(wc -l < "$CRIT" 2>/dev/null || echo 0)
      local_high=$(wc -l < "$HIGH" 2>/dev/null || echo 0)
      [[ "$local_crit" -gt 0 ]] && warn "🔴 ${local_crit} CRITICAL findings -> findings/critical.txt"
      [[ "$local_high" -gt 0 ]] && warn "🟠 ${local_high} HIGH findings    -> findings/high.txt"
    fi
  else
    warn "nuclei missing or no targets; skipping"
  fi
  echo
fi

# ── phase 6: xss probing ────────────────────────────────────────────
if want 6; then
  log "Phase 6 — xss candidates (gf + dalfox)"
  if have gf && [[ -s "$URLS" ]]; then
    gf xss < "$URLS" 2>/dev/null | sort -u > "${OUTDIR}/xss-candidates.txt" || true
    ok "$(wc -l < "${OUTDIR}/xss-candidates.txt" 2>/dev/null || echo 0) xss candidate urls"
    if have dalfox && [[ "$QUICK" -ne 1 ]] && [[ -s "${OUTDIR}/xss-candidates.txt" ]]; then
      log "running dalfox (this can take a while)..."
      dalfox file "${OUTDIR}/xss-candidates.txt" \
             --silence --no-color -o "${OUTDIR}/dalfox.txt" 2>/dev/null || true
      ok "dalfox done -> dalfox.txt"
      # ── triage confirmed XSS ──────────────────────────────────
      if [[ -s "${OUTDIR}/dalfox.txt" ]]; then
        grep -i '\[V\]\|\[POC\]\|CONFIRM' "${OUTDIR}/dalfox.txt" >> "$XSS_CONF" 2>/dev/null || true
        xss_count=$(wc -l < "$XSS_CONF" 2>/dev/null || echo 0)
        [[ "$xss_count" -gt 0 ]] && warn "🟡 ${xss_count} confirmed XSS   -> findings/xss-confirmed.txt"
      fi
    elif [[ "$QUICK" -eq 1 ]]; then
      log "quick mode: skipping dalfox (candidates saved for manual review)"
    fi
  else
    warn "gf missing or no urls; skipping"
  fi
  echo
fi

# ── phase 7: osint & deep crawl ─────────────────────────────────────
if want 7; then
  log "Phase 7 — OSINT & deep crawl"
  : > "$OSINT_SUM"

  # ── WHOIS ────────────────────────────────────────────────────
  if have whois; then
    echo "════ WHOIS ════" >> "$OSINT_SUM"
    whois "$TARGET" 2>/dev/null \
      | grep -iE 'registrar|registrant|creation|expir|name server|email|admin|tech' \
      >> "$OSINT_SUM" || true
    echo "" >> "$OSINT_SUM"
    ok "whois done"
  else warn "whois not found"; fi

  # ── DNS deep dive ─────────────────────────────────────────────
  if have dig; then
    echo "════ DNS (MX/TXT/NS/SPF/DMARC) ════" >> "$OSINT_SUM"
    for TYPE in MX TXT NS A AAAA CNAME; do
      echo "-- $TYPE --" >> "$OSINT_SUM"
      dig +short "$TYPE" "$TARGET" 2>/dev/null >> "$OSINT_SUM" || true
    done
    echo "-- SPF --" >> "$OSINT_SUM"
    dig +short TXT "$TARGET" 2>/dev/null | grep -i spf  >> "$OSINT_SUM" || true
    echo "-- DMARC --" >> "$OSINT_SUM"
    dig +short TXT "_dmarc.${TARGET}" 2>/dev/null        >> "$OSINT_SUM" || true
    echo "" >> "$OSINT_SUM"
    ok "dns deep-dive done"
  fi

  # ── Certificate Transparency (crt.sh) ────────────────────────
  if have curl; then
    echo "════ Certificate Transparency (crt.sh) ════" >> "$OSINT_SUM"
    curl -sf "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null \
      | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = sorted({e.get('name_value','') for e in data})
    [print(n) for n in names if n]
except: pass
" 2>/dev/null | tee -a "$OSINT_SUM" \
             | tee -a "$SUBS" > /dev/null || true
    echo "" >> "$OSINT_SUM"
    ok "crt.sh cert transparency done"
  fi

  # ── Wayback Machine URL harvest ────────────────────────────────
  if have curl; then
    echo "════ Wayback Machine URLs ════" >> "$OSINT_SUM"
    WAYBACK_URLS="${OUTDIR}/wayback-urls.txt"
    curl -sf "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=2000" \
      2>/dev/null | sort -u > "$WAYBACK_URLS" || true
    wc -l < "$WAYBACK_URLS" >> "$OSINT_SUM" 2>/dev/null || true
    echo " wayback URLs saved -> wayback-urls.txt" >> "$OSINT_SUM"
    cat "$WAYBACK_URLS" >> "$URLS" 2>/dev/null || true
    sort -u -o "$URLS" "$URLS" 2>/dev/null || true
    echo "" >> "$OSINT_SUM"
    ok "wayback machine harvest done ($(wc -l < "$WAYBACK_URLS") urls)"
  fi

  # ── theHarvester ──────────────────────────────────────────────
  if have theHarvester; then
    echo "════ theHarvester ════" >> "$OSINT_SUM"
    theHarvester -d "$TARGET" -b all -l 500 2>/dev/null \
      | tee "${OUTDIR}/theharvester.txt" \
      | grep -E '@|IP:|Host:' >> "$OSINT_SUM" || true
    echo "" >> "$OSINT_SUM"
    ok "theHarvester done"
  else warn "theHarvester not found (pip install theHarvester)"; fi

  # ── Shodan CLI ────────────────────────────────────────────────
  if have shodan; then
    echo "════ Shodan ════" >> "$OSINT_SUM"
    shodan domain "$TARGET" 2>/dev/null >> "$OSINT_SUM" || true
    echo "" >> "$OSINT_SUM"
    ok "shodan done"
  else warn "shodan CLI not found (pip install shodan + shodan init <KEY>)"; fi

  # ── Google Dorks (passive, output only — manual verification) ─
  echo "════ Google Dork Queries (manual) ════" >> "$OSINT_SUM"
  cat >> "$OSINT_SUM" <<DORKS
site:${TARGET} filetype:pdf
site:${TARGET} filetype:xlsx OR filetype:docx
site:${TARGET} inurl:admin OR inurl:login OR inurl:dashboard
site:${TARGET} intext:password OR intext:secret OR intext:api_key
site:${TARGET} ext:env OR ext:bak OR ext:sql OR ext:config
site:${TARGET} -www
"${TARGET}" inurl:pastebin.com
"${TARGET}" inurl:github.com password OR token OR secret
DORKS
  ok "google dork queries written to osint-summary.txt (manual use)"

  # ── Email pattern harvesting (from URLs + harvester) ──────────
  if [[ -s "$URLS" ]]; then
    echo "════ Emails found in crawled data ════" >> "$OSINT_SUM"
    grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
      "$URLS" "${OUTDIR}/theharvester.txt" 2>/dev/null \
      | grep -i "$TARGET" | sort -u >> "$OSINT_SUM" || true
    echo "" >> "$OSINT_SUM"
  fi

  # ── JS secret scanning (trufflehog / manual grep) ─────────────
  if [[ -s "$URLS" ]]; then
    echo "════ Potential secrets in URLs / JS ════" >> "$OSINT_SUM"
    JS_HITS="${OUTDIR}/js-secrets.txt"
    grep -E '\.js(\?|$)' "$URLS" 2>/dev/null | head -200 > "${OUTDIR}/js-urls.txt" || true
    if [[ -s "${OUTDIR}/js-urls.txt" ]]; then
      while IFS= read -r jsurl; do
        curl -sf --max-time 8 "$jsurl" 2>/dev/null \
          | grep -oE '(api[_-]?key|secret|token|password|passwd|auth)[[:space:]]*[:=][[:space:]]*["\047]?[A-Za-z0-9+/=_\-]{8,}' \
          | sed "s|^|[$jsurl] |" >> "$JS_HITS" || true
      done < "${OUTDIR}/js-urls.txt"
      if [[ -s "$JS_HITS" ]]; then
        cat "$JS_HITS" >> "$OSINT_SUM"
        warn "🔑 Potential secrets found in JS -> js-secrets.txt"
      fi
    fi
    echo "" >> "$OSINT_SUM"
  fi

  sort -u -o "$SUBS" "$SUBS" 2>/dev/null || true
  ok "OSINT summary -> findings/osint-summary.txt"
  echo
fi

# ── phase 8: darkweb search ──────────────────────────────────────────
if want 8; then
  log "Phase 8 — darkweb search (Tor onion indexes)"
  if [[ "$DARKWEB" -ne 1 ]]; then
    warn "Phase 8 skipped: pass --darkweb flag to enable"
  else
    # Gate: tor must be running (SOCKS5 on 9050)
    if ! have torsocks && ! have torify; then
      warn "torsocks / torify not found. Install tor + torsocks first."
      warn "  Ubuntu: sudo apt install tor torsocks && sudo systemctl start tor"
    else
      TOR_CMD="torsocks"; have torsocks || TOR_CMD="torify"
      : > "$DARKWEB_OUT"
      log "Tor proxy detected. Querying onion search indexes..."

      # Ahmia (clearnet Tor search index — no onion needed)
      if have curl; then
        log "Querying Ahmia..."
        echo "════ Ahmia results ════" >> "$DARKWEB_OUT"
        curl -sf --max-time 30 \
          "https://ahmia.fi/search/?q=${TARGET}" 2>/dev/null \
          | grep -oP '(?<=href=")/search/redirect\?[^"]+' \
          | sed 's|^|https://ahmia.fi|' \
          >> "$DARKWEB_OUT" || true
        echo "" >> "$DARKWEB_OUT"
        ok "Ahmia done"
      fi

      # Tor-proxied queries to onion search engines
      ONION_QUERY="${TARGET// /+}"

      # Torch (onion)
      log "Querying Torch via Tor..."
      echo "════ Torch (onion) ════" >> "$DARKWEB_OUT"
      $TOR_CMD curl -sf --max-time 45 \
        "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/4a1f6b371c/search.cgi?cmd=search&form=simple&fmt=url&q=${ONION_QUERY}" \
        2>/dev/null | grep -oP 'http[s]?://[^\s<>"]+' \
        | grep -v 'torch\|xmh57jr' >> "$DARKWEB_OUT" || true
      echo "" >> "$DARKWEB_OUT"

      # Haystak (onion)
      log "Querying Haystak via Tor..."
      echo "════ Haystak (onion) ════" >> "$DARKWEB_OUT"
      $TOR_CMD curl -sf --max-time 45 \
        "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q=${ONION_QUERY}" \
        2>/dev/null | grep -oP 'http[s]?://[^\s<>"]+' \
        | grep '\.onion' >> "$DARKWEB_OUT" || true
      echo "" >> "$DARKWEB_OUT"

      # Paste sites via Tor
      log "Checking paste sites via Tor..."
      echo "════ Paste Sites ════" >> "$DARKWEB_OUT"
      for PASTE in "https://psbdmp.ws/api/v3/search/${TARGET}" \
                   "https://pastebin.com/search?q=${TARGET}"; do
        $TOR_CMD curl -sf --max-time 30 "$PASTE" 2>/dev/null \
          | grep -oP '"url"\s*:\s*"\K[^"]+' \
          >> "$DARKWEB_OUT" || true
      done
      echo "" >> "$DARKWEB_OUT"

      DARK_COUNT=$(grep -c 'http' "$DARKWEB_OUT" 2>/dev/null || echo 0)
      if [[ "$DARK_COUNT" -gt 0 ]]; then
        warn "🕵️  ${DARK_COUNT} darkweb references found -> findings/darkweb.txt"
      else
        ok "No darkweb references found for ${TARGET}"
      fi
    fi
  fi
  echo
fi


printf "${C_GREEN}"
echo "════════════════════════════════════════════════════════════"
echo "  HUNT COMPLETE: $TARGET"
echo "════════════════════════════════════════════════════════════"
printf "${C_RESET}"
printf "${C_DIM}"
[[ -s "$SUBS" ]]                        && echo "  subdomains  : $(wc -l < "$SUBS") "
[[ -s "$LIVE" ]]                        && echo "  live hosts  : $(wc -l < "$LIVE") "
[[ -s "$URLS" ]]                        && echo "  urls        : $(wc -l < "$URLS") "
[[ -s "${OUTDIR}/nuclei.txt" ]]         && echo "  nuclei      : $(wc -l < "${OUTDIR}/nuclei.txt") findings"
[[ -s "${OUTDIR}/xss-candidates.txt" ]] && echo "  xss cands   : $(wc -l < "${OUTDIR}/xss-candidates.txt") "
[[ -s "${OUTDIR}/wayback-urls.txt" ]]   && echo "  wayback     : $(wc -l < "${OUTDIR}/wayback-urls.txt") urls"
[[ -s "${OUTDIR}/js-secrets.txt" ]]     && echo "  js secrets  : $(wc -l < "${OUTDIR}/js-secrets.txt") hits"
printf "${C_RESET}"
echo ""
# ── findings triage summary ──────────────────────────────────────
CRIT_N=$(wc -l < "$CRIT"     2>/dev/null || echo 0)
HIGH_N=$(wc -l < "$HIGH"     2>/dev/null || echo 0)
XSSC_N=$(wc -l < "$XSS_CONF" 2>/dev/null || echo 0)
OSINT_N=$(wc -l < "$OSINT_SUM" 2>/dev/null || echo 0)
DARK_N=0; [[ -s "$DARKWEB_OUT" ]] && DARK_N=$(grep -c 'http' "$DARKWEB_OUT" 2>/dev/null || echo 0)

echo -e "\033[38;2;26;225;255m  ┌─────────────────────────────────────┐\033[0m"
echo -e "\033[38;2;26;225;255m  │\033[0m  \033[1;37m⚑  FINDINGS TRIAGE\033[0m                  \033[38;2;26;225;255m│\033[0m"
echo -e "\033[38;2;26;225;255m  ├─────────────────────────────────────┤\033[0m"
[[ "$CRIT_N"  -gt 0 ]] && \
  printf "\033[38;2;26;225;255m  │\033[0m  \033[1;31m🔴 CRITICAL : %-5s\033[0m                \033[38;2;26;225;255m│\033[0m\n" "$CRIT_N"
[[ "$HIGH_N"  -gt 0 ]] && \
  printf "\033[38;2;26;225;255m  │\033[0m  \033[0;33m🟠 HIGH     : %-5s\033[0m                \033[38;2;26;225;255m│\033[0m\n" "$HIGH_N"
[[ "$XSSC_N"  -gt 0 ]] && \
  printf "\033[38;2;26;225;255m  │\033[0m  \033[1;33m🟡 XSS conf : %-5s\033[0m                \033[38;2;26;225;255m│\033[0m\n" "$XSSC_N"
[[ "$OSINT_N" -gt 0 ]] && \
  printf "\033[38;2;26;225;255m  │\033[0m  \033[1;36m🔵 OSINT    : %-5s lines\033[0m          \033[38;2;26;225;255m│\033[0m\n" "$OSINT_N"
[[ "$DARK_N"  -gt 0 ]] && \
  printf "\033[38;2;26;225;255m  │\033[0m  \033[1;35m🕵  DARKWEB  : %-5s refs\033[0m           \033[38;2;26;225;255m│\033[0m\n" "$DARK_N"
[[ "$CRIT_N" -eq 0 && "$HIGH_N" -eq 0 && "$XSSC_N" -eq 0 ]] && \
  printf "\033[38;2;26;225;255m  │\033[0m  \033[1;32m✓  No critical/high issues found\033[0m   \033[38;2;26;225;255m│\033[0m\n"
echo -e "\033[38;2;26;225;255m  └─────────────────────────────────────┘\033[0m"
echo ""
echo "  → $OUTDIR"
echo "  → $FINDINGS"
echo
#!/usr/bin/env bash
# bbenv — load BBHUNT credentials from OUTSIDE the repository.
#
# The key lives at ~/.config/bbhunt/env (mode 600), never in the repo, never in
# a tracked file, never in shell history. This repo is public — a key committed
# here is a key published to the world.
#
#   source tools/bbenv.sh          load into the current shell
#   tools/bbenv.sh --check         report status without printing the key
#   tools/bbenv.sh --set           prompt for a key and store it safely
#
# Model settings for the pipeline live here too, so local runs and CI match.

BBHUNT_ENV_FILE="${BBHUNT_ENV_FILE:-${HOME}/.config/bbhunt/env}"

# Pipeline model configuration (safe to keep in the repo — not secrets).
export BBHUNT_MODEL="${BBHUNT_MODEL:-claude-opus-5}"
export BBHUNT_EFFORT="${BBHUNT_EFFORT:-xhigh}"

_bbenv_mask() {
  # Show only enough to identify a key, never enough to use it.
  local k="$1"
  if [[ ${#k} -lt 12 ]]; then printf '****'; else printf '%s…%s' "${k:0:7}" "${k: -4}"; fi
}

_bbenv_load() {
  if [[ -f "$BBHUNT_ENV_FILE" ]]; then
    local perms
    perms="$(stat -c '%a' "$BBHUNT_ENV_FILE" 2>/dev/null || stat -f '%Lp' "$BBHUNT_ENV_FILE" 2>/dev/null)"
    if [[ "$perms" != "600" ]]; then
      printf '\033[1;33m[!]\033[0m %s is mode %s — tightening to 600\n' "$BBHUNT_ENV_FILE" "$perms" >&2
      chmod 600 "$BBHUNT_ENV_FILE"
    fi
    set -a
    # shellcheck disable=SC1090
    . "$BBHUNT_ENV_FILE"
    set +a
    return 0
  fi
  return 1
}

case "${1:-}" in
  --check)
    _bbenv_load
    printf 'env file : %s %s\n' "$BBHUNT_ENV_FILE" \
      "$( [[ -f "$BBHUNT_ENV_FILE" ]] && echo '(present)' || echo '(MISSING)')"
    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
      printf 'api key  : %s\n' "$(_bbenv_mask "$ANTHROPIC_API_KEY")"
    else
      printf 'api key  : NOT SET\n'
      printf '           run: tools/bbenv.sh --set\n'
    fi
    printf 'model    : %s\n' "$BBHUNT_MODEL"
    printf 'effort   : %s\n' "$BBHUNT_EFFORT"
    printf '\nGitHub Actions secret (separate from the local key):\n'
    if command -v gh >/dev/null 2>&1; then
      gh secret list 2>/dev/null | grep -i anthropic || printf '  ANTHROPIC_API_KEY not set on the repo\n'
    else
      printf '  gh not installed\n'
    fi
    exit 0
    ;;
  --set)
    mkdir -p "$(dirname "$BBHUNT_ENV_FILE")"
    chmod 700 "$(dirname "$BBHUNT_ENV_FILE")"
    printf 'Paste your Anthropic API key (input hidden, not echoed, not stored in history):\n> '
    read -rs KEY
    printf '\n'
    if [[ -z "$KEY" ]]; then
      printf '\033[1;31m[x]\033[0m empty input — nothing written\n' >&2; exit 1
    fi
    if [[ "$KEY" != sk-ant-* ]]; then
      printf '\033[1;33m[!]\033[0m that does not look like an Anthropic key (expected sk-ant-…)\n' >&2
      printf '    writing anyway; verify with tools/bbenv.sh --check\n' >&2
    fi
    umask 077
    printf 'ANTHROPIC_API_KEY=%s\n' "$KEY" > "$BBHUNT_ENV_FILE"
    chmod 600 "$BBHUNT_ENV_FILE"
    unset KEY
    printf '\033[1;32m[+]\033[0m stored in %s (mode 600)\n' "$BBHUNT_ENV_FILE"
    printf '\033[1;33m[!]\033[0m this file is outside the repo — keep it that way\n'
    exit 0
    ;;
  --help|-h)
    sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

# Sourced with no arguments: load quietly.
_bbenv_load || {
  printf '\033[1;33m[!]\033[0m no key file at %s — run: tools/bbenv.sh --set\n' "$BBHUNT_ENV_FILE" >&2
}

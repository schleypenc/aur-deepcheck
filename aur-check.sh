#!/usr/bin/env bash
#=============================================================================
# aur-check.sh - AUR supply-chain incident scanner orchestrator
# Version: 2.1
#
# Runs two passes:
#   1. Community scanner: lenucksi/aur-malware-check, updated before execution.
#   2. Local deep forensic scanner: aur-deepcheck.sh next to this file.
#
# Design goals:
#   - No direct script execution: every script is invoked through bash.
#     This avoids "Permission denied" on files without +x or on noexec mounts.
#   - Works under sudo while preserving the real user's AUR helper caches.
#   - Continues to pass 2 even if pass 1 reports findings.
#   - Produces deterministic logs and propagates the worst severity.
#
# Exit codes:
#   0 = clean
#   1 = warnings / incomplete coverage
#   2 = critical findings
#   3 = scanner/runtime error
#=============================================================================
set -Eeuo pipefail
IFS=$'\n\t'
LC_ALL=C

VERSION="2.1"
UMASK_OLD=$(umask)
umask 077

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd -P)"
DEEP_SCRIPT="${DEEP_SCRIPT:-$SCRIPT_DIR/aur-deepcheck.sh}"
COMMUNITY_REPO_URL="${COMMUNITY_REPO_URL:-https://github.com/lenucksi/aur-malware-check}"
COMMUNITY_DIR="${COMMUNITY_DIR:-$SCRIPT_DIR/aur-malware-check}"
COMMUNITY_SCRIPT="$COMMUNITY_DIR/aur_check-v2.sh"
LOG_DIR="${LOG_DIR:-$COMMUNITY_DIR/logs}"
REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | awk -F: '{print $6; exit}')"
REAL_HOME="${REAL_HOME:-$HOME}"
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || printf %s "$REAL_USER")"

WARN=0
CRIT=0
RUNTIME_ERR=0
PASS1_RC=0
PASS2_RC=0

sep() { printf '\n%s\n' "$(printf '=%.0s' {1..72})"; }
hdr() { sep; printf ' %s\n' "$*"; sep; }
info() { printf '  [INFO]     %s\n' "$*"; }
warn() { printf '  [WARNING]  %s\n' "$*"; WARN=$((WARN + 1)); }
err()  { printf '  [ERROR]    %s\n' "$*" >&2; RUNTIME_ERR=$((RUNTIME_ERR + 1)); }

cleanup() { umask "$UMASK_OLD"; }
trap cleanup EXIT

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

run_as_real_user() {
  if is_root && [ -n "${SUDO_USER:-}" ] && have sudo; then
    sudo -u "$REAL_USER" -H -- "$@"
  else
    "$@"
  fi
}

prepare_logs() {
  # Logs stay inside the community scanner checkout, not /tmp.
  # They are owned by the real user because pass 1 is intentionally de-rooted.
  if is_root && [ -n "${SUDO_USER:-}" ]; then
    mkdir -p -- "$LOG_DIR"
    chown -R "$REAL_USER:$REAL_GROUP" -- "$LOG_DIR" 2>/dev/null || true
    chmod 700 -- "$LOG_DIR" 2>/dev/null || true
  else
    mkdir -p -- "$LOG_DIR"
    chmod 700 -- "$LOG_DIR" 2>/dev/null || true
  fi
}

preflight() {
  hdr "Preflight"
  info "aur-check v$VERSION"
  info "script dir: $SCRIPT_DIR"
  info "real user : $REAL_USER ($REAL_HOME)"
  info "log dir   : $LOG_DIR"

  if ! have bash; then err "bash not found"; exit 3; fi
  if ! have git; then err "git not found - install git first"; exit 3; fi
  if ! have pacman; then err "pacman not found - this scanner targets Arch Linux"; exit 3; fi
  if [ ! -r "$DEEP_SCRIPT" ]; then
    err "deep scanner not readable: $DEEP_SCRIPT"
    err "place aur-deepcheck.sh next to this file or set DEEP_SCRIPT=/path/to/file"
    exit 3
  fi

}

update_community_scanner() {
  hdr "Updating community scanner"

  # If a previous sudo run created a root-owned checkout/log dir, give only
  # this scanner checkout back to the real user. Do not touch anything else.
  if is_root && [ -n "${SUDO_USER:-}" ] && [ -d "$COMMUNITY_DIR" ]; then
    chown -R "$REAL_USER:$REAL_GROUP" -- "$COMMUNITY_DIR" 2>/dev/null || true
  fi

  if [ ! -d "$COMMUNITY_DIR/.git" ]; then
    rm -rf -- "$COMMUNITY_DIR"
    # Clone as the real user when possible so future non-root runs can update it.
    if ! run_as_real_user git clone --depth=1 -- "$COMMUNITY_REPO_URL" "$COMMUNITY_DIR"; then
      err "failed to clone community scanner"
      return 3
    fi
  else
    if ! run_as_real_user git -C "$COMMUNITY_DIR" pull --ff-only; then
      warn "community scanner update failed; using existing checkout"
    fi
  fi

  if [ ! -r "$COMMUNITY_SCRIPT" ]; then
    err "community scanner script not readable: $COMMUNITY_SCRIPT"
    return 3
  fi

  if is_root && [ -n "${SUDO_USER:-}" ]; then
    chown -R "$REAL_USER:$REAL_GROUP" -- "$COMMUNITY_DIR" 2>/dev/null || true
  fi
  chmod u+rwX,go-rwx -- "$COMMUNITY_DIR" 2>/dev/null || true
  chmod u+r -- "$COMMUNITY_SCRIPT" 2>/dev/null || true
  prepare_logs
  info "community scanner ready: $COMMUNITY_SCRIPT"
  info "community logs   : $LOG_DIR"
  return 0
}

run_pass1() {
  hdr "PASS 1 - Community scanner"
  local ts log rc
  ts="$(date +%Y%m%d-%H%M%S)"
  log="$LOG_DIR/aur-community-$ts.log"

  export PACKAGE_LIST_FILE="$COMMUNITY_DIR/package_list.txt"

  # Use bash explicitly. Do not execute aur_check-v2.sh directly.
  set +e
  if is_root && [ -n "${SUDO_USER:-}" ] && have sudo; then
    sudo -u "$REAL_USER" -H -- env PACKAGE_LIST_FILE="$PACKAGE_LIST_FILE" \
      bash "$COMMUNITY_SCRIPT" --full --log-file="$log"
    rc=$?
  else
    bash "$COMMUNITY_SCRIPT" --full --log-file="$log"
    rc=$?
  fi
  set -e

  PASS1_RC=$rc
  info "pass 1 exit code: $PASS1_RC"
  info "pass 1 log      : $log"

  case "$PASS1_RC" in
    0) return 0 ;;
    1) WARN=$((WARN + 1)); return 1 ;;
    2) CRIT=$((CRIT + 1)); return 2 ;;
    *) err "community scanner returned unexpected/runtime code $PASS1_RC"; return 3 ;;
  esac
}

run_pass2() {
  hdr "PASS 2 - Deep forensic scanner"
  local ts log rc
  ts="$(date +%Y%m%d-%H%M%S)"
  log="$LOG_DIR/aur-deepcheck-$ts.log"

  # Use bash explicitly. Do not require +x on aur-deepcheck.sh.
  set +e
  MAX_PID_PROBE="${MAX_PID_PROBE:-65536}" bash "$DEEP_SCRIPT" | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e

  PASS2_RC=$rc
  info "pass 2 exit code: $PASS2_RC"
  info "pass 2 log      : $log"

  case "$PASS2_RC" in
    0) return 0 ;;
    1) WARN=$((WARN + 1)); return 1 ;;
    2) CRIT=$((CRIT + 1)); return 2 ;;
    *) err "deep scanner returned unexpected/runtime code $PASS2_RC"; return 3 ;;
  esac
}

final_verdict() {
  hdr "Final orchestrator verdict"
  printf ' Pass 1 rc : %s\n' "$PASS1_RC"
  printf ' Pass 2 rc : %s\n' "$PASS2_RC"
  printf ' Critical  : %s\n' "$CRIT"
  printf ' Warnings  : %s\n' "$WARN"
  printf ' Errors    : %s\n' "$RUNTIME_ERR"

  if [ "$RUNTIME_ERR" -gt 0 ]; then
    printf '\n VERDICT: RUNTIME ERROR - scanner coverage incomplete.\n'
    exit 3
  fi
  if [ "$CRIT" -gt 0 ] || [ "$PASS1_RC" -eq 2 ] || [ "$PASS2_RC" -eq 2 ]; then
    printf '\n VERDICT: CRITICAL - indicators require incident response.\n'
    exit 2
  fi
  if [ "$WARN" -gt 0 ] || [ "$PASS1_RC" -eq 1 ] || [ "$PASS2_RC" -eq 1 ]; then
    printf '\n VERDICT: WARNINGS - review findings and rerun with sudo + bpftool if needed.\n'
    exit 1
  fi
  printf '\n VERDICT: CLEAN - no indicators found by completed checks.\n'
  exit 0
}

main() {
  preflight
  if ! update_community_scanner; then
    RUNTIME_ERR=$((RUNTIME_ERR + 1))
  fi
  if [ "$RUNTIME_ERR" -eq 0 ]; then
    run_pass1 || true
  fi
  prepare_logs || true
  run_pass2 || true
  final_verdict
}

main "$@"

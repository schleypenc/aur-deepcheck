#!/usr/bin/env bash
#=============================================================================
# aur-deepcheck.sh - Deep host inspection for AUR supply-chain compromise
# Version: 2.1
#
# Read-mostly scanner. It does not intentionally modify host state.
# Exit codes: 0 clean, 1 warnings/incomplete coverage, 2 critical, 3 runtime.
#=============================================================================
set -uo pipefail
IFS=$'\n\t'
LC_ALL=C

VERSION="2.1"
WIN_START="${WIN_START:-2026-06-09 00:00:00}"
WIN_END="${WIN_END:-2026-06-13 00:00:00}"
IOC_REGEX="${IOC_REGEX:-atomic-lockfile|js-digest|herbsobering|temp\.sh|\.onion}"
MAX_PID_PROBE="${MAX_PID_PROBE:-65536}"

REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | awk -F: '{print $6; exit}')"
REAL_HOME="${REAL_HOME:-$HOME}"

WARN=0
CRIT=0
SKIPPED=0
RUNTIME_ERR=0

section() { printf '\n=== [%s] %s ===\n' "$1" "$2"; }
ok()      { printf '  [CLEAN]    %s\n' "$*"; }
note()    { printf '  [NOTE]     %s\n' "$*"; }
warn()    { printf '  [WARNING]  %s\n' "$*"; WARN=$((WARN + 1)); }
crit()    { printf '  [CRITICAL] %s\n' "$*"; CRIT=$((CRIT + 1)); }
skipped() { printf '  [SKIPPED]  %s\n' "$*"; SKIPPED=$((SKIPPED + 1)); }
err()     { printf '  [ERROR]    %s\n' "$*"; RUNTIME_ERR=$((RUNTIME_ERR + 1)); }
have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

safe_head4() { head -c 4 -- "$1" 2>/dev/null || true; }
owned_by_pacman() { pacman -Qoq -- "$1" >/dev/null 2>&1; }

preflight() {
  if ! have pacman; then
    printf 'ERROR: pacman not found - this scanner targets Arch Linux.\n' >&2
    exit 3
  fi
  printf 'aur-deepcheck v%s\n' "$VERSION"
  printf 'Mode: %s | User: %s (%s)\n' "$(is_root && echo root || echo unprivileged)" "$REAL_USER" "$REAL_HOME"
  printf 'Window: %s -> %s | Read-mostly\n' "$WIN_START" "$WIN_END"
}

check_filesystem_artifacts() {
  section A "Dropped binaries / filesystem artifacts"
  local clean=1 f owner elf_magic
  elf_magic=$(printf '\177ELF')

  if [ -e /usr/bin/monero-wallet-gui ]; then
    clean=0
    if owner=$(pacman -Qoq /usr/bin/monero-wallet-gui 2>/dev/null); then
      warn "/usr/bin/monero-wallet-gui present, package-owned by '$owner' - verify it is intentional"
    else
      crit "/usr/bin/monero-wallet-gui present and unowned - matches miner staging behavior"
    fi
  fi

  while IFS= read -r -d '' f; do
    if [ "$(safe_head4 "$f")" = "$elf_magic" ]; then
      clean=0
      crit "ELF named 'deps' found: $f"
    fi
  done < <(find "$REAL_HOME" /tmp /var/tmp /dev/shm -xdev -type f -name deps -print0 2>/dev/null)

  while IFS= read -r -d '' f; do
    if ! owned_by_pacman "$f"; then
      clean=0
      crit "unowned file in privileged path, written during window: $f"
    fi
  done < <(find /usr/bin /usr/local/bin /usr/lib/systemd -xdev -type f -newermt "$WIN_START" ! -newermt "$WIN_END" -print0 2>/dev/null)

  [ "$clean" -eq 1 ] && ok "no miner binary, no deps ELF, no unowned window-dated privileged files"
}

check_aur_caches() {
  section B "AUR helper build caches"
  local dirs=() d hits h
  for d in \
    "$REAL_HOME/.cache/yay" \
    "$REAL_HOME/.cache/paru/clone" \
    "$REAL_HOME/.cache/pikaur/aur_repos" \
    "$REAL_HOME/.cache/trizen" \
    "$REAL_HOME/.cache/aurutils" \
    "$REAL_HOME/.cache/pacaur"; do
    [ -d "$d" ] && dirs+=("$d")
  done

  if [ "${#dirs[@]}" -eq 0 ]; then
    skipped "no known AUR helper cache under $REAL_HOME/.cache"
    return
  fi

  hits=$(grep -rslE --include=PKGBUILD --include='*.install' --include='*.hook' "$IOC_REGEX" "${dirs[@]}" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    while IFS= read -r h; do [ -n "$h" ] && crit "IOC in cached build file: $h"; done <<< "$hits"
  else
    ok "no IOC strings in cached PKGBUILD/.install/.hook files"
  fi
}

check_pacman_db() {
  section C "pacman local database"
  local clean=1 hits h foreign d entry pkg

  hits=$(grep -lsE "$IOC_REGEX" /var/lib/pacman/local/*/install 2>/dev/null || true)
  if [ -n "$hits" ]; then
    clean=0
    while IFS= read -r h; do [ -n "$h" ] && crit "compromised scriptlet in local DB: $h"; done <<< "$hits"
  fi

  foreign=$(pacman -Qmq 2>/dev/null || true)
  while IFS= read -r -d '' d; do
    entry=$(basename -- "$d")
    pkg="${entry%-*-*}"
    if printf '%s\n' "$foreign" | grep -qxF -- "$pkg"; then
      clean=0
      warn "AUR package DB entry modified during window: $pkg - verify"
    fi
  done < <(find /var/lib/pacman/local -mindepth 1 -maxdepth 1 -type d -newermt "$WIN_START" ! -newermt "$WIN_END" -print0 2>/dev/null)

  [ "$clean" -eq 1 ] && ok "no IOC scriptlets in local DB; no AUR DB entries touched during window"
}

check_live_processes() {
  section D "Live processes"
  local clean=1 p pid exe cmd out name
  is_root || note "unprivileged - only accessible processes are visible"

  for p in /proc/[0-9]*; do
    [ -e "$p" ] || continue
    pid="${p#/proc/}"
    exe=$(readlink -- "$p/exe" 2>/dev/null) || continue
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)
    case "$exe" in
      *'(deleted)') clean=0; warn "PID $pid: deleted executable still running: $exe - cmd: ${cmd:-?}" ;;
    esac
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*|"$REAL_HOME"/.cache/*)
        clean=0; crit "PID $pid: executing from staging path: $exe - cmd: ${cmd:-?}" ;;
    esac
  done

  if out=$(pgrep -ax deps 2>/dev/null) && [ -n "$out" ]; then clean=0; crit "process named deps running: $out"; fi
  for name in monero-wallet-gui xmrig; do
    if out=$(pgrep -ax "$name" 2>/dev/null) && [ -n "$out" ]; then clean=0; warn "miner-like process running: $out - legitimate only if intentional"; fi
  done

  [ "$clean" -eq 1 ] && ok "no deleted/staging executables, no payload-named processes"
}

check_hidden_pids() {
  section E "Hidden-PID probe: stat/open vs getdents"
  local pid_max probe_max clean=1 i tgid cmd v
  pid_max=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 32768)
  probe_max="$MAX_PID_PROBE"
  case "$probe_max" in ''|*[!0-9]*) probe_max=65536 ;; esac
  [ "$probe_max" -gt "$pid_max" ] && probe_max="$pid_max"
  note "probing PIDs 1..$probe_max"

  declare -A enumerated=()
  while IFS= read -r v; do enumerated[$v]=1; done < <(find /proc -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | grep -E '^[0-9]+$' || true)

  i=1
  while [ "$i" -le "$probe_max" ]; do
    if [ -d "/proc/$i" ] && [ -z "${enumerated[$i]:-}" ]; then
      tgid=$(awk '/^Tgid:/{print $2; exit}' "/proc/$i/status" 2>/dev/null || true)
      if [ "$tgid" = "$i" ] && ! find /proc -maxdepth 1 -type d -name "$i" -print -quit 2>/dev/null | grep -qx "/proc/$i"; then
        clean=0
        cmd=$(tr '\0' ' ' < "/proc/$i/cmdline" 2>/dev/null || true)
        crit "PID $i: stat-visible but hidden from /proc enumeration - cmd: ${cmd:-?}"
      fi
    fi
    i=$((i + 1))
  done
  [ "$clean" -eq 1 ] && ok "no PIDs hidden from directory enumeration"
}

check_bpf() {
  section F "Kernel BPF enumeration"
  local clean=1 maps progs m p pins suspicious nprogs
  if ! is_root; then skipped "requires root - rerun with sudo"; return; fi
  if ! have bpftool; then skipped "bpftool not installed - pacman -S bpf"; return; fi

  maps=$(bpftool map show 2>/dev/null || true)
  progs=$(bpftool prog show 2>/dev/null || true)

  m=$(printf '%s\n' "$maps" | grep -Ei 'hidden_pids|hidden_names|hidden_inodes|hidden' || true)
  if [ -n "$m" ]; then clean=0; crit "rootkit-named BPF map(s) loaded:"; printf '%s\n' "$m" | sed 's/^/             /'; fi

  p=$(printf '%s\n' "$progs" | grep -Ei 'getdents|hidden' || true)
  if [ -n "$p" ]; then clean=0; crit "suspicious BPF program(s):"; printf '%s\n' "$p" | sed 's/^/             /'; fi

  pins=$(find /sys/fs/bpf -mindepth 1 -print 2>/dev/null || true)
  suspicious=$(printf '%s\n' "$pins" | grep -vE '^$|^/sys/fs/bpf/systemd(/|$)' || true)
  if [ -n "$suspicious" ]; then clean=0; warn "unexpected pinned BPF objects:"; printf '%s\n' "$suspicious" | sed 's/^/             /'; fi

  nprogs=$(printf '%s\n' "$progs" | grep -c '^[0-9]' || true)
  note "$nprogs BPF programs loaded in kernel"
  [ "$clean" -eq 1 ] && ok "no rootkit-named maps, getdents hooks, or unexpected pins"
}

check_network() {
  section G "Network state"
  local clean=1 line peer port mismatch=0 nl pf delta trial
  if ! have ss; then skipped "ss not available - install iproute2"; return; fi

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    peer=$(awk '{print $5}' <<< "$line")
    port="${peer##*:}"
    case "$port" in 9001|9030|9050|9051) clean=0; warn "connection to Tor-typical port: $line" ;; esac
  done < <(ss -Htnp state established 2>/dev/null || true)

  for trial in 1 2; do
    nl=$(ss -Htan 2>/dev/null | wc -l)
    pf=$(( $(wc -l < /proc/net/tcp 2>/dev/null || echo 1) - 1 ))
    [ -r /proc/net/tcp6 ] && pf=$(( pf + $(wc -l < /proc/net/tcp6) - 1 ))
    delta=$(( nl - pf )); [ "$delta" -lt 0 ] && delta=$(( -delta ))
    [ "$delta" -gt 3 ] && mismatch=$((mismatch + 1))
    sleep 1
  done
  if [ "$mismatch" -eq 2 ]; then clean=0; crit "persistent netlink/procfs socket count mismatch"; fi

  [ "$clean" -eq 1 ] && ok "no Tor-port connections; netlink/procfs socket counts agree"
}

check_systemd() {
  section H "systemd persistence"
  local clean=1 f d

  while IFS= read -r -d '' f; do
    if ! owned_by_pacman "$f"; then clean=0; crit "vendor unit owned by no package: $f"; fi
  done < <(find /usr/lib/systemd/system -type f \( -name '*.service' -o -name '*.timer' \) -print0 2>/dev/null)

  for d in /etc/systemd/system "$REAL_HOME/.config/systemd/user"; do
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do clean=0; warn "unit written during attack window: $f"; done \
      < <(find "$d" -type f \( -name '*.service' -o -name '*.timer' \) -newermt "$WIN_START" ! -newermt "$WIN_END" -print0 2>/dev/null)
    while IFS= read -r -d '' f; do clean=0; crit "unit ExecStart points into staging path: $f"; done \
      < <(grep -rlZsE '^Exec(Start|StartPre)=.*(/tmp/|/var/tmp/|/dev/shm/|\.cache/)' "$d" 2>/dev/null || true)
  done

  [ "$clean" -eq 1 ] && ok "all vendor units package-owned; no window-dated or staging-path units"
}

check_journal() {
  section I "Journal sweep"
  local hits
  if ! is_root; then skipped "requires root for full system journal"; return; fi
  if ! have journalctl; then skipped "journalctl not available"; return; fi

  hits=$(journalctl --since "$WIN_START" --until "$WIN_END" --no-pager -q 2>/dev/null | grep -E -m 20 "$IOC_REGEX" || true)
  if [ -n "$hits" ]; then
    warn "IOC strings in journal during window (first 20):"
    printf '%s\n' "$hits" | sed 's/^/             /'
  else
    ok "no IOC strings in system journal during window"
  fi
}

check_ssh() {
  section J "SSH material"
  local clean=1 f
  if [ ! -d "$REAL_HOME/.ssh" ]; then skipped "no ~/.ssh directory"; return; fi
  while IFS= read -r -d '' f; do clean=0; warn "SSH file modified during attack window: $f - review and rotate if unsure"; done \
    < <(find "$REAL_HOME/.ssh" -type f -newermt "$WIN_START" ! -newermt "$WIN_END" -print0 2>/dev/null)
  [ "$clean" -eq 1 ] && ok "no ~/.ssh file touched during attack window"
}

summary() {
  printf '\n%s\n' "$(printf '=%.0s' {1..72})"
  printf ' SUMMARY\n'
  printf '%s\n' "$(printf '=%.0s' {1..72})"
  printf ' Critical : %d\n Warnings : %d\n Skipped  : %d\n Errors   : %d\n' "$CRIT" "$WARN" "$SKIPPED" "$RUNTIME_ERR"
  printf '%s\n' "$(printf '=%.0s' {1..72})"

  if [ "$RUNTIME_ERR" -gt 0 ]; then
    cat <<'MSG'

 VERDICT: RUNTIME ERROR
 Scanner coverage is incomplete because one or more runtime errors occurred.
MSG
    exit 3
  elif [ "$CRIT" -gt 0 ]; then
    cat <<'MSG'

 VERDICT: CRITICAL
 Indicators consistent with compromise are present.
 Immediate response: isolate host, rotate secrets from a clean device, preserve evidence, and rebuild from trusted media.
MSG
    exit 2
  elif [ "$WARN" -gt 0 ] || [ "$SKIPPED" -gt 0 ]; then
    cat <<'MSG'

 VERDICT: WARNINGS / INCOMPLETE COVERAGE
 No direct critical indicator was found, but warnings or skipped checks need review.
 For strongest coverage, rerun with sudo and bpftool installed.
MSG
    exit 1
  else
    cat <<'MSG'

 VERDICT: CLEAN - HIGH confidence for the checked threat model
 No indicators were found across cache, pacman DB, filesystem, process, BPF, network, systemd, journal, and SSH checks.
MSG
    exit 0
  fi
}

main() {
  preflight
  check_filesystem_artifacts
  check_aur_caches
  check_pacman_db
  check_live_processes
  check_hidden_pids
  check_bpf
  check_network
  check_systemd
  check_journal
  check_ssh
  summary
}

main "$@"

#!/usr/bin/env bash
# lib.sh — shared helpers for all engagement scripts. Source, don't execute.
# Targets are loaded from a LOCAL, git-ignored file (never committed).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck disable=SC1091
source "$HERE/engagement.conf"

TS(){ date -u +%FT%TZ; }
LOGFILE=""
log(){ echo "$(TS) $*"; [ -n "$LOGFILE" ] && echo "$(TS) $*" >> "$LOGFILE"; }
die(){ echo "[!] $*" >&2; exit 1; }
info(){ echo "[i] $*"; }

# Load targets from the local file into TNAMES[] / TIPS[].
TNAMES=(); TIPS=()
load_targets(){
  local f="$ROOT/$TARGETS_FILE"
  [ -f "$f" ] || f="$TARGETS_FILE"
  [ -f "$f" ] || die "targets file not found: $TARGETS_FILE
    Create it from tools/targets.sample:  cp tools/targets.sample scope/targets.local  (then edit)"
  local name ip
  while read -r name ip _; do
    [ -z "${name:-}" ] && continue; [[ "$name" == \#* ]] && continue
    [ -z "${ip:-}" ] && continue
    TNAMES+=("$name"); TIPS+=("$ip")
  done < "$f"
  [ "${#TIPS[@]}" -gt 0 ] || die "no targets parsed from $f"
}

setup_out(){
  local phase="$1" sub="$2"
  mkdir -p "$OUTDIR"/{scope,discovery,ports,enumeration,web,sap,vulns,credentials,evidence,reports,logs,loot}
  LOGFILE="$OUTDIR/logs/command-log.txt"
  PHASE_DIR="$OUTDIR/$sub"; mkdir -p "$PHASE_DIR"
  load_targets
  printf '%s\n' "${TIPS[@]}" | sort -u > "$OUTDIR/scope/targets.txt"   # local only; engagement/ is git-ignored
  log "PHASE $phase start (tester=$TESTER host=$(hostname) uid=$(id -u) targets=${#TIPS[@]})"
}

need(){ command -v "$1" >/dev/null 2>&1 || die "missing tool: $1 (run tools/00-setup.sh)"; }
have(){ command -v "$1" >/dev/null 2>&1; }
scan_type(){ if [ "$(id -u)" = 0 ]; then echo "-sS"; else echo "-sT"; fi; }

for_each_target(){ local fn="$1" i; for i in "${!TIPS[@]}"; do "$fn" "${TNAMES[$i]}" "${TIPS[$i]}"; done; }

scope_guard(){
  echo "=== SCOPE CONFIRMATION ($ENGAGEMENT_NAME) ==="
  local i; for i in "${!TIPS[@]}"; do printf "   %-14s %s\n" "${TNAMES[$i]}" "${TIPS[$i]}"; done
  echo "Confirm: (1) on the AUTHORIZED tester host, (2) window open now, (3) SOC notified."
  if [ "${ASSUME_YES:-0}" = "1" ]; then info "ASSUME_YES=1 — skipping prompt"; return 0; fi
  read -r -p "Type 'GO' to proceed: " a; [ "$a" = "GO" ] || die "aborted by operator"
}

require_approval(){
  local what="$1"
  echo "*** GATED ACTION: $what ***"
  echo "Can cause: ${2:-service disruption / account lockout / detection escalation}."
  [ -n "${APPROVAL_REF:-}" ] || die "REQUIRES EXPLICIT RoE APPROVAL — set APPROVAL_REF='<ref>' and only if authorized."
  log "APPROVED-ACTION '$what' ref=$APPROVAL_REF"
  if [ "${ASSUME_YES:-0}" != "1" ]; then read -r -p "Approval ref '$APPROVAL_REF'. Type 'APPROVED' to run: " a; [ "$a" = "APPROVED" ] || die "aborted"; fi
}

open_ports_from(){ grep -E "^[0-9]+/tcp +open" "$1" 2>/dev/null | cut -d/ -f1 | paste -sd, -; }

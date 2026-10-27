#!/usr/bin/env bash
# 07-creds.sh — credential handling. SAFE-BY-DEFAULT.
# Default mode = VALIDATE a single KNOWN credential (provided by client) — no guessing.
# Subcommands:
#   validate  <proto> <user> <pass|-H hash>   test ONE known cred on in-scope hosts (CONTROLLED)
#   crack     <hashfile> <mode> [wordlist]    OFFLINE hashcat (SAFE — no target contact)
#   spray     <proto> <userfile> <password>   GATED: password spray (lockout risk)
# proto = smb|winrm|mssql|ssh (uses netexec/nxc)
# NEVER use this to brute force. Spray requires APPROVAL_REF + known lockout policy + pacing.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "07-creds" "credentials"
cmd="${1:-help}"; shift || true

nxcbin(){ if have nxc; then echo nxc; elif have netexec; then echo netexec; else die "need netexec/nxc"; fi; }

case "$cmd" in
  validate)
    scope_guard
    proto="${1:?proto}"; user="${2:?user}"; shift 2
    NXC=$(nxcbin)
    log "cred-validate proto=$proto user=$user (single known cred)"
    # pass as "$@" so you can supply  -p 'pw'  or  -H '<hash>'
    "$NXC" "$proto" "$OUTDIR/scope/targets.txt" -u "$user" "$@" --continue-on-success \
       | tee "$PHASE_DIR/validate-$proto-$user.txt"
    echo "[i] (Pwn3d!) = admin on that host. Record where it works in credentials.csv (ref only)."
    ;;
  crack)
    hashfile="${1:?hashfile}"; mode="${2:?hashcat -m mode}"; wl="${3:-/usr/share/wordlists/rockyou.txt}"
    need hashcat
    log "offline-crack mode=$mode (no target contact)"
    hashcat -m "$mode" "$hashfile" "$wl" --potfile-path "$OUTDIR/loot/hashcat.pot" -O \
       -o "$OUTDIR/loot/cracked-$mode.txt" || true
    echo "[i] Cracked -> engagement/loot/ (git-ignored). Then 'validate' reuse carefully."
    ;;
  spray)
    proto="${1:?proto}"; userfile="${2:?userfile}"; password="${3:?password}"
    require_approval "PASSWORD SPRAY ($proto)" "ACCOUNT LOCKOUT of real users + SOC alerts"
    [ -f "${LOCKOUT_POLICY:-}" ] || die "set LOCKOUT_POLICY=<file documenting threshold/window> first"
    scope_guard
    NXC=$(nxcbin)
    log "SPRAY proto=$proto users=$userfile ONE password, paced"
    echo "[!] One password, ONE attempt per user. Ensure interval >= lockout window between rounds."
    "$NXC" "$proto" "$OUTDIR/scope/targets.txt" -u "$userfile" -p "$password" \
       --continue-on-success | tee "$PHASE_DIR/spray-$proto.txt"
    ;;
  *)
    sed -n '2,14p' "$0" ;;
esac

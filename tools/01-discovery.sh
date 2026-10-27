#!/usr/bin/env bash
# 01-discovery.sh — host discovery. RISK: SAFE DISCOVERY.
# WHAT: confirm which in-scope hosts are live (gentle, multi-probe).
# WHY : narrow the target set before port work; "no reply" != "no host" (we keep -Pn later).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "01-discovery" "discovery"; scope_guard
need nmap
log "discovery: gentle ping sweep (ICMP + a few TCP probes)"
nmap -sn -PE -PS22,443,3200 -PA3300 $TIMING -iL "$OUTDIR/scope/targets.txt" \
     -oA "$PHASE_DIR/ping" >/dev/null
grep -E "Nmap scan report|Host is up" "$PHASE_DIR/ping.nmap" | tee "$PHASE_DIR/live.txt"
echo "[*] Discovery done -> $PHASE_DIR/  (next: tools/02-portscan.sh)"

#!/usr/bin/env bash
# 02-portscan.sh — curated TCP port scan, one host at a time. RISK: SAFE DISCOVERY.
# WHAT: find open TCP ports across common + ERP-signature ranges.
# WHY : fingerprint-first; curated set is gentler than a blind -p- on fragile ERP.
# OPT : FULL=1 adds a slow full-TCP pass (still -T2) for interesting hosts only.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "02-portscan" "ports"; scope_guard
need nmap; SCAN="$(scan_type)"; info "scan type: $SCAN"

COMMON="21,22,23,25,53,80,88,110,111,135,139,389,443,445,636,1433,1521,3306,3389,5432,5985,5986,8080,8443,8000,9000,9090,10000"
SAP="3200-3299,3300-3399,3600-3699,4800-4899,8100-8110,44300-44320,50000-50120,1128-1129,30000-30050"
OTHER_ERP="1526,7001,7002,8001,6015,6017"
PORTS="${COMMON},${SAP},${OTHER_ERP}"

scan_one(){
  local name="$1" ip="$2"
  log "portscan $name $ip (curated)"
  nmap -Pn $SCAN $TIMING -p "$PORTS" --open "$ip" -oA "$PHASE_DIR/$name" >/dev/null
  echo "=== $name ($ip) ==="; grep -E "^[0-9]+/tcp +open" "$PHASE_DIR/$name.nmap" || echo "  (none in curated set)"
  if [ "${FULL:-0}" = "1" ]; then
    log "portscan $name $ip (FULL TCP, slow)"
    nmap -Pn $SCAN $TIMING -p- --open "$ip" -oA "$PHASE_DIR/$name-full" >/dev/null
  fi
}
for_each_target scan_one
echo "[*] Port scan done -> $PHASE_DIR/  (next: tools/03-enum.sh)"

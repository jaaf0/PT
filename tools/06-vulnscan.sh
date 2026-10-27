#!/usr/bin/env bash
# 06-vulnscan.sh — safe vulnerability CHECKS (no exploitation). RISK: CONTROLLED.
# WHAT: nmap "vuln and safe" scripts (excluding brute/dos) on open ports.
# WHY : surface known issues to VALIDATE manually (playbook/17). Scanners = hypotheses.
# IMPORTANT: on fragile ERP even some "vuln" scripts probe hard. This excludes dos/brute and
#            keeps gentle timing. Review/skip per host if the client flags a node fragile.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "06-vulnscan" "vulns"; scope_guard
need nmap
echo "This runs nmap safe vuln scripts (NOT exploits, NOT brute, NOT dos)."
require_approval "nmap safe-vuln scripts against ERP hosts" "extra probing load on fragile services"

vuln_one(){
  local name="$1" ip="$2" pf="$OUTDIR/ports/$name.nmap" openp
  [ -f "$pf" ] || { info "$name: run 02 first"; return; }
  openp="$(open_ports_from "$pf")"; [ -z "$openp" ] && return
  log "vulnscan $name $ip ports=$openp"
  nmap -Pn -sV $TIMING -p "$openp" \
       --script "vuln and safe and not dos and not brute" --script-timeout 120s \
       "$ip" -oA "$PHASE_DIR/$name" >/dev/null
  echo "=== $name ==="; grep -iE "vulnerable|cve|state:" "$PHASE_DIR/$name.nmap" || echo "  (no safe-script hits)"
}
for_each_target vuln_one
echo "[*] Vuln checks done -> $PHASE_DIR/  (VALIDATE each hit before it's a finding — playbook/17)"

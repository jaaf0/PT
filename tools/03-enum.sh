#!/usr/bin/env bash
# 03-enum.sh — safe version + default-script fingerprint on OPEN ports only.
# RISK: SAFE DISCOVERY -> light CONTROLLED (version probes touch services, intensity kept low).
# WHAT: identify service/version and basic config; classify each host's stack.
# WHY : turn "port open" into "what is it", so you pick the right deep-dive.
# NOTE: uses ONLY safe, non-intrusive scripts. No brute/dos/vuln scripts here (see 06).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "03-enum" "enumeration"; scope_guard
need nmap

enum_one(){
  local name="$1" ip="$2" pf="$OUTDIR/ports/$name.nmap"
  [ -f "$pf" ] || { info "$name: run 02-portscan first"; return; }
  local openp; openp="$(open_ports_from "$pf")"
  [ -z "$openp" ] && { info "$name: no open ports"; return; }
  log "enum $name $ip ports=$openp"
  nmap -Pn -sV --version-intensity 2 $TIMING -p "$openp" \
       --script "banner,http-title,http-headers,http-server-header,ssl-cert,ssh2-enum-algos,rdp-ntlm-info,ms-sql-info,oracle-tns-version,(sap-* and safe)" \
       --script-timeout 60s "$ip" -oA "$PHASE_DIR/$name" >/dev/null
  echo "=== $name ($ip) ==="; grep -E "^[0-9]+/tcp +open" "$PHASE_DIR/$name.nmap"
}
for_each_target enum_one

# Stack classification across all hosts
{
  echo "# Stack classification — $(TS)"
  for i in "${!TIPS[@]}"; do
    n="${TNAMES[$i]}"; f="$PHASE_DIR/$n.nmap"; [ -f "$f" ] || continue
    sap=$(grep -icE 'sap|netweaver|saprouter|disp\+work|icman' "$f")
    ora=$(grep -icE 'oracle|tns|weblogic|e-business' "$f")
    mss=$(grep -icE 'ms-sql|microsoft sql' "$f")
    hana=$(grep -icE 'hana|hdbindexserver|3001[3-5]' "$f")
    printf -- "- %-14s SAP=%s Oracle=%s MSSQL=%s HANA=%s\n" "$n" "$sap" "$ora" "$mss" "$hana"
  done
  echo; echo "Decide stack, then: SAP -> tools/04-sap-enum.sh ; web present -> tools/05-web.sh ; generic -> playbook/05"
} | tee "$PHASE_DIR/stack-classification.md"
echo "[*] Enum done -> $PHASE_DIR/"

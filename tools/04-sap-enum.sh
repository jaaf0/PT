#!/usr/bin/env bash
# 04-sap-enum.sh — SAP-aware SAFE enumeration (read-only information disclosure checks).
# RISK: SAFE DISCOVERY. Reachability + unauthenticated version/info only.
# WHAT: map SAP instances/tiers and spot classic exposures (open ICF, MS/GW ACLs, old kernel).
# WHY : SAP has a specific surface; generic tools miss it.
# GATED (NOT here): default-credential checks (lockout!), gw/ms registration abuse, RFC,
#                   Invoker servlet, RECON/10KBLAZE, any pysap/metasploit EXPLOIT action.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "04-sap-enum" "sap"; scope_guard
need curl

probe_http(){ # name ip port scheme path
  local name="$1" ip="$2" port="$3" scheme="$4" path="$5"
  local url="$scheme://$ip:$port$path"
  local code; code=$(curl -skSL --max-time 8 -o "$PHASE_DIR/${name}_${port}$(echo "$path"|tr '/?' '__').body" \
                     -w '%{http_code}' -D "$PHASE_DIR/${name}_${port}_hdr.txt" "$url" 2>/dev/null) || return 0
  echo "  $url -> HTTP $code"
  echo "### $url -> $code" >> "$PHASE_DIR/$name-icm.txt"
}

sap_one(){
  local name="$1" ip="$2" pf="$OUTDIR/ports/$name.nmap" openp
  [ -f "$pf" ] && openp="$(open_ports_from "$pf")" || openp=""
  echo "=== SAP enum: $name ($ip) ==="
  log "sap-enum $name $ip open=$openp"
  # Identify SAP-relevant open ports
  echo "  SAP-relevant open ports: $(echo "$openp" | tr ',' '\n' | grep -E '^(32|33|36|48|81)[0-9]{2}$|^443[0-9]{2}$|^500[0-9]{2}$|^112[89]$|^3299$|^8000$|^3001[0-9]$' | paste -sd, - )"
  # ICM / Web app server info (unauthenticated public endpoints)
  for pp in 8000 50000 80 8080; do probe_http "$name" "$ip" "$pp" http  "/sap/public/info"; done
  for pp in 44300 443;        do probe_http "$name" "$ip" "$pp" https "/sap/public/info"; done
  probe_http "$name" "$ip" 8000  http  "/sap/bc/ping"
  probe_http "$name" "$ip" 8000  http  "/sap/public/icman/ping"
  # SAP Start Service (sapctrl) SOAP GetVersionInfo — unauth version info only
  for sp in 50013 50113 50213; do
    curl -skS --max-time 8 -H 'Content-Type: text/xml' \
      --data '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><ns1:GetVersionInfo xmlns:ns1="urn:SAPControl"/></SOAP-ENV:Body></SOAP-ENV:Envelope>' \
      "http://$ip:$sp/" -o "$PHASE_DIR/${name}_sapctrl_${sp}.xml" 2>/dev/null && \
      [ -s "$PHASE_DIR/${name}_sapctrl_${sp}.xml" ] && echo "  sapctrl $sp: version info saved"
  done
  # Safe nmap SAP scripts if available
  if have nmap && [ -n "$openp" ]; then
    nmap -Pn $TIMING -p "$openp" --script "sap-* and safe" --script-timeout 90s "$ip" \
         -oN "$PHASE_DIR/$name-sap-nse.txt" >/dev/null 2>&1 || true
  fi
}
for_each_target sap_one
echo
echo "[*] SAP enum done -> $PHASE_DIR/"
echo "    Review for: exposed ICF services, message-server/gateway ACL openness, kernel/patch"
echo "    level, verbose /sap/public/info, weak TLS. Each -> validate (playbook/17) before finding."
echo "    GATED next steps (default creds / gw-ms abuse / exploits) need APPROVAL_REF + scheduling."

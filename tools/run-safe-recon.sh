#!/usr/bin/env bash
# run-safe-recon.sh — run the SAFE DISCOVERY phases in order (01 -> 05).
# Does NOT run 06 (vuln checks, gated) or 07 (creds, gated). RISK: SAFE->light CONTROLLED.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "[*] Safe recon chain: discovery -> portscan -> enum -> sap-enum -> web"
echo "    (vuln checks and credential work are separate, gated scripts.)"
"$HERE/01-discovery.sh"
"$HERE/02-portscan.sh"
"$HERE/03-enum.sh"
"$HERE/04-sap-enum.sh"
"$HERE/05-web.sh"
echo "[*] Safe recon complete. Review engagement/enumeration/stack-classification.md,"
echo "    then tools/08-report.sh to collate. Gated phases need APPROVAL_REF."

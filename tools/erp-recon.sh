#!/usr/bin/env bash
# erp-recon.sh — quick all-in-one SAFE, fingerprint-first recon for fragile ERP hosts.
# (For the modular version, use tools/00-setup.sh + run-safe-recon.sh.)
# Reads targets from scope/targets.local (git-ignored) — NO IPs are stored in this script.
# SAFE DISCOVERY only: discovery + curated ports + light version/HTTP fingerprint.
# No auth, brute, UDP flood, vuln/dos scripts, or exploitation.
# RUN FROM YOUR AUTHORIZED TESTER HOST — not a cloud session.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"
TF="${TARGETS_FILE:-$ROOT/scope/targets.local}"
[ -f "$TF" ] || { echo "[!] Create your target list first: cp tools/targets.sample scope/targets.local && edit"; exit 1; }

OUT="${1:-erp-recon-$(date -u +%Y%m%d-%H%M%SZ)}"
TS(){ date -u +%FT%TZ; }
command -v nmap >/dev/null || { echo "[!] nmap required"; exit 1; }
mkdir -p "$OUT"/{discovery,ports,fingerprint,http}

TIMING="-T2 --max-rate 60 --max-retries 1 --host-timeout 20m --scan-delay 15ms"
COMMON="21,22,23,25,53,80,88,110,111,135,139,389,443,445,636,1433,1521,3306,3389,5432,5985,5986,8080,8443,8000,9000,9090,10000"
SAP="3200-3299,3300-3399,3600-3699,4800-4899,8100-8110,44300-44320,50000-50120,1128-1129,30000-30050"
OTHER_ERP="1526,7001,7002,8001,6015,6017"
PORTS="${COMMON},${SAP},${OTHER_ERP}"
[ "$(id -u)" = 0 ] && SCAN="-sS" || { SCAN="-sT"; echo "[i] not root: using -sT"; }

# Load NAME IP pairs from the local file
NAMES=(); IPS=()
while read -r n ip _; do [ -z "${n:-}" ] && continue; [[ "$n" == \#* ]] && continue; [ -z "${ip:-}" ] && continue; NAMES+=("$n"); IPS+=("$ip"); done < "$TF"
[ "${#IPS[@]}" -gt 0 ] || { echo "[!] no targets in $TF"; exit 1; }

echo "About to run SAFE DISCOVERY against ${#IPS[@]} in-scope hosts from $TF."
echo "Confirm you are on the AUTHORIZED tester host, window is open, SOC notified."
read -r -p "Type 'GO': " a; [ "$a" = "GO" ] || { echo "Aborted."; exit 0; }
printf '%s\n' "${IPS[@]}" | sort -u > "$OUT/targets.txt"

echo "$(TS) STAGE0 reachability" | tee -a "$OUT/command-log.txt"
nmap -sn -PE -PS22,443,3200 -PA3300 $TIMING -iL "$OUT/targets.txt" -oA "$OUT/discovery/ping" >/dev/null || true

for i in "${!IPS[@]}"; do
  n="${NAMES[$i]}"; ip="${IPS[$i]}"
  echo "$(TS) scan $n" | tee -a "$OUT/command-log.txt"
  nmap -Pn $SCAN $TIMING -p "$PORTS" --open "$ip" -oA "$OUT/ports/$n" >/dev/null
  openp=$(grep -E "^[0-9]+/tcp +open" "$OUT/ports/$n.nmap" | cut -d/ -f1 | paste -sd, -)
  echo "=== $n open: ${openp:-none} ==="
  [ -n "$openp" ] && nmap -Pn -sV --version-intensity 2 $TIMING -p "$openp" \
    --script "banner,http-title,http-headers,ssl-cert,(sap-* and safe)" --script-timeout 60s \
    "$ip" -oA "$OUT/fingerprint/$n" >/dev/null
done
echo "[*] Done. Review $OUT/ (fingerprint/*.nmap). For the full workflow use the numbered tools/."

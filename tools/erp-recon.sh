#!/usr/bin/env bash
# erp-recon.sh — SAFE, fingerprint-first reconnaissance for FRAGILE ERP hosts.
# Scope: host discovery + curated TCP port scan + careful version/HTTP fingerprinting.
# It does NOT: authenticate, brute force, spray, run vuln/dos/intrusive scripts,
#              exploit, or scan UDP broadly. Those are later, separately-approved phases.
#
# RUN THIS FROM YOUR AUTHORIZED TESTING HOST (whitelisted egress IP) — not a random box.
#
# Usage:  sudo ./erp-recon.sh            # sudo enables stealthier -sS; plain works too (-sT)
#         ./erp-recon.sh /path/to/outdir
set -uo pipefail

# ---- Targets (confirmed in-scope, window agreed) --------------------------------
declare -A HOSTS=(
  [<HOST-REDACTED>]=<IP-REDACTED>
  [<HOST-REDACTED>]=<IP-REDACTED>
  [<HOST-REDACTED>]=<IP-REDACTED>
  [<HOST-REDACTED>]=<IP-REDACTED>
  [<HOST-REDACTED>]=<IP-REDACTED>
)

OUT="${1:-erp-recon-$(date -u +%Y%m%d-%H%M%SZ)}"
TS(){ date -u +%FT%TZ; }
LOG(){ echo "$(TS) $*" | tee -a "$OUT/command-log.txt"; }

# ---- Gentle timing profile for fragile production ERP ---------------------------
# -T2, low rate, 1 retry, host-timeout so a wedged host can't stall you.
# NO -A, NO -T4/5, NO --script vuln/brute/dos, NO -O flood.
TIMING="-T2 --max-rate 60 --max-retries 1 --host-timeout 20m --scan-delay 15ms"

# ---- Curated port set --------------------------------------------------------
# Common admin/db/web ports + ERP signatures (fingerprint-first; instance # unknown).
COMMON="21,22,23,25,53,80,88,110,111,135,139,389,443,445,636,1433,1521,3306,3389,5432,5985,5986,8080,8443,8000,9000,9090,10000"
# SAP signature ranges (NN = instance 00-99): dispatcher 32NN, gateway 33NN/48NN,
# message server 36NN/81NN, ICM web 80NN/443NN, start service 5NN13-14, SAProuter 3299,
# SAP Host Agent 1128-1129, HANA 3NN13-15/30013-30041.
SAP="3200-3299,3300-3399,3600-3699,4800-4899,8100-8110,44300-44320,50000-50120,1128-1129,30000-30050"
# Oracle/other ERP hints: Oracle TNS 1521/1526, WebLogic 7001-7002, EBS 8000/8001, JD Edwards 6015-6017.
OTHER_ERP="1526,7001,7002,8001,6015,6017"
PORTS="${COMMON},${SAP},${OTHER_ERP}"

# ---- Preconditions ----------------------------------------------------------
command -v nmap >/dev/null || { echo "[!] nmap not found. Install nmap first."; exit 1; }
mkdir -p "$OUT"/{discovery,ports,fingerprint,http}
if [ "$(id -u)" = "0" ]; then SCAN="-sS"; else SCAN="-sT"; echo "[i] Not root: using TCP connect scan (-sT). sudo gives stealthier -sS."; fi

# ---- Scope guard: require explicit confirmation -----------------------------
echo "About to run SAFE DISCOVERY against these IN-SCOPE hosts:"
for n in "${!HOSTS[@]}"; do printf "   %-14s %s\n" "$n" "${HOSTS[$n]}"; done
echo "Confirm: (1) you are on the AUTHORIZED testing host, (2) the window is open now,"
echo "         (3) SOC is notified per RoE."
read -r -p "Type 'GO' to proceed: " ans
[ "$ans" = "GO" ] || { echo "Aborted."; exit 0; }

printf '%s\n' "${HOSTS[@]}" | sort -u > "$OUT/targets.txt"
LOG "START erp-recon from $(hostname) as uid=$(id -u) scan=$SCAN"

# ---- STAGE 0: Reachability (gentle) -----------------------------------------
LOG "STAGE0 reachability"
nmap -sn -PE -PS22,443,3200 -PA3300 $TIMING -iL "$OUT/targets.txt" \
     -oA "$OUT/discovery/ping" >/dev/null
grep -E "Nmap scan report" "$OUT/discovery/ping.nmap" || echo "[i] No ICMP/TCP ping reply (hosts may filter) — continuing with -Pn."

# ---- STAGE 1: Curated TCP port scan, ONE HOST AT A TIME ---------------------
LOG "STAGE1 curated TCP port scan (sequential, gentle)"
for n in "${!HOSTS[@]}"; do
  ip="${HOSTS[$n]}"
  LOG "  scan $n $ip"
  nmap -Pn $SCAN $TIMING -p "$PORTS" --open "$ip" \
       -oA "$OUT/ports/$n" >/dev/null
  echo "=== $n ($ip) open ports ===" ; grep -E "^[0-9]+/tcp +open" "$OUT/ports/$n.nmap" || echo "  (none in curated set)"
done

# ---- STAGE 2: Safe version + default-script fingerprint on OPEN ports only ---
# --version-intensity 2 = light probing. Script set = SAFE & non-intrusive ONLY.
LOG "STAGE2 version + safe-script fingerprint (open ports only)"
for n in "${!HOSTS[@]}"; do
  ip="${HOSTS[$n]}"
  openp=$(grep -E "^[0-9]+/tcp +open" "$OUT/ports/$n.nmap" | cut -d/ -f1 | paste -sd, -)
  [ -z "$openp" ] && { echo "[i] $n: no open ports to fingerprint"; continue; }
  LOG "  fingerprint $n $ip ports=$openp"
  nmap -Pn -sV --version-intensity 2 $TIMING -p "$openp" \
       --script "banner,http-title,http-headers,http-server-header,ssl-cert,sap-* and safe" \
       --script-timeout 60s "$ip" -oA "$OUT/fingerprint/$n" >/dev/null
done

# ---- STAGE 3: HTTP/ICM identification (SAP vs Oracle vs generic) -------------
LOG "STAGE3 HTTP/ICM identification"
for n in "${!HOSTS[@]}"; do
  ip="${HOSTS[$n]}"
  for p in 80 8000 8080 50000 50013 443 44300 8443; do
    url="http://$ip:$p/"; [ "$p" = 443 -o "$p" = 44300 -o "$p" = 8443 ] && url="https://$ip:$p/"
    hdr=$(curl -skSL --max-time 8 -D - -o /dev/null "$url" 2>/dev/null) || continue
    [ -n "$hdr" ] && { echo "### $n $url" >> "$OUT/http/headers.txt"; echo "$hdr" >> "$OUT/http/headers.txt"; echo >> "$OUT/http/headers.txt"; }
  done
done

# ---- Stack identification summary -------------------------------------------
LOG "SUMMARY stack identification"
{
  echo "# ERP Recon Summary — $(TS)"
  echo
  echo "## Open ports per host"
  for n in "${!HOSTS[@]}"; do
    echo "### $n (${HOSTS[$n]})"
    grep -E "^[0-9]+/tcp +open" "$OUT/fingerprint/$n.nmap" 2>/dev/null || \
      grep -E "^[0-9]+/tcp +open" "$OUT/ports/$n.nmap" 2>/dev/null || echo "  (none)"
    echo
  done
  echo "## Stack signals (grep across fingerprint + HTTP headers)"
  echo "- SAP indicators:    $(grep -rilE 'sap|netweaver|icm|saprouter|disp\+work' "$OUT/fingerprint" "$OUT/http" 2>/dev/null | wc -l) file(s)"
  echo "- Oracle indicators: $(grep -rilE 'oracle|tns|weblogic|e-business' "$OUT/fingerprint" "$OUT/http" 2>/dev/null | wc -l) file(s)"
  echo "- MSSQL indicators:  $(grep -rilE 'ms-sql|microsoft sql' "$OUT/fingerprint" 2>/dev/null | wc -l) file(s)"
  echo "- HANA indicators:   $(grep -rilE 'hana|hdbindexserver|3001[3-5]' "$OUT/fingerprint" 2>/dev/null | wc -l) file(s)"
  echo
  echo "## Next step"
  echo "Read fingerprint/*.nmap + http/headers.txt, decide the stack, then jump to the"
  echo "matching chapter: SAP -> (SAP-aware enum, see guidance); generic -> playbook/05+."
} > "$OUT/SUMMARY.md"

LOG "DONE. Review: $OUT/SUMMARY.md"
echo; echo "[*] Done. Start with: $OUT/SUMMARY.md"

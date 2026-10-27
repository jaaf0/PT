#!/usr/bin/env bash
# 05-web.sh — web discovery & fingerprinting on any HTTP(S) ports found. RISK: SAFE->CONTROLLED.
# WHAT: identify web apps, tech, TLS, headers, and do light content discovery.
# WHY : ERP web tiers (SAP ICM/Fiori, Oracle EBS, WebLogic) carry high-value exposures.
# NOTE: no auth, no destructive fuzzing; ffuf/nuclei rate-limited; manual testing = Burp (playbook/10).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "05-web" "web"; scope_guard

# Build url list from open web-ish ports discovered in 02.
: > "$PHASE_DIR/urls.txt"
web_urls(){
  local name="$1" ip="$2" pf="$OUTDIR/ports/$name.nmap" p
  [ -f "$pf" ] || return
  for p in $(open_ports_from "$pf" | tr ',' ' '); do
    case "$p" in
      80|8080|8000|50000|9090|10000|8001) echo "http://$ip:$p"  >> "$PHASE_DIR/urls.txt" ;;
      443|8443|44300|7002)                echo "https://$ip:$p" >> "$PHASE_DIR/urls.txt" ;;
    esac
  done
}
for_each_target web_urls
sort -u -o "$PHASE_DIR/urls.txt" "$PHASE_DIR/urls.txt"
info "web targets: $(wc -l < "$PHASE_DIR/urls.txt")"

if have httpx; then httpx -silent -l "$PHASE_DIR/urls.txt" -title -tech-detect -status-code -server \
   -o "$PHASE_DIR/httpx.txt" -rl 20 2>/dev/null; cat "$PHASE_DIR/httpx.txt"; else info "httpx not installed (optional)"; fi
if have whatweb; then whatweb -a3 -i "$PHASE_DIR/urls.txt" --log-brief="$PHASE_DIR/whatweb.txt" >/dev/null 2>&1 || true; fi
if have testssl.sh; then while read -r u; do [[ $u == https* ]] && testssl.sh --quiet --color 0 "$u" > "$PHASE_DIR/tls-$(echo "$u"|tr ':/' '__').txt" 2>&1; done < "$PHASE_DIR/urls.txt"; fi

# Gentle, non-intrusive templated checks ONLY (exclude dos/intrusive/fuzzing).
if have nuclei; then
  info "nuclei: safe templates only, rate-limited"
  nuclei -silent -l "$PHASE_DIR/urls.txt" -rl 20 -c 10 \
    -severity low,medium,high,critical \
    -etags dos,intrusive,fuzz,brute -o "$PHASE_DIR/nuclei.txt" 2>/dev/null || true
else info "nuclei not installed (optional)"; fi
echo "[*] Web recon done -> $PHASE_DIR/  (validate hits manually in Burp before any finding)"

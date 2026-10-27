#!/usr/bin/env bash
# 10-owasp.sh — OWASP Top 10 (2021) web testing: SAFE/automatable parts only.
# RISK: SAFE DISCOVERY -> light CONTROLLED. No exploitation, no data mutation, no brute.
# WHAT: runs the non-destructive checks for each OWASP category and emits a per-URL
#       checklist you complete MANUALLY in Burp (authz/logic/injection validation).
# WHY : most of the Top 10 (A01/A03/A04/A08/A10) is manual by nature; this does the
#       automatable 20% (A02/A05/A06 + evidence scaffolding) and structures the rest.
# INPUT: engagement/web/urls.txt from tools/05-web.sh (git-ignored; built from your targets).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "10-owasp" "web/owasp"; scope_guard
URLS="$OUTDIR/web/urls.txt"
[ -s "$URLS" ] || die "no URL list — run tools/05-web.sh first ($URLS)"
info "URLs under test: $(wc -l < "$URLS")"

hdr(){ curl -skSL --max-time 10 -D - -o /dev/null "$1" 2>/dev/null; }

while read -r u; do
  [ -z "$u" ] && continue
  slug=$(echo "$u" | tr ':/?.' '____'); d="$PHASE_DIR/$slug"; mkdir -p "$d"
  log "owasp checks $u"

  # ---- A02 Cryptographic Failures: TLS + sensitive-header hygiene ----
  if [[ $u == https* ]] && have testssl.sh; then
    testssl.sh --quiet --color 0 --severity LOW "$u" > "$d/A02-tls.txt" 2>&1 || true
  fi
  H=$(hdr "$u"); echo "$H" > "$d/headers.txt"

  # ---- A05 Security Misconfiguration: headers, methods, listing, verbose errors ----
  {
    echo "# A05 misconfig — $u"
    for h in Strict-Transport-Security Content-Security-Policy X-Frame-Options \
             X-Content-Type-Options Referrer-Policy Permissions-Policy; do
      echo "$H" | grep -qi "^$h:" && echo "[ok]   $h present" || echo "[MISS] $h ABSENT"
    done
    echo "$H" | grep -iE '^(Server|X-Powered-By|X-AspNet-Version):' | sed 's/^/[info] banner: /'
    echo "--- allowed methods (OPTIONS) ---"
    curl -skSL --max-time 10 -X OPTIONS -D - -o /dev/null "$u" 2>/dev/null | grep -i '^Allow:' || echo "[info] no Allow header"
    echo "[check] TRACE/PUT/DELETE enabled? verify in Burp before concluding"
  } > "$d/A05-misconfig.txt"

  # ---- A06 Vulnerable/Outdated Components: safe templated checks ----
  if have nuclei; then
    nuclei -silent -u "$u" -rl 20 -c 10 -etags dos,intrusive,fuzz,brute \
      -severity low,medium,high,critical -o "$d/A06-nuclei.txt" 2>/dev/null || true
  fi
  if have whatweb; then whatweb -a3 "$u" --log-brief="$d/A06-whatweb.txt" >/dev/null 2>&1 || true; fi

  # ---- A01 Broken Access Control: safe pre-checks (no exploitation) ----
  {
    echo "# A01 access control — $u"
    echo "[check] CORS reflection:"; curl -skSL --max-time 10 -H 'Origin: https://evil.example' -D - -o /dev/null "$u" 2>/dev/null | grep -i 'access-control-allow' || echo "  none"
    echo "[manual] IDOR/BOLA: compare 2 accounts in Burp (playbook/10 & /11)"
    echo "[manual] forced browsing to /admin,/actuator,/console,/webdynpro,/OA_HTML (ERP consoles)"
  } > "$d/A01-access.txt"

  # ---- A10 SSRF: enumerate candidate params (manual validation only) ----
  echo "# A10 SSRF — inspect params like url=,uri=,next=,redirect=,dest=,feed=,img= in Burp; point at your listener. DO NOT hit internal infra without noting it." > "$d/A10-ssrf.txt"

  echo "  -> $d"
done < "$URLS"

# ---- Per-engagement OWASP checklist (manual categories spelled out) ----
cat > "$PHASE_DIR/CHECKLIST.md" <<'MD'
# OWASP Top 10 (2021) — manual test checklist (per web app)
Complete in Burp against each app; attach req/resp evidence per finding (playbook/26).

- [ ] A01 Broken Access Control — IDOR/BOLA (2 accounts), forced browsing to consoles
      (SAP /sap/bc/webdynpro,/sap/bc/gui; EBS /OA_HTML; WebLogic /console), path traversal, CORS
- [ ] A02 Cryptographic Failures — TLS (A02-tls.txt), secrets in transit, weak ciphers, cookies Secure/HttpOnly/SameSite
- [ ] A03 Injection — SQLi/LDAP/cmd/XSS: time-based/benign PoC ONLY; no data mutation (gate heavy tests)
- [ ] A04 Insecure Design — business-logic abuse (workflow skip, negative values, race) in a TEST account
- [ ] A05 Security Misconfiguration — headers (A05-misconfig.txt), default creds (single try), dir listing, verbose errors, exposed admin
- [ ] A06 Vulnerable & Outdated Components — versions→CVE (A06-nuclei.txt); VALIDATE before claiming (playbook/17)
- [ ] A07 Identification & Auth Failures — weak session mgmt, missing MFA, lockout policy, JWT flaws; NO brute/spray (gated, playbook/20)
- [ ] A08 Software & Data Integrity Failures — insecure deserialization (Java/.NET — common in ERP!), unsigned updates, CI/CD exposure
- [ ] A09 Security Logging & Monitoring Failures — did your actions alert? cross-ref detection log (playbook/24)
- [ ] A10 SSRF — url/redirect params; point at your listener/metadata (read-only); note internal reachability

ERP cautions: all CONTROLLED/heavy tests on PRODUCTION nodes stay gentle and, where they could
disrupt, REQUIRE EXPLICIT RoE APPROVAL. Prefer the TEST node for noisier validation first.
MD
echo "[*] OWASP automated checks done -> $PHASE_DIR/  (now work $PHASE_DIR/CHECKLIST.md in Burp)"

#!/usr/bin/env bash
# 08-report.sh — collate outputs into a report skeleton + evidence index. RISK: none (local).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
setup_out "08-report" "reports"
R="$PHASE_DIR/draft-report.md"
{
  echo "# $ENGAGEMENT_NAME — Penetration Test Report (DRAFT)"
  echo "_Generated $(TS) by $TESTER._"
  echo; echo "## Scope"; echo "Targets: $(wc -l < "$OUTDIR/scope/targets.txt") in-scope hosts (see scope/targets.local, not committed)."
  echo; echo "## Hosts & open ports"
  for i in "${!TIPS[@]}"; do
    n="${TNAMES[$i]}"; f="$OUTDIR/ports/$n.nmap"
    echo "### $n"; [ -f "$f" ] && grep -E "^[0-9]+/tcp +open" "$f" | sed 's/^/    /' || echo "    (no scan)"
  done
  echo; echo "## Stack classification"; cat "$OUTDIR/enumeration/stack-classification.md" 2>/dev/null || echo "(run 03-enum)"
  echo; echo "## Candidate findings (validate before finalizing — playbook/17 & 27)"
  echo "| ID | Host | Service | Issue | Severity | Status |"; echo "|----|------|---------|-------|----------|--------|"
  echo "| F-001 | | | | | candidate |"
  echo; echo "## Evidence index"; find "$OUTDIR" -type f \( -name '*.nmap' -o -name '*.txt' -o -name '*.md' \) 2>/dev/null | sed 's/^/- /'
  echo; echo "## Next (gated) phases"
  echo "- Validate candidates manually. SAP default-cred / gw-ms / exploit phases need APPROVAL_REF + window."
} > "$R"
echo "[*] Draft report -> $R"
echo "[i] Fill findings using playbook/28 format; keep IPs/evidence LOCAL (engagement/ is git-ignored)."

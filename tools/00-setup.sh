#!/usr/bin/env bash
# 00-setup.sh — install dependencies and prepare the local engagement tree.
# RISK: none (local). Run once on your tester host.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"

info "Checking core tools..."
CORE=(nmap curl git jq)
WEB=(httpx whatweb nuclei ffuf)
AD=(netexec nxc impacket-getuserspns bloodhound-python)   # optional, later phases
MISS=()
for t in "${CORE[@]}"; do have "$t" || MISS+=("$t"); done
if [ "${#MISS[@]}" -gt 0 ]; then
  echo "[!] Missing core tools: ${MISS[*]}"
  echo "    Debian/Ubuntu/Kali:  sudo apt update && sudo apt install -y nmap curl git jq"
  echo "    RHEL/Rocky/Alma:     sudo dnf install -y nmap curl git jq"
fi
echo "[i] Optional web tools (install when you reach the web phase): ${WEB[*]}"
echo "    e.g.  go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
echo "          go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
echo "          go install github.com/ffuf/ffuf/v2@latest ; apt install -y whatweb"
echo "[i] Optional internal/AD tools (only if the stack turns out to need them): ${AD[*]}"
echo "          pipx install netexec ; pipx install impacket ; pipx install bloodhound"

# Local engagement tree + targets file
mkdir -p "$ROOT"/{scope,} "$OUTDIR"
if [ ! -f "$ROOT/scope/targets.local" ]; then
  cp "$HERE/targets.sample" "$ROOT/scope/targets.local"
  echo "[*] Created scope/targets.local — EDIT IT with your real in-scope hosts (git-ignored)."
else
  echo "[i] scope/targets.local already exists."
fi
echo "[*] Setup done. Next: edit scope/targets.local, then run tools/01-discovery.sh"

#!/usr/bin/env bash
# 99-cleanup.sh — end-of-engagement cleanup helper & checklist. RISK: none.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"
cat <<CHK
=== Cleanup checklist (verify each, then record in engagement/logs/) ===
[ ] Remove any uploaded tools / binaries from target hosts
[ ] Remove any test files you created (uploads, webshells, markers)
[ ] Remove any accounts/group memberships you added (and reversals confirmed)
[ ] Disable anything you enabled (e.g. xp_cmdshell) — restore original state
[ ] Drop any scheduled tasks / cron you created
[ ] Close tunnels / pivots (chisel/ligolo/ssh)
[ ] Confirm no persistence left behind
[ ] Securely store evidence; schedule destruction per RoE retention
Local-only data reminder: engagement/, loot/, scope/targets.local are git-ignored.
CHK
echo "[i] Command log for audit: $OUTDIR/logs/command-log.txt"

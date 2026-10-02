#!/usr/bin/env bash
# init-engagement.sh — create the standard engagement working tree.
# Usage: ./init-engagement.sh <ENGAGEMENT_NAME>
# WHY: a fixed structure means every artifact has one obvious home, so a second
# consultant (or you, in week 3) can find evidence without asking.
set -euo pipefail
ENG="${1:-engagement}"
mkdir -p "$ENG"/{scope,inventory,discovery,scans/{tcp,udp,quick},enumeration,web,windows,linux,active-directory,credentials,exploitation,privilege-escalation,lateral-movement,segmentation,attack-paths,evidence,screenshots,notes,reports,loot,logs}
# seed tracking files
: > "$ENG/scope/in-scope.txt"            # one CIDR or IP per line (authorized)
: > "$ENG/scope/out-of-scope.txt"        # explicit exclusions — check EVERY target against this
: > "$ENG/inventory/hosts.csv"
echo "asset_id,cidr,ip,hostname,os,role,status,notes" > "$ENG/inventory/hosts.csv"
echo "asset_id,ip,port,proto,service,version,state,auth,notes" > "$ENG/inventory/services.csv"
echo "finding_id,asset_id,ip,port,service,vuln,severity,exploitability,status,evidence_path,owner,notes" > "$ENG/inventory/findings.csv"
echo "cred_id,source_finding,realm,username,secret_type,secret_ref,validated_on,scope,notes" > "$ENG/credentials/credentials.csv"
echo "path_id,initial_asset,initial_access,credential,intermediate,privilege,next_hop,critical_asset,impact,evidence,status" > "$ENG/attack-paths/paths.csv"
# command log — append every command you run with a timestamp
: > "$ENG/logs/command-log.txt"
echo "[*] Engagement tree created at: $ENG"
find "$ENG" -maxdepth 2 -type d | sort

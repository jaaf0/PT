# Engagement Toolkit

Modular, safety-railed scripts for this engagement. **Run from your authorized tester host**
(whitelisted egress IP) on the network that routes to the targets — never from the cloud session.

## Golden rules baked in
- **Targets are never committed.** They live in `scope/targets.local` (git-ignored). Create it
  from `tools/targets.sample`. Keep real IPs/hostnames off the repo/cloud.
- **All engagement output is git-ignored** (`engagement/`, `*.nmap`, `loot/`, …).
- **Scope guard** on every active script (type `GO`).
- **Gentle timing** (`-T2`, low rate) for fragile ERP — set in `engagement.conf`, don't raise it.
- **Gated actions** (vuln scripts, credential spray) refuse unless `APPROVAL_REF` is set and
  you confirm — these can disrupt or lock accounts.

## Setup
```bash
./tools/00-setup.sh                 # checks tools, creates scope/targets.local
nano scope/targets.local            # add your real in-scope hosts: NAME<space>IP
```

## Phases
| Script | Phase | Risk |
|--------|-------|------|
| `00-setup.sh` | install deps, make targets file | none |
| `01-discovery.sh` | host discovery (gentle) | SAFE |
| `02-portscan.sh` | curated TCP ports (`FULL=1` adds slow full-TCP) | SAFE |
| `03-enum.sh` | version + safe-script fingerprint; classifies stack | SAFE→light CONTROLLED |
| `04-sap-enum.sh` | SAP-aware read-only enum (ICM/ICF, sapctrl, ACL reachability) | SAFE |
| `05-web.sh` | web fingerprint + safe nuclei/httpx/whatweb/testssl | SAFE→CONTROLLED |
| `10-owasp.sh` | OWASP Top 10 (2021) web checks + manual checklist | SAFE→CONTROLLED |
| `run-safe-recon.sh` | runs 01→05 in order | SAFE→light CONTROLLED |
| `06-vulnscan.sh` | nmap safe-vuln scripts (no brute/dos) | CONTROLLED (gated) |
| `07-creds.sh` | `validate` known cred / `crack` offline / `spray` (gated) | CONTROLLED / GATED |
| `08-report.sh` | collate outputs into draft report + evidence index | none |
| `99-cleanup.sh` | end-of-engagement cleanup checklist | none |

## Typical flow
```bash
./tools/00-setup.sh && nano scope/targets.local
./tools/run-safe-recon.sh                      # 01-05, safe
# review engagement/enumeration/stack-classification.md -> decide SAP / Oracle / generic
APPROVAL_REF='RoE-ticket-123' ./tools/06-vulnscan.sh     # gated, within window
./tools/07-creds.sh validate smb 'svc_user' -p 'KnownPass1'   # single KNOWN cred only
./tools/08-report.sh
./tools/99-cleanup.sh
```

## What these scripts deliberately DO NOT do
No exploitation, no account brute force, no DoS, no UDP flood, no persistence, no SAP
default-credential spraying or gateway/message-server abuse. Those map to `playbook/18`+ and
require explicit written approval and scheduling. The scripts gate or omit them on purpose.

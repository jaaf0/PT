# 26 — Evidence Collection

> **Objective:** capture proof such that **another consultant can reproduce every finding** from
> your evidence alone, and such that you can prove you stayed in scope. Evidence is collected
> *continuously*, not at the end.

## WHY the standard is "reproducible by a stranger"

Reports get challenged ("we can't reproduce this", "were you even authorized to touch that?").
Evidence that is timestamped, command-complete, and scope-anchored ends those arguments and is
the difference between a finding that gets fixed and one that gets dismissed.

## Per-finding evidence record (capture ALL of these)

```
Finding ID:        F-014
Target asset ID:   ACME-SRV-014
IP / Hostname:     10.10.10.14 / SRV14.acme.local
Port / Protocol:   445/tcp
Service / Version: SMB / Windows Server 2019 (10.0.17763)
Tool:              netexec 1.x
Command:           nxc smb 10.10.10.14 -u svc_app -p '<ref>' --shares
Timestamp (UTC):   2026-10-02T14:32:10Z
Source IP:         <your tester IP>     ← proves in-scope origin
Raw output:        evidence/F-014/nxc-shares.txt
Screenshot:        screenshots/F-014-readable-share.png
Request/Response:  evidence/F-014/req-resp.http   (web/API findings)
User / Context:    svc_app (domain user) → READ on \\SRV14\Finance
Reproduction:      step-by-step (below)
Impact:            read access to finance documents incl. payroll_2026.xlsx
Recommendation:    restrict share ACL; rotate svc_app; enable auditing
```

Store each finding's artifacts under `evidence/<finding_id>/`. The CSV
(`inventory/findings.csv`) holds the index + `evidence_path`.

## Capture discipline
- **Timestamp everything in UTC** and keep the global `logs/command-log.txt` (every command, with
  time + source). This is your scope/behavior audit trail.
- **Full commands, not paraphrases** — including flags. A reader must be able to paste and run.
- **Raw tool output** saved to a file (don't rely on scrollback). Use `nmap -oA`, `tee`, redirect.
- **Screenshots** named `<finding_id>-<desc>.png`; annotate (box/arrow) the relevant part; show
  context (URL bar, hostname, `whoami`).
- **Request/response pairs** for web/API findings (save the exact HTTP, headers included).
- **Redact** per RoE (PII/secrets) in anything that leaves `loot/`; keep unredacted originals
  only in encrypted `loot/` if the RoE allows.

## Reproduction section (the test of good evidence)
Write it as numbered steps a peer can follow with no prior context:
```
1. From a host on the USER VLAN (10.10.20.0/24), as domain user svc_app:
2. Run: nxc smb 10.10.10.14 -u svc_app -p <pass> --shares
3. Observe READ permission on the 'Finance' share.
4. Run: smbclient //10.10.10.14/Finance -U 'acme\svc_app%<pass>' -c 'ls'
5. Observe payroll_2026.xlsx is readable (screenshot F-014-readable-share.png).
```

## Chain-of-custody for sensitive data
- Log access to any sensitive dataset (what, when, how much, why) in `notes/data-access-log.csv`.
- **Sample to prove exposure** (a few records / a redacted screenshot) — do **not** exfiltrate in
  bulk. Bulk collection needs explicit RoE approval and a defined secure-handling + destruction
  plan.

## Cleanup log
Every artifact you create (uploaded tool, shell, added account, test file, enabled feature like
xp_cmdshell) → record in `notes/cleanup-log.csv` with "removed?" status. Nothing left behind.

## Evidence structure
```
evidence/<finding_id>/   raw outputs, req/resp, PoC code
screenshots/             <finding_id>-*.png
loot/                    secrets/dumps (encrypted, gitignored)
logs/command-log.txt     global timestamped activity
notes/cleanup-log.csv    artifacts created & removed
notes/data-access-log.csv sensitive-data access record
```

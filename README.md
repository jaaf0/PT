# Operational Penetration Testing Playbook

A tool-driven, decision-first field manual for an **authorized** internal/external
network penetration test spanning 50–500+ hosts across multiple CIDRs.

> **This playbook assumes a signed engagement with a written Rules of Engagement (RoE).**
> Every action here is scoped to that authorization. Anything that can cause outage,
> lockout, data change, or detection escalation is explicitly flagged
> **`REQUIRES EXPLICIT RoE APPROVAL`**. When in doubt, stop and ask the client POC.

## How to read this playbook

Every phase follows the same loop. Train yourself to think in it:

```
OBSERVATION → OBJECTIVE → PRIMARY TOOL → COMMAND → EXPECTED OUTPUT
→ INTERPRETATION → DECISION → NEXT TOOL → VALIDATION → EVIDENCE → NEXT PHASE
```

The point is not the commands — it is the **decision at each branch**. A command
you run without knowing what you'll do with each possible result is wasted packets
and wasted risk budget.

## Risk labels used throughout

| Label | Meaning |
|-------|---------|
| **SAFE DISCOVERY** | Read-only, low-noise, no state change. Parallelize freely within rate limits. |
| **CONTROLLED VALIDATION** | Touches auth or sends crafted input, but non-destructive and reversible. Log it. |
| **POTENTIALLY DISRUPTIVE** | Could degrade a service, trip a threshold, or alter state. Throttle, schedule, notify. |
| **REQUIRES EXPLICIT RoE APPROVAL** | Do not run without written, specific sign-off referencing this technique. |

## Index

| # | File | Phase |
|---|------|-------|
| 00 | [00-rules-of-engagement.md](playbook/00-rules-of-engagement.md) | RoE, scope confirmation, pre-flight questions |
| 01 | [01-cidr-inventory.md](playbook/01-cidr-inventory.md) | CIDR normalization, target inventory, directory structure |
| 02 | [02-methodology-framework.md](playbook/02-methodology-framework.md) | The master tool-driven loop & how to use the tables |
| 03 | [03-host-discovery.md](playbook/03-host-discovery.md) | ICMP/TCP/UDP/ARP/DNS host discovery |
| 04 | [04-port-discovery.md](playbook/04-port-discovery.md) | Scalable port scanning strategy |
| 05 | [05-service-enumeration.md](playbook/05-service-enumeration.md) | Per-port enumeration matrix |
| 06 | [06-smb.md](playbook/06-smb.md) | SMB deep-dive |
| 07 | [07-active-directory.md](playbook/07-active-directory.md) | AD by access level (none→DC) |
| 08 | [08-windows-enum.md](playbook/08-windows-enum.md) | Windows host enumeration |
| 09 | [09-linux-enum.md](playbook/09-linux-enum.md) | Linux host enumeration |
| 10 | [10-web-app.md](playbook/10-web-app.md) | Web application testing |
| 10b | [OWASP-TOP10.md](playbook/OWASP-TOP10.md) | OWASP Top 10 (2021) ERP web guide |
| 11 | [11-api.md](playbook/11-api.md) | API testing |
| 12 | [12-dns.md](playbook/12-dns.md) | DNS |
| 13 | [13-ssh.md](playbook/13-ssh.md) | SSH |
| 14 | [14-rdp.md](playbook/14-rdp.md) | RDP |
| 15 | [15-winrm.md](playbook/15-winrm.md) | WinRM |
| 16 | [16-databases.md](playbook/16-databases.md) | MSSQL/MySQL/PostgreSQL/Oracle/Redis |
| 17 | [17-vuln-scanning.md](playbook/17-vuln-scanning.md) | Scanner orchestration & validation |
| 18 | [18-exploitation-decision.md](playbook/18-exploitation-decision.md) | Exploitation decision tree |
| 19 | [19-privilege-escalation.md](playbook/19-privilege-escalation.md) | Win & Linux privesc |
| 20 | [20-credential-testing.md](playbook/20-credential-testing.md) | Spraying, reuse, Kerberos/NTLM |
| 21 | [21-lateral-movement.md](playbook/21-lateral-movement.md) | Building the chain |
| 22 | [22-segmentation.md](playbook/22-segmentation.md) | Segmentation matrix |
| 23 | [23-network-devices.md](playbook/23-network-devices.md) | Firewalls, routers, VPN, appliances |
| 24 | [24-soc-edr-siem.md](playbook/24-soc-edr-siem.md) | Detection/response validation |
| 25 | [25-attack-path-analysis.md](playbook/25-attack-path-analysis.md) | Findings → paths → impact |
| 26 | [26-evidence.md](playbook/26-evidence.md) | Evidence standard |
| 27 | [27-severity.md](playbook/27-severity.md) | Severity & CVSS limits |
| 28 | [28-reporting.md](playbook/28-reporting.md) | Report & finding structure |
| 29 | [29-master-decision-tree.md](playbook/29-master-decision-tree.md) | One giant Mermaid tree |
| 30 | [30-tool-chains.md](playbook/30-tool-chains.md) | Per-service tool chains |
| 31 | [31-tool-map.md](playbook/31-tool-map.md) | Master tool map |
| 32 | [32-what-next-matrix.md](playbook/32-what-next-matrix.md) | "What do I do next?" matrix |
| 33 | [33-parallelization.md](playbook/33-parallelization.md) | Parallel vs sequential vs approval |
| 34 | [34-daily-workflow.md](playbook/34-daily-workflow.md) | 2–3 week day-by-day plan |
| 35 | [35-tracking-schema.md](playbook/35-tracking-schema.md) | Tracking & attack-path schemas |
| 36 | [36-mermaid-diagrams.md](playbook/36-mermaid-diagrams.md) | All methodology diagrams |
| 37 | [37-master-checklist.md](playbook/37-master-checklist.md) | The follow-along checklist |

## Quick start

```bash
./tools/init-engagement.sh ACME-2026Q4
# then populate ACME-2026Q4/scope/in-scope.txt and out-of-scope.txt from the RoE
```

Start at **[00-rules-of-engagement.md](playbook/00-rules-of-engagement.md)**. Do not scan first.

# 35 — Tracking Database / Spreadsheet Schema

Two linked tables run the whole engagement: an **asset/finding tracker** and an **attack-path
tracker**. Keep them as CSVs in `inventory/` and `attack-paths/` (the scaffold seeds them), or
import into a DB/spreadsheet. **Secrets are referenced, never stored inline.**

## Master tracker (`inventory/` — joined view)

| Field | Example | Notes |
|-------|---------|-------|
| asset_id | ACME-SRV-014 | stable primary key |
| cidr | 10.10.10.0/24 | |
| ip | 10.10.10.14 | |
| hostname | SRV14.acme.local | |
| os | Windows Server 2019 | |
| role | file server / DC / web | |
| port | 445 | |
| protocol | tcp | |
| service | SMB | |
| version | 10.0.17763 | |
| authentication | domain / local / anon / none | how access is gained |
| finding_id | F-014 | links to finding |
| vulnerability | share ACL exposes Finance | |
| severity | High | from §27 (with rationale) |
| exploitability | confirmed / theoretical / FP | |
| credentials | cred_id=C-003 (ref) | pointer, not the secret |
| initial_access | yes/no | was this an entry point? |
| privilege | user / admin / SYSTEM / DA | highest achieved |
| lateral_movement | reached from / reaches | hop links |
| evidence | evidence/F-014/ | path |
| status | open / validated / reported / retest | workflow state |
| owner | tester initials | who's on it |
| notes | free text | |

In practice split across the seeded files (`hosts.csv`, `services.csv`, `findings.csv`,
`credentials.csv`) joined on `asset_id`/`finding_id`/`cred_id` — normalized is easier to maintain
than one giant sheet, but the fields above are the union you need.

## Attack-path tracker (`attack-paths/paths.csv`)

| Field | Example |
|-------|---------|
| path_id | P-01 |
| initial_asset | USER-VLAN (assumed breach) |
| initial_access | LLMNR poisoning (F-101) |
| credential | NetNTLMv2 svc_app (C-003) |
| intermediate_asset | SRV14 → SRV22 |
| privilege | local admin → DA |
| next_hop | SRV22 (DA session) |
| critical_asset | DC01 / Finance DB |
| impact | full domain compromise; payroll read/modify |
| evidence | attack-paths/P-01/ + diagram |
| status | proven / partial / theoretical |

Each hop should cross-reference the finding IDs that enable it, so remediation of one finding
visibly breaks the path (choke-point analysis, §25).

## Credential tracker (`credentials/credentials.csv`) — refs only
```
cred_id,source_finding,realm,username,secret_type,secret_ref,validated_on,scope,notes
C-003,F-101,ACME,svc_app,NetNTLMv2->cracked,loot/creds/C-003.txt,2026-10-05,"SRV14,SRV22",service acct
```
`secret_ref` points into gitignored, encrypted `loot/`. **Never** put the cleartext/hash value in
the CSV or the repo.

## Status lifecycle
```
discovered → enumerated → candidate(vuln) → validated → (exploited) → reported → retested → closed
false-positive (terminal) ──┘
```

## Why two tables
The asset/finding table answers "what is wrong and where". The attack-path table answers "what can
an attacker actually *do*". Executives read the second; admins fix from the first. Keeping them
linked (by IDs) lets you show both from one dataset.

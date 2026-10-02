# 12 — DNS (53)

> **Observation:** 53/tcp or 53/udp open, or you've identified an internal resolver (often a DC).
> **Objective:** harvest internal names/topology cheaply and quietly, and flag DNS misconfigs.
> **Risk:** mostly SAFE DISCOVERY; zone transfer attempts are SAFE but logged.

## WHY DNS matters

DNS is a free map of the environment: hostnames reveal roles (DC01, SQL, VPN, JUMP), zone
transfers can dump the entire internal estate, and the resolver is often a Domain Controller.
It's high-value, low-noise reconnaissance.

| Step | Objective | Tool | Command | Look for | If found |
|------|-----------|------|---------|----------|----------|
| D1 | Identify server/version | dig/nmap | `dig version.bind txt chaos @<ip>`; `nmap -p53 -sV <ip>` | BIND/Windows DNS version | version CVEs; DC indicator |
| D2 | Basic records | dig | `dig any acme.local @<ip>` | SOA, NS, MX, A, TXT | mail/infra hosts, SPF/DKIM |
| D3 | **Zone transfer** | dig | `dig AXFR acme.local @<ip>` | full zone dumps | **misconfig finding** + full host list → inventory |
| D4 | Reverse DNS sweep | dnsx | `prips 10.10.10.0/24 \| dnsx -ptr -resp-only` | hostnames per IP | naming convention → role mapping |
| D5 | Subdomain discovery (ext) | dnsx/amass/ffuf | `ffuf -u https://FUZZ.acme.com ...`; passive via amass (if authorized) | hidden hosts/apps | new scope candidates (confirm in-scope!) |
| D6 | Internal/split DNS | dig | compare internal vs public answers | internal-only names, split-horizon leaks | internal topology |
| D7 | Misconfigs | dig/nmap | dynamic update test (`nsupdate` — gated), recursion `dig google.com @<ip>` | open recursion, dynamic update allowed | recursion=amplification risk finding; dynamic update=**gated** |

## Decision flow
```
AXFR succeeds → dump zone → import hostnames to inventory → pick high-value targets (DC/SQL/VPN)
Reverse DNS reveals naming → prioritize DCxx, SQLxx, VPNxx for enumeration
Subdomain found → is it in-scope? → yes: add; no: report, do NOT test (§00)
Open recursion → external amplification exposure → finding (do NOT run an actual amp attack)
Dynamic updates allowed → spoofing risk → REQUIRES EXPLICIT RoE APPROVAL to demonstrate
```

## Safety
- Zone transfer is read-only (safe). **Do not** perform DNS cache poisoning, dynamic-record
  injection, or amplification *demonstrations* without explicit approval — those alter name
  resolution / can disrupt.

## Evidence
`discovery/dns/` — axfr output, dnsx ptr results, subdomain lists, `dig` transcripts. Add every
discovered host to `inventory/hosts.csv` (status=discovered, pending scope check).

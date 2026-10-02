# 23 — Firewalls & Network Devices

> **Targets:** firewalls, routers, switches, VPN gateways, FortiGate/PAN/Cisco-class devices,
> IPMI/BMC, printers, and their management interfaces. **Objective:** find exposed management,
> weak/default auth, dangerous CVEs, and misconfig — **without changing any device config**.
> **Risk:** enum SAFE; auth testing CONTROLLED; **never** modify configs (that's destructive).

## WHY

Network devices are high-value and often neglected: default creds, exposed admin panels,
unpatched VPN/firewall RCEs (a recurring real-world initial-access vector), and SNMP that leaks
entire configs. Compromising one can mean full traffic visibility or pivoting across segments.

| Area | Objective | Tool | Command | Look for |
|------|-----------|------|---------|----------|
| Mgmt exposure | find admin interfaces | nmap/httpx | `nmap -p22,23,80,443,161,8080,8443,4443 <dev>` | SSH/Telnet/HTTP(S) admin, vendor panels |
| Fingerprint | identify vendor/model/firmware | whatweb/httpx | `whatweb https://<dev>` | FortiOS/PAN-OS/IOS/etc. + version → CVEs |
| **SNMP** | config/cred leak | onesixtyone/snmpwalk | `onesixtyone <dev> public private`; `snmpwalk -v2c -c public <dev>` | community strings → full config, users, ARP |
| SNMP write | config exposure | — | (writable community) | **do NOT write**; report as critical exposure |
| TLS | weak crypto on mgmt | testssl.sh | `testssl.sh https://<dev>` | weak ciphers, expired/self-signed |
| Default creds | weak auth | manual | vendor default lists (single careful attempt) | admin/admin etc. — **do not brute (lockout)** |
| VPN/IKE | VPN exposure | ike-scan | `ike-scan <dev>`; `ike-scan -A <dev>` | aggressive mode (PSK crackable offline) |
| Firmware CVEs | known RCE | nuclei/nmap | `nuclei -u https://<dev> -tags fortinet,cisco,citrix` | validate version → §18 (gate; appliance RCE can brick) |
| Telnet/cleartext | weak mgmt | nc | `nc <dev> 23` | cleartext admin = finding |

## Decision flow
```
SNMP 'public' works → snmpwalk → config/creds/topology → high finding (NEVER snmpset/write)
IKE aggressive mode → capture PSK hash → crack OFFLINE → VPN access finding
default creds on mgmt panel → access (read-only) → critical finding → do NOT change config
unpatched VPN/firewall CVE (e.g. Fortinet/Citrix/PAN) → validate version → §18 gate
  → appliance exploits can brick devices → REQUIRES EXPLICIT RoE APPROVAL + off-hours
IPMI/BMC (623) → nmap ipmi-version; IPMI 2.0 RAKP hash retrieval → crack offline → BMC = host control
```

## Hard safety rules
- **Never modify device configuration** (ACLs, routes, NAT, rules, firmware). Read-only only.
  Config change = destructive/disruptive = out of bounds.
- **No `snmpset`** (writes). Report writable community as a finding instead.
- **No credential brute force** on network gear (lockouts/mgmt disruption) — single
  default-cred checks only, and spraying is RoE-gated.
- Appliance RCE PoCs are notoriously unstable → gate through §18, prefer version-based reporting.

## What to assess (checklist)
Management exposure, authentication strength, TLS, firmware/patch level, default credentials,
ACL/ruleset exposure (via SNMP/config read), NAT/VPN config, logging enabled, admin interface
reachability from user segments (ties to §22).

## Evidence
`enumeration/<dev_id>-*.txt` — snmpwalk excerpt (redact secrets), version banner, screenshot of
exposed panel/login (no config changes), ike-scan output. Any leaked config → `loot/` (redacted
copy for evidence).

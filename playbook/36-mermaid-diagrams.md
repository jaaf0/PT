# 36 — Mermaid Diagrams

Decision-oriented diagrams per methodology area. The single master tree is in §29; these are the
per-domain drill-downs. Each uses IF/ELSE decision diamonds.

## 36.1 Master methodology (condensed)
```mermaid
flowchart LR
  A[CIDR list] --> B[Scope/RoE §00] --> C[Inventory §01] --> D[Host disc §03]
  D --> E[Port disc §04] --> F[Service ID §05] --> G[Enumeration §06-16]
  G --> H[Vuln disc §17] --> I{Validated?}
  I -- no --> Hx[FP log] 
  I -- yes --> J{Exploit ok? §18}
  J -- no --> R
  J -- yes --> K[Exploit §18] --> L[Privesc §19] --> M[Creds §20]
  M --> N[Lateral §21] --> O[Attack paths §25] --> P[Impact]
  P --> Q[Evidence §26] --> R[Severity §27] --> S([Report §28])
```

## 36.2 External pentest
```mermaid
flowchart TD
  A[External IPs/domains] --> B[Passive recon + subdomain disc §12]
  B --> C[Port/service disc §04/05]
  C --> D{Service type?}
  D -- Web --> E[Web/API testing §10/§11]
  D -- VPN --> F[IKE/VPN §23]
  D -- Mail --> G[SMTP enum/relay §05]
  D -- RDP/SSH exposed --> H[Exposure finding + authorized cred §13/§14]
  E --> I{Foothold? SSRF/RCE/creds}
  I -- yes --> J[Internal pivot §21] --> K[Internal methodology 36.3]
  I -- no --> L[Report external findings §28]
```

## 36.3 Internal pentest
```mermaid
flowchart TD
  A[Internal position / assumed breach] --> B[Host+port disc §03/04]
  B --> C{Windows/AD present?}
  C -- yes --> D[AD methodology 36.4]
  C -- no --> E[Per-service enum §05-16]
  D --> F[Creds §20]
  E --> F
  F --> G{Lateral hop? 4 gates §21}
  G -- yes --> H[Move] --> D
  G -- no --> I[Attack paths §25] --> J[Report §28]
```

## 36.4 Active Directory
```mermaid
flowchart TD
  A[Domain detected §07] --> B{Access level?}
  B -- none --> C[RID/AS-REP/kerbrute]
  B -- domain user --> D[BloodHound + Kerberoast + ADCS + LAPS/GPP]
  B -- local admin --> E[SAM/LSA/LSASS dump; reuse-sweep]
  B -- priv domain --> F[DCSync]
  C --> G{Got cred?}
  G -- yes --> D
  G -- no --> C2[Spray? REQUIRES RoE APPROVAL]
  D --> H{Path to DA? ACL/delegation/ADCS/roast}
  H -- yes --> I[Abuse edge §18] --> F
  H -- no --> E
  E --> J{Priv creds found?}
  J -- yes --> F
  J -- no --> K[Lateral §21] --> D
  F --> L[Prove impact: NTDS/crown jewel] --> M[STOP escalating; evidence]
```

## 36.5 Windows host
```mermaid
flowchart TD
  A[Access to Windows host] --> B{Privilege?}
  B -- none/remote --> C[SMB/RDP/WinRM enum §06/14/15]
  B -- low --> D[winPEAS/Seatbelt; whoami /all]
  D --> E{Vector?}
  E -- SeImpersonate --> F[PrintSpoofer -> SYSTEM]
  E -- weak service/task --> G[hijack -> SYSTEM *restart risk]
  E -- AlwaysInstallElevated --> H[MSI -> SYSTEM]
  E -- stored creds --> I[§20]
  E -- none --> J[pivot on creds §21]
  F --> K[Admin/SYSTEM]
  G --> K
  H --> K
  K --> L[Dump creds/LSASS §20] --> M{Priv/domain creds?}
  M -- yes --> N[AD 36.4]
  M -- no --> J
```

## 36.6 Linux host
```mermaid
flowchart TD
  A[Access to Linux host] --> B{Privilege?}
  B -- none/remote --> C[SSH/NFS/web/DB §13/05/10/16]
  B -- user --> D[linPEAS; sudo -l; SUID; getcap; cron]
  D --> E{Vector?}
  E -- sudo/SUID/cap GTFOBins --> F[root safe]
  E -- writable cron/service --> G[inject -> root]
  E -- docker/lxd group --> H[escape -> host root]
  E -- NFS no_root_squash --> I[write SUID -> root]
  E -- kernel LPE --> J[gate §18 - panic risk]
  E -- creds/keys --> K[§20 -> lateral §21]
  E -- none --> K
  F --> L[root]
  G --> L
  H --> L
  I --> L
  L --> M[harvest shadow/keys/configs §20] --> K
```

## 36.7 Web application
```mermaid
flowchart TD
  A[HTTP/HTTPS] --> B[Fingerprint/TLS/headers/methods]
  B --> C[Content+vhost disc ffuf]
  C --> D[Burp crawl/map]
  D --> E{Auth present?}
  E -- yes --> F[Authz/IDOR/BOLA + session + JWT/OAuth]
  E -- no --> G[Input: SQLi/XSS/SSRF/XXE/cmdi/traversal/upload]
  F --> G
  G --> H[API §11 + business logic]
  H --> I{Vuln confirmed?}
  I -- yes, read-only --> J[finding + evidence]
  I -- yes, RCE/data --> K[§18 controlled PoC -> §25 impact]
  I -- no --> L[note; scanners miss logic - keep manual]
```

## 36.8 API
```mermaid
flowchart TD
  A[API endpoints] --> B[Find spec: swagger/openapi/introspection]
  B --> C[Import to Burp]
  C --> D{Authz test}
  D -- BOLA --> E[swap IDs across 2 accounts]
  D -- BFLA --> F[call admin fn as user]
  D -- mass assign --> G[inject role/isAdmin]
  E --> H{Sensitive data?}
  F --> H
  G --> H
  H -- yes --> I[finding §25]
  H -- no --> J[input/JWT/rate/logic tests]
  J --> I
```

## 36.9 Credential attack path
```mermaid
flowchart TD
  A[Credential source] --> B{Type}
  B -- hash --> C[crack OFFLINE hashcat]
  B -- cleartext --> D[validate nxc]
  B -- ticket --> E[PtT]
  C --> D
  D --> F{Works where? reuse-sweep}
  F -- many hosts --> G[no LAPS/shared admin - systemic finding + §21]
  F -- priv user --> H[AD 36.4]
  F -- one host --> I[§08/09 enum -> more creds]
  subgraph GATED
   J[spray] -.RoE.-> D
   K[Responder/relay] -.RoE.-> A
  end
```

## 36.10 Lateral movement
```mermaid
flowchart TD
  A[Owned host + creds] --> B[internal disc from vantage]
  B --> C[reuse-sweep: where do creds work?]
  C --> D{Next host: 4 gates - scope/auth/safe/necessary?}
  D -- fail any --> E[report reachability only]
  D -- all pass --> F{Method}
  F -- WinRM --> G[evil-winrm]
  F -- WMI --> H[wmiexec]
  F -- SMB --> I[psexec - loud]
  F -- SSH --> J[key/cred]
  G --> K[new access -> privesc §19 -> creds §20]
  H --> K
  I --> K
  J --> K
  K --> L{Critical asset reached?}
  L -- no --> B
  L -- yes --> M[STOP; prove impact §25; evidence]
```

## 36.11 Network segmentation
```mermaid
flowchart TD
  A[For each source segment] --> B[probe each dest segment:ports]
  B --> C{observed vs expected}
  C -- open where deny --> D[SEGMENTATION FAILURE finding]
  C -- filtered where deny --> E[PASS - control works]
  C -- open where allow --> F[PASS - intended]
  D --> G{dest sensitive? MGMT/OT/DC/PCI}
  G -- yes --> H[high/critical + feed attack path §25]
  G -- no --> I[medium finding]
```

## 36.12 Vulnerability validation
```mermaid
flowchart TD
  A[Scanner finding] --> B[verify version+config]
  B --> C{reachable + really vulnerable?}
  C -- no --> D[false positive -> fp-log]
  C -- unsure/version-only --> E[attempt safe proof]
  C -- yes --> F[manual validation]
  E --> F
  F --> G{exploitable path to impact?}
  G -- no --> H[lower severity §27; still note]
  G -- yes --> I{exploit adds evidence? §18}
  I -- no --> J[report as validated]
  I -- yes --> K[controlled PoC -> §25]
```

## 36.13 Evidence & reporting
```mermaid
flowchart TD
  A[Each validated finding] --> B[capture: cmd/output/timestamp/screenshot/req-resp §26]
  B --> C[write reproduction steps]
  C --> D[rate severity + rationale §27]
  D --> E[consolidate duplicates]
  E --> F[link to attack path §25]
  F --> G[draft per-finding writeup §28]
  G --> H[QA/peer review]
  H --> I[client draft -> final]
  I --> J[cleanup verified + retention agreed]
  J --> K([Deliver + readout + retest plan])
```

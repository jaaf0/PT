# 29 — Master Decision Tree

One tree from CIDR list to reporting, with every major service branch converging on the common
validation→exploitation→impact→evidence→reporting spine. Read it top-down; each service node links
to its chapter.

```mermaid
flowchart TD
  START([CIDR LIST]) --> SCOPE{Scope &amp; RoE confirmed?}
  SCOPE -- no --> STOP0[STOP: confirm RoE §00]
  SCOPE -- yes --> NORM[Normalize CIDRs, build inventory §01]
  NORM --> HD[Host Discovery §03<br/>ARP / ICMP / TCP / UDP]
  HD --> LIVE{Live hosts?}
  LIVE -- none --> FILT[Firewall-aware retry / note filtered]
  LIVE -- yes --> PD[Port Discovery §04<br/>quick → version → full → UDP]
  PD --> SID[Service Identification §05]

  SID --> WEB[HTTP/HTTPS §10/§11]
  SID --> SMB[SMB 445 §06]
  SID --> ADsvc[Kerberos/LDAP 88/389 §07]
  SID --> SSH[SSH 22 §13]
  SID --> DNS[DNS 53 §12]
  SID --> SMTP[SMTP 25 §05]
  SID --> RDP[RDP 3389 §14]
  SID --> WINRM[WinRM 5985 §15]
  SID --> DB[Databases §16]
  SID --> VPN[VPN/IKE 500 §23]
  SID --> FW[Firewall/Net Device §23]

  %% SMB branch
  SMB --> SMBa{Anon/null access?}
  SMBa -- yes --> SMBshare[Enumerate shares/users<br/>hunt secrets]
  SMBa -- no --> SMBcred{Have creds?}
  SMBshare --> SMBdom
  SMBcred -- yes --> SMBauth[Authenticated enum] --> SMBdom
  SMBcred -- no --> VScan
  SMBdom{Domain member?} -- yes --> ADsvc
  SMBdom -- no --> VScan

  %% AD branch
  ADsvc --> ADlvl{Access level?}
  ADlvl -- none --> ADnone[RID/AS-REP/kerbrute §07-A]
  ADlvl -- domain user --> ADuser[BloodHound+Kerberoast+ADCS §07-B]
  ADlvl -- local admin --> ADla[Dump creds/LSASS §07-C/§08]
  ADlvl -- priv domain --> ADda[DCSync §07-D/E]
  ADnone --> CREDS
  ADuser --> CREDS
  ADla --> CREDS
  ADda --> IMPACT

  %% Web branch
  WEB --> WEBfp[Fingerprint/TLS/headers/content §10]
  WEBfp --> WEBtest[Authz/IDOR/SQLi/SSRF/logic + API §11]
  WEBtest --> VALID

  %% Other services
  SSH --> SSHx[audit + authorized creds §13] --> CREDS
  DNS --> DNSx[AXFR/rev-DNS/subdomains §12] --> NORM
  SMTP --> SMTPx[user enum/relay §05] --> VScan
  RDP --> RDPx[ntlm-info/NLA; authorized login §14] --> ADsvc
  WINRM --> WINRMx[authorized shell post-cred §15] --> WINDOWS
  DB --> DBx[version/auth/privs/data §16] --> VALID
  VPN --> VPNx[ike-scan; offline PSK §23] --> CREDS
  FW --> FWx[SNMP/default creds/CVE §23] --> VALID

  VScan[Vulnerability Scanning §17] --> VALID

  %% Common spine
  VALID[Manual Validation §17] --> REAL{Real &amp; exploitable?}
  REAL -- no --> LOGFP[Log false positive]
  REAL -- yes --> EXPDEC{Exploitation authorized<br/>&amp; safe? §18}
  EXPDEC -- no/destructive --> REPORTonly[Report as exploitable, no PoC]
  EXPDEC -- yes --> EXP[Controlled Exploitation §18]
  EXP --> PRIV[Privilege Escalation §19]
  PRIV --> CREDS[Credential Analysis §20]
  CREDS --> LAT{In-scope, authorized,<br/>safe, necessary hop? §21}
  LAT -- yes --> LATmove[Lateral Movement §21] --> ADlvl
  LAT -- no --> IMPACT
  CREDS --> IMPACT[Impact Validation / Attack Paths §25]
  WINDOWS[Windows Enum §08] --> PRIV

  IMPACT --> EVID[Evidence Collection §26]
  REPORTonly --> EVID
  LOGFP --> EVID
  EVID --> SEV[Severity §27]
  SEV --> REPORT([Reporting §28])

  %% Global stops
  STOPg{{Any instability / lockout / out-of-scope / window closed?}}
  STOPg -. at any node .-> STOPaction[STOP, log, notify POC §00]
```

**How to use it:** you're always somewhere on this tree. Identify your current node, read its
decision diamond, follow the branch, land in the linked chapter. Every branch eventually reaches
the **common spine**: Validation → Exploitation decision → Privesc → Credentials → Lateral/Impact →
Evidence → Severity → Reporting. The global STOP applies at every node.

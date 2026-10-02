# 32 — "What Do I Do Next?" Matrix

Observation → Tool → Action → Interpretation → Decision → Next tool → Evidence.
This is the lookup table for "I just saw X, now what?".

| Observation | Tool | Action | Interpretation | Decision / Next | Evidence |
|-------------|------|--------|----------------|-----------------|----------|
| **445 open** | nxc smb | OS/domain/signing + null session | Windows host; maybe domain | domain→§07; null→enum shares; signing off→relay candidate | smb enum txt |
| **389/88 open** | ldapsearch/nmap | naming context, is-DC | Domain Controller | →§07 AD; sync clock; RID/AS-REP | ldap base txt |
| **Kerberos (88) detected** | kerbrute/impacket | userenum, AS-REP roast | DC present, users enumerable | AS-REP hashes→crack offline; build user list | asrep hashes (loot) |
| **3389 (RDP) open** | nmap rdp-ntlm-info | pull domain/host; check NLA | exposure + AD info leak | external→high finding; **NO brute**; authorized cred only | ntlm-info txt |
| **5985 (WinRM) open** | nxc winrm | note; test when creds exist | remote mgmt channel | after §20 cred→evil-winrm shell | winrm txt |
| **80/443 (HTTP) open** | httpx/whatweb | fingerprint, TLS, headers | web app surface | →§10: content disc→Burp→manual | httpx/whatweb |
| **Admin panel found** | Burp/manual | identify product/version | privileged entry point | default creds (single)→access; CVE→§17/§18; **no brute** | screenshot |
| **Default credentials found** | manual | single authorized login | weak auth | access read-only→finding; expand via §20 reuse | login screenshot |
| **A password discovered** | nxc | validate; reuse-sweep | valid cred | works where?→§21; priv?→§07; **no spray w/o approval** | nxc sweep |
| **Low-priv shell obtained** | winpeas/linpeas | enumerate privesc | foothold | §19 escalate; harvest creds §20 | peas output |
| **Local admin obtained** | secretsdump/nxc | dump SAM/LSA/LSASS; reuse-sweep | host owned | cached DA?→§07; hash reuse→§21 | dump refs (loot) |
| **Domain user obtained** | BloodHound | collect graph; Kerberoast; ADCS | foothold in domain | shortest path to DA; roast→crack | bloodhound zip |
| **Domain Controller discovered** | nxc/nmap | confirm role; enum | crown of AD | don't exploit beyond proving path; §07 D/E; DCSync if rights | dc enum |
| **Another CIDR reachable** | check scope → nmap | verify in-scope first | new segment | in-scope→§03/§04; unexpected→§22 finding too | reachability log |
| **Nessus reports Critical** | manual/nmap | verify version+reachability | hypothesis | real+reachable→validate→§18; stale→downgrade §27 | validation note |
| **Nuclei reports a vuln** | Burp/manual | reproduce manually | templated hit | confirm→finding; FP→fp-log | req/resp |
| **SMB signing disabled (many)** | — | note systemic | relay exposure | §20 relay (gated); systemic finding | signing list |
| **Readable share w/ secrets** | smbclient | read, loot | creds/data exposure | §20 validate creds; data→§25 impact | files (loot) |
| **SNMP 'public' works** | snmpwalk | dump config | device exposure | config/creds→finding; **no snmpset** | snmp excerpt |
| **SSRF confirmed** | Burp | point at metadata/internal | server-side reach | cloud metadata→critical; internal→§21 | req/resp |
| **IDOR/BOLA confirmed** | Burp | prove with 2-3 objects | broken authz | data sensitivity→severity; **no mass scrape** | req/resp pairs |
| **SQLi confirmed** | sqlmap (low risk) | time-based proof | DB access path | sysadmin→RCE §18; data→sample only | sqlmap log |
| **Kerberoastable SPN** | GetUserSPNs | request TGS | service acct exposure | crack offline→reuse | hash (loot) |
| **LSASS has DA creds** | pypykatz | parse minidump | privilege jump | →§07 D; prove impact | parse output |
| **The SOC detects activity** | — | follow §00 procedure | you were caught (good data) | announced: log §24; blind: pause/assess; if contacted→respond per RoE | detection-log |
| **Exploitation causes instability** | — | STOP immediately | you may have caused impact | cease, preserve state, notify POC (§00 emergency) | incident note |
| **Account appears locked** | — | STOP auth testing | you may have locked a user | halt spraying, notify POC, review pacing | spray log |
| **Out-of-scope host reachable** | — | do NOT touch | scope boundary | report; request extension (§00) | note |
| **Writable NFS (no_root_squash)** | mount | note | server privesc path | §18 write SUID (controlled) | exports txt |
| **Redis unauth** | redis-cli | info/keys | common critical misconfig | data→finding; write-RCE→§18 | info output |
| **VPN aggressive mode** | ike-scan -A | capture PSK | offline-crackable | hashcat→access | psk hash (loot) |
| **Clean scan (nothing found)** | Burp/manual | don't trust it | scanners miss logic | manual test auth/logic/chains §10 | — |

# 30 — Tool Chains (per service)

Each chain = the default sequence of tools for a service, from discovery to finding. Follow the
chain; branch out only when a step tells you to. `→` means "feeds into".

## HTTP/HTTPS
```
nmap/httpx (discover) → whatweb (fingerprint) → testssl.sh (TLS) → ffuf (content/vhost)
→ Burp Suite (crawl/map/manual) → nuclei (known CVEs) → manual validation → evidence → finding
```

## SMB
```
nmap smb-scripts → nxc smb (OS/domain/signing) → nxc --shares/--rid-brute (null/guest)
→ smbclient/smbmap (read shares) → nxc -M spider_plus (hunt secrets)
→ [domain?] AD chain → BloodHound (if authorized) → manual validation → evidence → finding
```

## Active Directory
```
nmap (is-DC) → ldapsearch (naming context) → nxc (enum) → bloodhound-python/SharpHound (graph)
→ impacket GetNPUsers/GetUserSPNs (roast) → certipy (ADCS) → hashcat (crack offline)
→ nxc reuse-sweep → secretsdump (DCSync, gated) → manual validation → evidence → finding
```

## LDAP
```
ldapsearch (base/namingContexts) → [anon bind?] ldapdomaindump → nxc ldap (-M laps/user-desc)
→ feed BloodHound → evidence → finding
```

## Kerberos
```
nmap krb5-enum-users → kerbrute userenum → impacket-GetNPUsers (AS-REP)
→ impacket-GetUserSPNs (Kerberoast) → hashcat (offline) → Rubeus (on-host ticket ops)
→ evidence → finding
```

## DNS
```
dig version/any → dig AXFR (zone transfer) → dnsx (reverse/subdomain) → amass (passive, authorized)
→ import hosts to inventory → evidence → finding
```

## SSH
```
nmap -sV → ssh-audit (crypto/auth) → [harvested key/cred] ssh/nxc ssh (authorized login)
→ sshd_config review → evidence → finding
```

## RDP
```
nmap rdp-ntlm-info (domain leak) → nmap rdp-enum-encryption/rdp-sec-check (NLA/TLS)
→ [authorized cred] nxc rdp / xfreerdp → evidence → finding   (NO brute — lockout)
```

## WinRM
```
nxc winrm (reachable) → [cred/hash] nxc winrm (Pwn3d?) → evil-winrm (shell)
→ §08 Windows enum → evidence → finding
```

## FTP
```
nmap ftp-anon/ftp-syst → ftp client (anon browse) → download sensitive files → [writable+webroot?] §18
→ evidence → finding
```

## SMTP
```
nmap smtp-commands/open-relay/enum-users → manual VRFY/EXPN → user list (feeds spray, gated)
→ open-relay check → evidence → finding
```

## MSSQL
```
nmap ms-sql-info → nxc mssql (auth) → impacket-mssqlclient (query) → privilege check
→ [sysadmin] xp_cmdshell PoC §18 → evidence → finding
```

## MySQL
```
nmap mysql-info → mysql client (anon/empty root) → nxc mysql → SHOW GRANTS (FILE priv)
→ [FILE] INTO OUTFILE webroot §18 → evidence → finding
```

## PostgreSQL
```
nmap pgsql → psql (trust auth) → \du superuser check → [superuser] COPY TO PROGRAM §18
→ evidence → finding
```

## Oracle
```
nmap/odat sidguesser → odat (default accounts) → sqlplus → session_privs → [DBA] UTL_*/Java §18
→ evidence → finding
```

## NFS
```
rpcinfo -p → showmount -e → mount read-only → [no_root_squash] write SUID §18
→ evidence → finding
```

## Redis
```
redis-cli info (unauth?) → keys/get (data) → [write] CONFIG SET dir → authorized_keys/cron §18
→ evidence → finding
```

## VPN / IKE
```
ike-scan → ike-scan -A (aggressive mode) → capture PSK hash → psk-crack/hashcat (offline)
→ [access] authorized VPN login → evidence → finding
```

## Firewalls / Network devices
```
nmap/httpx (mgmt) → whatweb (vendor/firmware) → onesixtyone/snmpwalk (SNMP) → testssl.sh
→ default-cred check (single) → nuclei (appliance CVEs) → §18 (gated) → evidence → finding
```

## Linux host
```
(access) → linpeas → manual (sudo -l/SUID/getcap/cron) → GTFOBins → root
→ harvest creds/keys (§20) → §21 lateral → evidence → finding
```

## Windows host
```
(access) → winpeas/Seatbelt → whoami /all → PrintSpoofer/service/MSI → SYSTEM
→ secretsdump/LSASS (§20) → nxc reuse-sweep → §21 lateral → evidence → finding
```

## APIs
```
katana/gau + Burp (endpoints) → swagger/introspection (spec) → Burp (BOLA/BFLA/mass-assign)
→ jwt_tool (tokens) → manual logic → evidence → finding
```

## Cloud-facing services
```
httpx/whatweb (identify) → check for SSRF→metadata (§10) → exposed buckets/keys (trufflehog)
→ [valid key, minimal check] cloud CLI enum → evidence → finding
(cloud resources often need PROVIDER authorization — confirm scope §00)
```

# 05 — Service Enumeration (Master Port Matrix)

> **Objective:** for every open port, know exactly what to run, what to look for, and
> which deep-dive chapter to jump to. **An open port is a question, not a finding.**
> **Risk:** mostly SAFE DISCOVERY; auth checks are CONTROLLED VALIDATION.

## How to use this matrix

For each open port on each host: run the **primary enum**, read the **look-for**, make the
**decision**, jump to the linked deep-dive. Save output to `enumeration/<asset_id>-<port>.txt`.

| Port | Service | Primary enum tool | Command (quick) | Look for | Deep-dive |
|------|---------|-------------------|-----------------|----------|-----------|
| 21 | FTP | nmap scripts | `nmap -p21 -sV --script ftp-anon,ftp-syst <ip>` | anonymous login, writable dir, version CVEs | below |
| 22 | SSH | nmap + ssh-audit | `ssh-audit <ip>` | version, weak KEX/ciphers, auth methods | [13](13-ssh.md) |
| 23 | Telnet | nmap/banner | `nc <ip> 23` | cleartext mgmt, device banner, default creds | §network devices [23](23-network-devices.md) |
| 25 | SMTP | nmap scripts | `nmap -p25 --script smtp-commands,smtp-open-relay,smtp-enum-users <ip>` | open relay, VRFY/EXPN user enum, TLS | below |
| 53 | DNS | dig/dnsx | `dig any acme.local @<ip>`; `dig AXFR …` | zone transfer, version, internal records | [12](12-dns.md) |
| 80 | HTTP | httpx/whatweb | `whatweb http://<ip>`; `httpx -title -tech-detect` | tech stack, admin panels, default pages | [10](10-web-app.md) |
| 88 | Kerberos | nmap/krb tools | `nmap -p88 --script krb5-enum-users …` | **this host is a DC** | [07](07-active-directory.md) |
| 110/995 | POP3 | banner/nmap | `nmap -p110 --script pop3-capabilities <ip>` | cleartext auth, version | below |
| 111 | RPC/portmapper | rpcinfo | `rpcinfo -p <ip>` | NFS/mountd exposure | NFS below / [16] |
| 135 | MSRPC | nmap/impacket | `nmap -p135 --script msrpc-enum <ip>` | Windows host; endpoint mapper | [07](07-active-directory.md)/[08](08-windows-enum.md) |
| 137-139 | NetBIOS | nbtscan | `nbtscan <ip>`; `nmap --script nbstat` | hostname, domain, workgroup | [06](06-smb.md) |
| 143/993 | IMAP | nmap | `nmap -p143 --script imap-capabilities <ip>` | cleartext, version | below |
| 161 | SNMP | snmpwalk/onesixtyone | `onesixtyone <ip> public` | **community strings → device config, users** | §network devices [23](23-network-devices.md) |
| 389/636 | LDAP(S) | ldapsearch/nmap | `ldapsearch -x -H ldap://<ip> -s base` | naming context → domain; anon bind | [07](07-active-directory.md) |
| 443 | HTTPS | httpx/sslscan | `sslscan <ip>`; `whatweb https://<ip>` | TLS issues, tech, vhosts | [10](10-web-app.md) |
| 445 | SMB | nxc/enum4linux-ng | `nxc smb <ip>` | signing, null session, shares, OS, domain | [06](06-smb.md) |
| 464 | kpasswd | — | (presence) | confirms DC | [07](07-active-directory.md) |
| 500/4500 | IKE/VPN | ike-scan | `ike-scan <ip>` | VPN gateway, aggressive mode | [23](23-network-devices.md) |
| 623 | IPMI | nmap/msf | `nmap -p623 --script ipmi-version -sU <ip>` | BMC — often default creds, hash dump | [23](23-network-devices.md) |
| 1433 | MSSQL | nxc/nmap | `nmap -p1433 --script ms-sql-info <ip>` | version, instance, auth mode | [16](16-databases.md) |
| 1521 | Oracle | odat/nmap | `nmap -p1521 --script oracle-sid-brute <ip>` | SID, TNS, version | [16](16-databases.md) |
| 2049 | NFS | showmount | `showmount -e <ip>` | exported shares, no_root_squash | below / [16] |
| 3268/3269 | GC LDAP | ldapsearch | query global catalog | **DC / forest-wide LDAP** | [07](07-active-directory.md) |
| 3306 | MySQL | nmap/nxc | `nmap -p3306 --script mysql-info <ip>` | version, anon, auth | [16](16-databases.md) |
| 3389 | RDP | nmap/rdp-sec-check | `nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption <ip>` | NLA, TLS, hostname/domain leak | [14](14-rdp.md) |
| 5432 | PostgreSQL | nmap/nxc | `nmap -p5432 --script pgsql-brute <ip>`(careful) | version, trust auth | [16](16-databases.md) |
| 5900 | VNC | nmap | `nmap -p5900 --script vnc-info,realvnc-auth-bypass <ip>` | no-auth, weak auth | below |
| 5985/5986 | WinRM | nxc | `nxc winrm <ip>` | remote mgmt — key post-cred | [15](15-winrm.md) |
| 6379 | Redis | redis-cli | `redis-cli -h <ip> info` | **unauth access** very common | [16](16-databases.md) |
| 8080/8443 | HTTP(S)-alt | httpx | `httpx -u http://<ip>:8080` | apps, proxies, mgmt consoles, Jenkins/Tomcat | [10](10-web-app.md) |

## The per-service loop (applies to EVERY port)

```
1. Banner / version   (nmap -sV, or native client)   → WHAT is it, WHICH version
2. Config review      (scripts, flags)                → HOW is it set up
3. Auth review        (anon? default? provided creds) → WHO can get in
4. Misconfig checks   (service-specific)              → what's wrong
5. Vuln hypotheses    (version → known CVEs)          → what MIGHT be exploitable
6. Manual validation  (confirm before claiming)       → is it REAL
7. Evidence           (save output + screenshot)      → prove it
8. Branch             (deep-dive chapter)             → go deeper
```

## FTP (21) — worked example of the loop

| Step | Command | If found → |
|------|---------|-----------|
| Version | `nmap -p21 -sV <ip>` | note product/version → check CVEs (e.g. vsftpd 2.3.4 backdoor, ProFTPD) |
| Anon | `nmap --script ftp-anon <ip>` or `ftp <ip>` (user `anonymous`) | **anon allowed** → list, download (read-only). Writable? → possible web-root upload |
| Browse | `ftp> ls -la; get <file>` | config files, backups, creds → `loot/` |
| Decision | anon+sensitive files → **finding**; anon+writable+web-reachable → potential RCE path → §18 | |

**IF anon login works → SAFE DISCOVERY** (listing/download). **IF you upload to test write
→ CONTROLLED** (log the file, remove it in cleanup). **IF you chain upload→web RCE →** that's
exploitation → gate through §18.

## SMTP (25) user enumeration

`VRFY`/`EXPN`/`RCPT` can confirm valid users (feeds spraying lists — **spraying itself is
RoE-gated**). Open relay test (`smtp-open-relay`) is SAFE to check but **do not actually
relay bulk mail**. Finding: open relay = reportable misconfig.

## NFS (2049) / portmapper (111)

```
showmount -e <ip>            # list exports
mkdir -p /mnt/nfs && mount -t nfs <ip>:/export /mnt/nfs -o nolock   # mount read
```
Look for: world-readable exports, `no_root_squash` (lets you write files as root → privesc
vector on the server), home dirs with SSH keys. **Mounting is CONTROLLED; writing is §18.**

## Decision output
Every open port → a row in `services.csv` with version + an enum note, and a jump to its
deep-dive. Prioritize: AD/DC indicators (88/389/445/135) and web (80/443/8080) usually yield
the fastest paths.

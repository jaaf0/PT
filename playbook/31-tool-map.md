# 31 — Master Tool Map

Phase → input → primary tool (default) → alternative → purpose → output → decision → next tool.
**Use the PRIMARY unless you have a reason not to.** Not every tool belongs in every engagement.

| Phase | Input | Primary Tool | Alternative | Purpose | Output | Decision | Next Tool |
|-------|-------|--------------|-------------|---------|--------|----------|-----------|
| Normalize | CIDRs | python `ipaddress` | ipcalc/prips | dedupe/split/expand | clean target list | overlaps? split? | fping |
| Host disc (L2) | subnet | arp-scan | nmap -PR | find on-link hosts | MAC+IP | live? | nmap |
| Host disc (L3) | targets | fping | nmap -sn | fast live sweep | responders | silent? | nmap -Pn |
| Host disc (multi) | silent set | nmap -sn (multi-probe) | masscan --ping | beat ICMP filter | up/down | still silent? | nmap -Pn TCP |
| Port disc (wide) | live hosts | masscan | rustscan / nmap -F | fast all-port sweep | ip:port | open ports? | nmap -sV |
| Port disc (version) | open ports | nmap -sV -sC | — | identify service | service+version | which service? | service chapter |
| Port disc (UDP) | live hosts | nmap -sU top | — | find UDP services | open/of | DNS/SNMP/IKE? | service tool |
| SMB enum | 445 | netexec (nxc) | enum4linux-ng | OS/domain/shares/signing | enum data | domain? anon? | smbclient/AD |
| Share read | share+cred | smbclient | smbmap | read files | file listing | secrets? | loot/§20 |
| AD graph | domain cred | BloodHound + SharpHound/bloodhound-python | ldapdomaindump | attack-path graph | graph/zip | path to DA? | impacket/certipy |
| Kerberos roast | domain cred | impacket GetUserSPNs/GetNPUsers | Rubeus | get crackable hashes | TGS/AS-REP | crackable? | hashcat |
| ADCS | domain cred | certipy | — | find/abuse cert templates | ESC findings | ESC1-8? | certipy req |
| Hash crack | hashes | hashcat | john | offline crack | plaintext | cracked? | nxc reuse |
| Cred validate/reuse | creds | netexec | crackmapexec/kerbrute | where creds work | Pwn3d list | admin? | §08/§21 |
| DCSync | repl rights | impacket-secretsdump | mimikatz | dump NTDS | hashes | domain owned | IMPACT |
| LDAP | 389 | ldapsearch | ldapdomaindump | query directory | LDAP data | anon bind? | BloodHound |
| Win local enum | shell | winPEAS | Seatbelt | find privesc | vector list | SeImperson? | PrintSpoofer |
| Win cred dump | admin | netexec/secretsdump | pypykatz/mimikatz | extract creds | hashes/tickets | priv user? | §07/§21 |
| Linux enum | shell | linPEAS | manual GTFOBins | find privesc | vector list | sudo/SUID? | GTFOBins |
| Web discover | web IPs | httpx | nmap http | live web+tech | url list | which app? | whatweb |
| Web fingerprint | url | whatweb | wappalyzer | identify stack | tech/versions | CVE? | nuclei/Burp |
| Web content | url | ffuf | feroxbuster | find paths/vhosts | dirs/files | admin/backup? | Burp |
| Web manual | url | Burp Suite | ZAP | manual testing | req/resp | vuln? | validate |
| Web CVE | url | nuclei | nikto | templated checks | hits | real? | §17 validate |
| API | endpoints | Burp | Postman | authz/logic | req/resp | BOLA? | §11 |
| TLS | 443 | testssl.sh | sslscan | crypto review | issues | weak? | finding |
| DNS | 53 | dig | dnsx/host | records/AXFR | zone/records | transfer? | inventory |
| Vuln scan (net) | hosts | Nessus | OpenVAS/Greenbone | broad scan | findings | validate! | §17 manual |
| SNMP | 161 | onesixtyone→snmpwalk | snmp-check | community/config | config data | public? | finding |
| VPN | 500 | ike-scan | — | IKE/PSK | aggressive? | PSK hash | hashcat |
| Lateral | cred+host | evil-winrm | impacket-wmiexec/psexec | execute remotely | shell | new access? | §19 |
| Pivot | foothold | ligolo-ng | chisel/sshuttle | tunnel to segment | SOCKS | new subnet? | §03 (re-scope) |
| Exploit (framework) | validated vuln | Metasploit (check first) | manual PoC | controlled exploit | session | impact? | §18/§25 |
| Capture (gated) | LAN position | Responder (-A then poison) | Inveigh | capture NetNTLM | hashes | **RoE!** | ntlmrelayx |
| Relay (gated) | no-signing hosts | impacket-ntlmrelayx | — | relay NTLM | access | **RoE!** | §07 |
| Packet analysis | traffic | Wireshark | tcpdump | inspect/passive disc | pcap | cleartext creds? | loot |

## Tool-selection reasoning (why the primaries)
- **netexec (nxc)** is the internal workhorse: one tool spans SMB/LDAP/WinRM/MSSQL/RDP enum + auth +
  modules. Default for "does this cred work / what's here".
- **BloodHound** because AD is a graph humans can't trace by hand; it finds the path you'd miss.
- **Burp Suite** because web/API testing is manual by nature; scanners feed it, humans judge in it.
- **nmap** stays the reference for accurate service/version + safe NSE checks; masscan/rustscan are
  for *speed* at scale, then you confirm with nmap `-sV`.
- **hashcat + offline** always beats online guessing (no lockout, no noise).
- **impacket/certipy** are the precise AD-attack instruments once BloodHound shows the edge.
- Tools marked **RoE!** (Responder poisoning, ntlmrelayx, Metasploit exploit actions) are power
  tools gated by authorization — don't reach for them reflexively.

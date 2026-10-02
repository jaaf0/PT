# 14 — RDP (3389)

> **Observation:** 3389 open. **Objective:** assess exposure, NLA/TLS posture, leaked
> host/domain info, and gain access only with authorized creds — **without locking accounts**.
> **Risk:** enum SAFE; auth testing CONTROLLED with real **lockout danger**.

## WHY

Exposed RDP is a top ransomware entry vector. Even unauthenticated, RDP leaks hostname/domain
(great for AD mapping) and its config reveals whether NLA/strong TLS are enforced.

| Step | Objective | Tool | Command | Look for |
|------|-----------|------|---------|----------|
| 1 | Host/domain leak | nmap | `nmap -p3389 --script rdp-ntlm-info <ip>` | NetBIOS/DNS name, **domain**, OS build (feeds §07) |
| 2 | Encryption/NLA | nmap/rdp-sec-check | `nmap -p3389 --script rdp-enum-encryption <ip>`; `rdp-sec-check.pl <ip>` | NLA required? TLS vs RDP security layer? |
| 3 | CVE posture | nmap | `nmap -p3389 --script rdp-vuln-ms12-020 <ip>` | legacy vuln (ms12-020 is DoS → **do not** trigger) |
| 4 | Exposure context | inventory | is it internet-facing / on a server VLAN? | external RDP = high-sev exposure finding |
| 5 | Authorized login | xfreerdp/nxc | `nxc rdp <ip> -u <u> -p <p>` (single known cred) | valid access; `(Pwn3d!)` = admin |
| 6 | PtH over RDP (if NLA + restricted admin) | xfreerdp | `xfreerdp /u:admin /pth:<hash> /v:<ip>` | hash-based access (post-§08) |

## Lockout warning (read first)
- **Do NOT spray/brute RDP.** RDP failures count toward AD lockout → you can lock real users
  and cause an incident. Password guessing over RDP = `REQUIRES EXPLICIT RoE APPROVAL` and even
  then only with the lockout policy known and threadcount=1, delays, from a validated user list.
- Testing **one known-good credential** is fine (CONTROLLED).

## Decision flow
```
rdp-ntlm-info reveals domain → add to §07 AD mapping even if you can't log in
NLA disabled + legacy OS → higher risk (BlueKeep-era); validate OS/patch, do NOT fire DoS exploits
External-facing RDP → immediate high-severity exposure finding regardless of creds
Valid cred + (Pwn3d!) → interactive access → §08 host enum / §21 lateral
```

## Evidence
`enumeration/<id>-rdp.txt`, rdp-ntlm-info output (domain leak), screenshot of the desktop on
authorized login (redact per RoE).

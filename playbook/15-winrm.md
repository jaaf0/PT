# 15 — WinRM (5985/5986)

> **Observation:** 5985 (HTTP) / 5986 (HTTPS) open. **Objective:** confirm it's reachable and,
> **once you have credentials**, use it as a clean remote shell / command channel.
> **Risk:** enum SAFE; authenticated use CONTROLLED (and comparatively EDR-visible).

## WHY

WinRM is the intended remote-management channel — so when you have valid creds it gives a
stable PowerShell session with far less friction than SMB exec, and it's "expected" admin
traffic. It's most relevant **after** you've obtained a credential (§07/§08/§20).

| Step | Objective | Tool | Command | Look for |
|------|-----------|------|---------|----------|
| 1 | Is WinRM up? | nxc/nmap | `nxc winrm <ip>`; `nmap -p5985,5986 <ip>` | service present, HTTP vs HTTPS |
| 2 | Cred check | nxc | `nxc winrm <ip> -u <u> -p <p>` | `(Pwn3d!)` = creds valid + in Remote Management Users/Admins |
| 3 | PtH check | nxc | `nxc winrm <ip> -u <u> -H <nthash>` | hash works (post-§08) |
| 4 | Interactive shell | evil-winrm | `evil-winrm -i <ip> -u <u> -p <p>` (or `-H <hash>`, `-k` for Kerberos) | PowerShell session |
| 5 | Domain context | from shell | `whoami /all`, `$env:USERDOMAIN` | pivot to §07/§08 |

## Decision flow
```
nxc winrm → (Pwn3d!) → evil-winrm shell → §08 Windows enum → privesc / cred harvest
cred works on many hosts via WinRM → §21 lateral sweep
5986 (HTTPS) only → use -S / --ssl; note stronger transport in report
no creds yet → WinRM is a note; come back after §20
```

## Safety
- WinRM logons are logged (event 4624 type 3, WinRM operational log) and often EDR-watched →
  record use as a §24 detection-validation data point.
- Prefer WinRM over noisier SMB `psexec`-style exec when you want a cleaner footprint.

## Evidence
`enumeration/<id>-winrm.txt`, screenshot of the evil-winrm `whoami` proving access & context.

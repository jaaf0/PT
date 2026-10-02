# 08 — Windows Host Enumeration

> **Objective:** from whatever access you have on a Windows host, inventory the system and
> find the next step (privesc or lateral). **Risk:** local enum is SAFE/CONTROLLED;
> credential extraction is CONTROLLED and EDR-noisy.

## The access ladder (what changes at each rung)

```
NO ACCESS → remote enum only (SMB/LDAP/RDP/WinRM from network)  — see §06/§07/§14/§15
LOW-PRIV SHELL → local recon, hunt privesc + stored creds
ADMIN (local) → dump SAM/LSA/LSASS, pivot, check cred reuse
DOMAIN context → feed AD graph (§07), DCSync if rights
```

## A. No access (remote-only)

Covered by SMB (§06), AD (§07), RDP (§14), WinRM (§15). Goal: a credential or a shell.

## B. Low-privileged shell

**Primary tool:** WinPEAS (automated), cross-checked by manual commands + Seatbelt.
**Why WinPEAS:** it enumerates the dozens of privesc vectors consistently and color-flags the
promising ones; manual commands confirm and keep you from trusting a tool blindly.

| Objective | Command (native) | Look for |
|-----------|------------------|----------|
| Who am I / privileges | `whoami /all` | `SeImpersonatePrivilege`/`SeAssignPrimaryToken` → Potato attacks; group memberships |
| OS / patch level | `systeminfo` | build + hotfixes → missing-patch privesc (compare to known KBs) |
| Users / groups | `net user`, `net localgroup administrators` | who is admin |
| Running services | `wmic service get name,pathname,startmode` / `sc qc <svc>` | **unquoted service paths**, weak binary perms |
| Service binary perms | `icacls "C:\path\svc.exe"` | writable by you → replace binary → SYSTEM |
| Scheduled tasks | `schtasks /query /fo LIST /v` | tasks running as SYSTEM with writable script/binary |
| Registry autoruns | `reg query HKLM\...\Run` | writable autorun targets |
| AlwaysInstallElevated | `reg query HKCU\...\Installer /v AlwaysInstallElevated` (+HKLM) | both =1 → MSI as SYSTEM |
| Stored creds | `cmdkey /list`; `reg query HKLM /f password /t REG_SZ /s` | saved creds, runas |
| Unattend/GPP files | `C:\Windows\Panther\Unattend.xml`, SYSVOL GPP | cleartext/cpassword |
| Network | `ipconfig /all`, `netstat -ano`, `arp -a`, `route print` | other subnets, internal services, pivots |
| Installed software | `wmic product get name,version` | vulnerable apps, agents |
| AV/EDR present | `sc query`, `tasklist` | which EDR → informs noise (§24) |

```
# Automated:
winpeas.exe quiet > C:\Windows\Temp\wp.txt        # or run in-memory to reduce footprint
# Seatbelt for structured checks:
Seatbelt.exe -group=all
```

**Decision branches (B):**
- **SeImpersonate present** (service accounts, IIS, MSSQL) → PrintSpoofer/Potato → SYSTEM.
  CONTROLLED, usually safe; validate then → Level C.
- **Unquoted service path + writable dir** → place payload → service restart → SYSTEM.
  Service restart may interrupt the service → note POTENTIALLY DISRUPTIVE if prod.
- **Writable service binary / scheduled-task script** → replace → SYSTEM. Same disruption note.
- **Stored creds / cpassword / unattend password** → §20 validate → may unlock other hosts.
- **No local privesc** → focus on stored creds + network pivots; you may move laterally
  before you elevate.

## C. Local administrator

| Objective | Tool | Command | Yields |
|-----------|------|---------|--------|
| SAM/LSA/cached | nxc / secretsdump / reg save | `reg save HKLM\SAM sam; reg save HKLM\SYSTEM sys` then secretsdump offline | local hashes, cached domain creds, LSA secrets (service acct passwords!) |
| LSASS (live) | nanodump / comsvcs minidump | dump then `pypykatz lsa minidump` offline | plaintext creds, Kerberos tickets of logged-on users |
| Cred reuse (PtH) | nxc | `nxc smb <range> -u Administrator -H <nthash> --local-auth` | every host sharing that local admin hash |
| DPAPI secrets | SharpDPAP/mimikatz | masterkeys → browser/cred-vault secrets | saved browser & app passwords |

**Decision branches (C):**
- **LSASS reveals a privileged domain user** → Level D / straight into AD graph (§07).
- **Local admin hash reused across hosts** → lateral movement sweep (§21); flag "no LAPS /
  shared local admin" finding.
- **LSA secrets contain a service account password** → often high-priv domain account → §07.

> **EDR note:** SAM dump via `reg save` is quieter than touching LSASS. LSASS access triggers
> most EDRs → do it deliberately, log it as a detection test (§24), and prefer offline parsing
> of a minidump over running mimikatz on the box.

## D. Domain context
Feed everything into §07 (AD). A domain-joined admin host is your launchpad for BloodHound,
Kerberoast, DCSync-rights checks, and lateral movement.

## Evidence
`windows/<asset_id>/` — winpeas.txt, seatbelt.json, whoami-all.txt, systeminfo.txt, screenshots
of the privesc proof (e.g. `nt authority\system` shell). Secrets → `loot/` encrypted.

## When to stop
Once you've reached SYSTEM locally **and** harvested creds/tickets, the host is "done" — pivot
to AD/lateral. Don't keep poking a box you already own; spend the window widening the graph.

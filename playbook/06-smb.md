# 06 — SMB (445/139)

> **Observation:** port 445 (and/or 139) open. **Objective:** determine OS/domain, signing
> posture, whether anonymous access is allowed, what shares exist, and what's readable —
> then branch to AD or Windows enumeration.
> **Risk:** enumeration is SAFE DISCOVERY; auth testing is CONTROLLED (watch lockout).

## WHY SMB is the internal crown jewel

SMB leaks OS version, hostname, domain membership, shares, and sometimes files — often
**without credentials**. It's the fastest way to map a Windows estate and frequently the
first foothold (readable shares with scripts/creds, or SMB-signing-off for relay).

## The flow

```
445 open
 → nmap SMB scripts          (version, signing, OS, domain)      SAFE
 → nxc smb <ip>              (one-shot: OS, domain, signing)     SAFE
 → null/guest session test   (anonymous enumeration)            SAFE
 → share enumeration         (what shares, what perms)          SAFE
 → read accessible shares     (hunt files/creds)                SAFE (read-only)
 → (with creds) authenticated enum                               CONTROLLED
 → domain detected?           → branch to AD (07)
 → signing disabled?          → relay candidate (20, RoE-gated)
 → sensitive files?           → finding + loot
```

## Step table

| Step | Objective | Primary | Alternative | Command | Look for | If found | Evidence |
|------|-----------|---------|-------------|---------|----------|----------|----------|
| S1 | Version/OS/signing | `nxc smb` | `nmap --script smb2-security-mode,smb-os-discovery` | `nxc smb <ip>` | OS build, domain/workgroup, `signing:False` | domain→§07; signing False→relay candidate | `enumeration/<id>-smb.txt` |
| S2 | SMBv1 present? | nmap | — | `nmap -p445 --script smb-protocols <ip>` | SMBv1 enabled | legacy/EternalBlue candidate (validate!) | same |
| S3 | Null session | `nxc -u '' -p ''` | `smbclient -N -L //<ip>` | `nxc smb <ip> -u '' -p '' --shares` | anonymous lists shares/users | **misconfig finding**; enumerate | screenshot |
| S4 | Guest session | `nxc -u guest -p ''` | `smbclient -U guest%` | `nxc smb <ip> -u guest -p '' --shares` | guest readable shares | enumerate shares | — |
| S5 | Share enum | `nxc --shares` | `smbmap -H <ip>` | `nxc smb <ip> -u '<user>' -p '<pass>' --shares` | READ/WRITE perms per share | READ on non-default → browse | `enumeration/<id>-shares.txt` |
| S6 | Read shares | `smbclient` | `smbmap -R` | `smbclient //<ip>/<share> -U '<user>%<pass>'` then `recurse;ls;get` | scripts, .xml, configs, backups, KeePass | creds/secrets → `loot/` + §20 | file + note |
| S7 | Spider for secrets | `nxc -M spider_plus` | `manspider` | `nxc smb <ip> -u u -p p -M spider_plus` | passwords in files, unattend.xml, web.config | finding + cred | json output |
| S8 | User/RID enum | `nxc --rid-brute` | `enum4linux-ng` | `nxc smb <ip> -u '' -p '' --rid-brute` | domain/local user list | feeds §07 user list | `enumeration/<id>-users.txt` |
| S9 | Password policy | `nxc --pass-pol` | `enum4linux-ng -P` | `nxc smb <ip> -u u -p p --pass-pol` | **lockout threshold** (critical before any spray) | record before §20 | note |

## Interpreting signing

| `signing` | Meaning | Action |
|-----------|---------|--------|
| `False` / not required | SMB relay possible | relay candidate (NTLM relay → §20, **RoE-gated**) |
| `True` / required | relay blocked for SMB | note; relay may still work to LDAP/other |

## Decision branches

- **IF domain field is a real domain (not WORKGROUP)** → this is a domain member → **go to
  [07-active-directory.md](07-active-directory.md)**. If OS = Server and 88/389 also open → **it's a DC**.
- **IF null/guest session enumerates shares or users** → misconfiguration finding; harvest
  everything readable.
- **IF a readable share contains credentials/secrets** → §20 (validate creds), and this may
  be your foothold.
- **IF signing disabled across many hosts** → systemic relay exposure finding (§20 to exploit,
  RoE-gated).
- **IF SMBv1 enabled + unpatched legacy OS** → possible MS17-010/EternalBlue. **Do NOT fire
  the exploit to "check"** — validate safely with `nmap --script smb-vuln-ms17-010` (which is
  a safe check), then gate real exploitation through §18 (EternalBlue can crash hosts →
  POTENTIALLY DISRUPTIVE / REQUIRES EXPLICIT RoE APPROVAL).

## Lockout safety (read before any authenticated SMB test)

- Get the lockout policy (S9) **first**. If threshold is low (e.g. 3–5), a single wrong
  password across many hosts for one user can lock that account.
- Testing **one known-good credential** = safe. **Guessing** passwords = spraying = **§20,
  RoE-gated**.

## Evidence
- `enumeration/<id>-smb.txt`, `-shares.txt`, `-users.txt`; spider JSON; screenshots of
  readable sensitive files (redact as required by RoE). Any secret → `loot/` (encrypted),
  pointer in `credentials/credentials.csv`.

## When to stop / escalate
- You have OS, domain, signing, shares, and have read what's accessible.
- Domain present → the engagement pivots to AD (07). That's where the paths are.

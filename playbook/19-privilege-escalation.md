# 19 — Privilege Escalation

> **Objective:** turn initial access into full control of the host (SYSTEM/root), as a stepping
> stone to credentials and lateral movement. **Risk:** most misconfig-based privesc is
> CONTROLLED/safe; kernel/service-restart methods can be **POTENTIALLY DISRUPTIVE**.

See §08 (Windows enum) and §09 (Linux enum) for the enumeration commands; this chapter is the
**decision workflow** for each vector.

## Windows privesc workflow

```
Low-priv shell
 → whoami /all  →  SeImpersonate/SeAssignPrimaryToken?  → YES → Potato/PrintSpoofer → SYSTEM (safe)
 → services     →  unquoted path w/ writable dir? / weak binary ACL? → replace → SYSTEM*
 → scheduled tasks → writable script/binary run as SYSTEM? → inject → SYSTEM*
 → registry     →  AlwaysInstallElevated (HKLM+HKCU)=1? → malicious MSI → SYSTEM
 → credentials  →  cmdkey/DPAPI/unattend/GPP/registry passwords? → §20 → maybe admin elsewhere
 → tokens       →  impersonatable token of priv user? → token theft → their context
 → local groups →  misconfigured admin membership? → use it
 → software     →  vulnerable 3rd-party service running as SYSTEM? → validate CVE → §18
 → AD privileges → domain rights on this principal? → §07
```
`*` service/scheduled-task hijack often requires a **service/host restart** to trigger →
**POTENTIALLY DISRUPTIVE** on production; prefer token/privilege-based routes or schedule it.

| Vector | Validate | Impact | Disruption |
|--------|----------|--------|-----------|
| SeImpersonate → PrintSpoofer/GodPotato | run tool → `whoami` = SYSTEM | SYSTEM | low (safe) |
| Unquoted service path | `wmic service`, `icacls` dir writable | SYSTEM on restart | medium (restart) |
| Weak service binary ACL | `icacls svc.exe` shows WRITE | SYSTEM on restart | medium |
| AlwaysInstallElevated | both reg keys =1 | SYSTEM via MSI | low |
| Stored creds (GPP/unattend/cmdkey) | decode/validate (§20) | varies | low |
| Vulnerable driver/service CVE | confirm version | SYSTEM | **high (gate §18)** |

## Linux privesc workflow

```
User shell
 → sudo -l       → NOPASSWD + GTFOBins binary? → spawn root (safe)
 → SUID/SGID     → non-standard SUID in GTFOBins? → root (safe)
 → capabilities  → cap_setuid/cap_dac_override on a binary? → root (safe)
 → cron          → root cron runs writable script / wildcard? → inject → root (wait for run)
 → services      → root service with writable config/binary? → root*
 → writable files→ /etc/passwd writable? PATH hijack? → root
 → credentials   → keys/.env/history/shadow? → §20 → lateral/root
 → containers    → docker.sock / privileged / lxd group? → host root
 → config        → misconfigured NFS no_root_squash? mounted? → write SUID → root
 → kernel        → old kernel w/ public LPE? → **gate §18 (panic risk)**
```

| Vector | Validate | Impact | Disruption |
|--------|----------|--------|-----------|
| sudo NOPASSWD + GTFOBins | `sudo -l`; run GTFOBins recipe | root | low (safe) |
| SUID GTFOBins binary | `find -perm -4000`; GTFOBins | root | low |
| Capabilities | `getcap -r /` | root | low |
| Writable root cron / wildcard | read crontab; test write | root | low–med (don't break job) |
| docker/lxd/disk group | `id`; mount/escape | host root | low–med |
| NFS no_root_squash | `/etc/exports`; mount+SUID | root on server | medium |
| Kernel LPE | exact kernel vs CVE | root | **high — panic risk (gate §18)** |

## Universal decision rule
```
multiple vectors available → pick the SAFEST that proves root (misconfig > kernel exploit)
root/SYSTEM achieved → immediately §20 (dump creds/keys/tickets) → §21 (lateral) / §07 (AD)
only kernel-exploit path on a prod/fragile host → §18 gate; prefer to report as privesc-capable
  and demonstrate on a non-prod twin or with explicit approval
```

## Evidence
Screenshot of `id`/`whoami` showing root/SYSTEM, the exact escalation command, the vulnerable
config (icacls/getcap/sudo -l output). Store in `privilege-escalation/<asset_id>/`.

## When to stop
Root/SYSTEM + creds harvested = host owned. Don't gold-plate; pivot. Record the path precisely
so the client can reproduce and remediate.

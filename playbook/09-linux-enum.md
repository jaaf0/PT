# 09 — Linux Host Enumeration

> **Objective:** from whatever Linux access you have, inventory the host and find the path to
> root or to the next host. **Risk:** local enum is SAFE/CONTROLLED.

## The access ladder

```
NO ACCESS → remote enum only (SSH/NFS/web/DB) — §13/§05/§10/§16
USER ACCESS (valid login, maybe low-value) → local recon
LOW PRIVILEGE → hunt privesc vectors + stored creds
ROOT → dump creds, pivot, read everything
```

## A. No access
Get a shell/credential via SSH (§13), a web app (§10), a database (§16), NFS no_root_squash
(§05), or reused creds (§20).

## B / C. User & low-privilege (recon + privesc hunting)

**Primary tool:** LinPEAS (automated) + manual confirmation. **Why:** LinPEAS covers the long
tail of Linux privesc; manual commands verify and avoid false confidence.

| Objective | Command | Look for |
|-----------|---------|----------|
| Identity | `id; whoami; groups` | membership in `sudo`,`docker`,`lxd`,`disk`,`adm` → fast root |
| OS/kernel | `uname -a; cat /etc/os-release` | old kernel → kernel-exploit candidate (validate carefully) |
| Sudo rights | `sudo -l` | NOPASSWD entries, exploitable binaries (GTFOBins) |
| SUID/SGID | `find / -perm -4000 -type f 2>/dev/null` | non-standard SUID → GTFOBins → root |
| Capabilities | `getcap -r / 2>/dev/null` | `cap_setuid`, `cap_dac_override` on a binary → root |
| Cron jobs | `cat /etc/crontab; ls -la /etc/cron.*` | root cron running a writable script/wildcard |
| Writable files/paths | `find / -writable -type f 2>/dev/null`; `find / -perm -2 -type d` | writable scripts in root's path, PATH hijack |
| Services/processes | `ps aux; ss -tulpn` | root processes, internal-only services, pivot ports |
| Stored creds | `grep -rniE 'password|secret|api[_-]?key' /home /etc /var/www 2>/dev/null` | configs, `.env`, `.git`, history files |
| SSH material | `ls -la ~/.ssh /home/*/.ssh; cat ~/.bash_history` | private keys, known_hosts (pivot targets), passwords in history |
| Mounts / NFS | `mount; cat /etc/fstab; cat /etc/exports` | no_root_squash, nosuid missing |
| Containers | `cat /proc/1/cgroup; ls -la /.dockerenv` | am I in a container? docker sock? → escape |
| DB creds | `cat /var/www/**/config*.php wp-config.php .env` | app→DB creds (reuse) |

```
# Automated:
./linpeas.sh -a | tee linux/<asset_id>/linpeas.txt
```

## Decision branches

- **`sudo -l` shows NOPASSWD on a GTFOBins binary** (e.g. `vim`,`find`,`less`,`awk`,`python`)
  → spawn root shell. CONTROLLED, safe, reversible. → Level ROOT.
- **Member of `docker`/`lxd`/`disk` group** → mount host fs / spawn privileged container →
  root. Document the group-based escalation.
- **Non-standard SUID binary** → check GTFOBins → exploit → root.
- **Capability `cap_setuid+ep` on a binary** → `./bin -c 'import os;os.setuid(0);…'` → root.
- **Root cron runs a world-writable script or a wildcard (`tar *`, `rsync`)** → inject →
  wait for cron → root. Note: cron timing = you may wait; don't break the legit job.
- **Readable SSH private key / password in history / .env creds** → §20 (reuse) → lateral
  (§21). A key in a user's `~/.ssh` + a `known_hosts` list is a ready-made pivot map.
- **Kernel is old & matches a public LPE** → kernel exploits can **panic the box**
  → **POTENTIALLY DISRUPTIVE**: prefer a misconfig path; only run a kernel exploit with
  care, ideally off-hours, and treat as §18 exploitation. Never on a fragile/prod host
  without approval.
- **In a container with the docker socket mounted** (`/var/run/docker.sock`) → container
  escape to host root.
- **No privesc vector** → pivot on creds/keys instead; you don't always need local root to
  progress the engagement.

## D. Root

| Objective | Command | Yields |
|-----------|---------|--------|
| Shadow hashes | `cat /etc/shadow` | crack offline (§20) → maybe reused elsewhere |
| All SSH keys | `find / -name 'id_*' 2>/dev/null` | pivot keys |
| App/DB secrets | read all config/.env | lateral creds |
| History/logs | `/root/.bash_history`, app logs | tokens, hosts, commands revealing infra |
| Pivot map | `ss -tulpn`, `arp -a`, `/etc/hosts` | internal targets for §21 |

## Evidence
`linux/<asset_id>/` — linpeas.txt, id.txt, sudo-l.txt, suid.txt, screenshot of `id` as root.
Keys/hashes → `loot/` encrypted; pointers in `credentials/credentials.csv`.

## When to stop
Root + creds harvested + pivot map built → move on. Document the exact escalation path (which
misconfig, which command) so it's reproducible in the report.

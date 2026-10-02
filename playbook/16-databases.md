# 16 — Databases (MSSQL/MySQL/PostgreSQL/Oracle/Redis)

> **Observation:** a DB port open (1433/3306/5432/1521/6379). **Objective:** identify version,
> test authorized/anon access, review privileges, and assess sensitive-data exposure — without
> modifying or destroying data. **Risk:** access CONTROLLED; `xp_cmdshell`/writes/dumps are §18.

## WHY

Databases hold the crown-jewel data and often have weak auth (default/blank/`trust`), reused
app creds, and command-exec features (MSSQL `xp_cmdshell`, PG `COPY TO PROGRAM`) that turn a DB
login into host RCE. Many (Redis especially) are frequently unauthenticated.

## Universal DB loop
`Discovery → Version → Authentication → Config/Privileges → Authorized access → Sensitive data
→ Security impact → Evidence`. **Never** `DROP`, `DELETE`, `UPDATE`, or truncate. Read-only
(`SELECT`, metadata) by default; writes/command-exec are exploitation (§18).

## MSSQL (1433)
| Step | Tool | Command | Look for |
|------|------|---------|----------|
| Version/instance | nmap | `nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info <ip>` | version, instance, domain |
| Auth | nxc | `nxc mssql <ip> -u <u> -p <p>` (or `-H` / `--local-auth`) | valid login, sysadmin? |
| Access | impacket | `impacket-mssqlclient acme/<u>:<p>@<ip> -windows-auth` | query shell |
| Privs | SQL | `SELECT IS_SRVROLEMEMBER('sysadmin');` | sysadmin → xp_cmdshell path |
| Sensitive data | SQL | `SELECT name FROM sys.databases; SELECT TOP 5 * FROM <t>` | PII/creds (sample only) |
| RCE | — | `xp_cmdshell` / linked servers | **§18 only** (host command exec) |

## MySQL (3306)
| Step | Command | Look for |
|------|---------|----------|
| Version | `nmap -p3306 --script mysql-info <ip>` | version, auth plugin |
| Anon/empty | `mysql -h <ip> -u root` (no pass) | blank root |
| Auth | `nxc mysql <ip> -u <u> -p <p>` | valid login |
| Privs | `SELECT user,host FROM mysql.user; SHOW GRANTS;` | FILE priv → read/write files |
| Data | `SHOW DATABASES; SELECT * FROM ... LIMIT 5;` | sensitive data (sample) |

FILE privilege → `LOAD_FILE`/`INTO OUTFILE` (web-root write) = RCE path → §18.

## PostgreSQL (5432)
| Step | Command | Look for |
|------|---------|----------|
| Version/auth | `nmap -p5432 --script pgsql-brute` *(careful — avoid brute; prefer known creds)* | version |
| Access | `psql -h <ip> -U postgres` | `trust` auth = no password |
| Privs | `\du`, `SELECT current_setting('is_superuser');` | superuser |
| Data | `\l`, `\dt`, `SELECT * FROM ... LIMIT 5;` | sensitive data |

Superuser → `COPY ... TO PROGRAM` = RCE → §18.

## Oracle (1521)
| Step | Tool | Command | Look for |
|------|------|---------|----------|
| SID | nmap/odat | `nmap -p1521 --script oracle-sid-brute`; `odat sidguesser -s <ip>` | valid SID |
| Creds | odat | `odat passwordguesser -s <ip> -d <SID>` *(spray = gated)* | default accounts (scott/tiger etc.) |
| Access | sqlplus | `sqlplus user/pass@<ip>/<SID>` | query shell |
| Privs/data | SQL | `SELECT * FROM session_privs;` | DBA → UTL_* / Java RCE → §18 |

## Redis (6379)
| Step | Command | Look for |
|------|---------|----------|
| Unauth? | `redis-cli -h <ip> info` | responds without auth = **common critical misconfig** |
| Data | `redis-cli -h <ip> keys '*'` (careful on huge sets) | sessions, tokens, cache secrets |
| RCE paths | module load / write SSH key / cron via `CONFIG SET dir` | **§18 only** (writes files) |

Unauthenticated Redis is usually an immediate finding; RCE via it (writing authorized_keys or
cron) is powerful but **writes to disk → §18 + RoE**, and reversible-cleanup required.

## Decision flow (all DBs)
```
anon/default/blank auth → access → finding (severity by data sensitivity + privilege)
app config creds (from §09/§10 loot) reused on DB → access → §20 track, §21 pivot
sysadmin/superuser/DBA + command-exec feature → RCE candidate → §18 (controlled, benign PoC)
sensitive data readable → sample a few rows for proof → §25 impact → do NOT exfil bulk data
```

## Safety
- Read-only by default. For RCE features: a **benign** proof (e.g. `xp_cmdshell 'whoami'`) via
  §18, logged, with any created artifact removed in cleanup. **No bulk exfiltration** — sample
  to prove exposure; mass dumps need explicit RoE approval and secure handling.

## Evidence
`enumeration/<id>-<db>.txt`, query transcripts (redacted), schema list, screenshot of version +
privilege + a sample (redacted) row. Creds → `loot/`.

# 01 — CIDR Normalization & Target Inventory

> **Objective:** turn a messy list of ranges into a clean, deduplicated, categorized,
> trackable inventory — so that every later phase operates on known, bounded data and
> every host has a stable ID you can reference in the report.

## WHY normalize first

If you scan the raw client list you will: scan the same host twice (overlapping
ranges), waste the testing window on dead space, and produce evidence you can't tie
back to an asset. Normalization is cheap insurance.

## Step 1 — Normalize & deduplicate CIDRs

**Primary tool:** `ipcalc` / `prips` / `nmap` / small Python with `ipaddress`.
**Why:** `ipaddress` collapses overlaps and dedupes deterministically; `prips`/`nmap -sL`
expands to host lists for tooling that wants IPs not CIDRs.

```bash
# scope/in-scope.txt (example)
# 10.10.10.0/24
# 10.10.20.0/24
# 10.10.30.0/24
# 192.168.50.0/24
# 10.10.10.0/25     <-- overlaps the first line

# Collapse overlaps & dedupe into minimal CIDR set:
python3 - <<'PY'
import ipaddress
nets=[]
for line in open("scope/in-scope.txt"):
    line=line.strip()
    if not line or line.startswith("#"): continue
    nets.append(ipaddress.ip_network(line, strict=False))
for n in ipaddress.collapse_addresses(nets):
    print(n)
PY
```

**Expected output:** a minimal, non-overlapping list of networks.
**What it means:** overlaps are gone; total host count is now accurate.
**Detect overlaps/duplicates explicitly** (to report sloppy scoping back to client):

```bash
python3 - <<'PY'
import ipaddress, itertools
nets=[ipaddress.ip_network(l.split()[0],strict=False)
      for l in open("scope/in-scope.txt") if l.strip() and not l.startswith("#")]
for a,b in itertools.combinations(nets,2):
    if a.overlaps(b): print("OVERLAP:",a,b)
PY
```

## Step 2 — Split large networks if appropriate

A `/16` is 65k hosts — don't feed it to a slow scanner as one blob. Split into `/24`s
so you can parallelize, track progress, and resume after interruption.

```bash
python3 - <<'PY'
import ipaddress
for l in open("scope/in-scope.txt"):
    l=l.strip()
    if not l or l.startswith("#"): continue
    n=ipaddress.ip_network(l,strict=False)
    if n.prefixlen < 24 and n.version==4:
        for s in n.subnets(new_prefix=24): print(s)
    else:
        print(n)
PY
> scope/cidrs-split.txt
```

## Step 3 — Categorize networks

Before touching them, label each CIDR by **expected role** (from client docs / naming).
Record in `inventory/networks.csv`:

```
cidr,label,expected_role,sensitivity,window,notes
10.10.10.0/24,SERVER,"server VLAN",high,night,"likely AD + file servers"
10.10.20.0/24,USER,"workstations",medium,business-hours-ok,
10.10.30.0/24,DMZ,"public-facing",high,24x7,"web/proxy"
192.168.50.0/24,MGMT,"OOB management",critical,by-approval,"iLO/iDRAC/switches - fragile"
```

**Why:** category drives *how* you scan it. MGMT/OT networks are fragile → gentle,
sequential, often **REQUIRES EXPLICIT RoE APPROVAL**. DMZ is noisy-tolerant but
monitored. USER networks have lockout-sensitive accounts.

## Step 4 — Asset IDs & tracking

Assign a stable ID the moment a host is confirmed live. Scheme: `<SITE>-<CIDRtag>-<n>`
e.g. `ACME-SRV-014`. Everything downstream (services, findings, creds, paths,
screenshots) references this ID.

The scaffold (`tools/init-engagement.sh`) seeds these CSVs:

| File | Tracks |
|------|--------|
| `inventory/hosts.csv` | asset_id, cidr, ip, hostname, os, role, status, notes |
| `inventory/services.csv` | asset_id, ip, port, proto, service, version, state, auth, notes |
| `inventory/findings.csv` | finding_id, asset_id, …, severity, status, evidence_path |
| `credentials/credentials.csv` | cred_id, source, realm, user, type, ref, validated, scope |
| `attack-paths/paths.csv` | path_id, initial→critical hops, impact, evidence, status |

> **Secrets rule:** never put a cleartext password or hash *value* in a CSV in the repo.
> Store the *reference* (`loot/creds/ACME-SRV-014-mssql.txt`, encrypted) and put only the
> pointer in the tracker. See `20-credential-testing.md`.

## Step 5 — Directory structure

Use the scaffold. It extends the structure you specified with a few battle-tested adds:

```
engagement/
├── scope/            # roe.md, in-scope.txt, out-of-scope.txt, targets-active.txt
├── inventory/        # hosts/services/findings/networks CSVs
├── discovery/        # host-discovery raw output (ping sweeps, arp, dns)
├── scans/            # nmap outputs: quick/ tcp/ udp/
├── enumeration/      # per-service enum output, named by asset_id
├── web/              # per-target web: httpx, nuclei, dirs, burp projects
├── windows/          # per-host windows enum
├── linux/            # per-host linux enum
├── active-directory/ # bloodhound zips, ldap dumps, kerberos artifacts
├── credentials/      # tracker only; real secrets go in loot/ (encrypted)
├── exploitation/     # per-finding PoC notes + output
├── privilege-escalation/
├── lateral-movement/
├── segmentation/     # matrix + probe results
├── attack-paths/     # paths.csv + diagrams
├── evidence/         # finalized, finding-linked evidence bundles
├── screenshots/      # named <finding_id>-<desc>.png
├── notes/            # daily log, scratch
├── reports/          # draft + final
├── loot/             # ADDED: encrypted secrets, dumps, keys (gitignored)
└── logs/             # ADDED: command-log.txt (timestamped activity audit trail)
```

**Added `loot/`** (encrypted, never committed) separates *secrets* from *tracking*.
**Added `logs/command-log.txt`** — append every command with a timestamp. This is your
own audit trail: it proves what you ran, when, from where, and is invaluable if the
client asks "did you cause X at 14:32?".

```bash
# wrap your shell to log automatically:
log(){ echo "$(date -u +%FT%TZ) $*" >> engagement/logs/command-log.txt; "$@"; }
# usage: log nmap -sn 10.10.10.0/24
```

Add a `.gitignore` so loot never leaks:
```
loot/
*.kdbx
*_secrets*
```

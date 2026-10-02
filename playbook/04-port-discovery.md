# 04 — Port Discovery

> **Objective:** for each live host, learn which TCP/UDP ports are open and roughly what
> runs there — scalably, and without lighting up every IDS at once.
> **Risk:** SAFE DISCOVERY → CONTROLLED (version scans touch services).

## WHY a staged approach

A full TCP scan (65535 ports) + version detection on 300 hosts, run naively, takes days
and screams at the SOC. Staging lets you get 80% of the value fast and quietly, then spend
deep scans only where they pay off.

## The staged flow

```
Live hosts (discovery/live-all.txt)
  → Stage A: QUICK top-ports SYN scan (all hosts)          SAFE
  → Stage B: SERVICE/VERSION on found-open ports only      CONTROLLED
  → Stage C: FULL TCP (65535) on INTERESTING hosts only    SAFE-ish (slower/louder)
  → Stage D: SELECTIVE UDP (key ports) on relevant hosts   SAFE (slow)
  → Feed service enumeration (05+)
```

## Stage table

| Stage | Objective | Primary | Alternative | Why | Command | Expected | Next |
|-------|-----------|---------|-------------|-----|---------|---------|------|
| A | Fast wide port sweep | `masscan` (huge sets) / `rustscan` | `nmap -F` | masscan does the whole scope at high rate; rustscan is fast per-host | `masscan -iL discovery/live-all.txt -p1-65535 --rate 1000 -oL scans/quick/masscan.txt` *(tune rate per RoE)* | `open` lines ip+port | feed open ports to Stage B |
| A' | Quick nmap top-ports | `nmap -sS --top-ports 1000` | `nmap -F` (top 100) | when masscan not allowed; nmap SYN is reliable | `nmap -sS -T4 --top-ports 1000 -iL discovery/live-all.txt -oA scans/quick/top1000` | per-host open ports | Stage B |
| B | Identify service+version | `nmap -sV` | `nmap -sV --version-intensity 9` | turns "445 open" into "SMB, Windows Server 2019" | `nmap -sS -sV -sC -p<open> -iL <hosts> -oA scans/tcp/versions` | service, product, version, default-script hits | drives service chapters |
| C | Full TCP on key hosts | `nmap -p-` | `rustscan -r 1-65535` | catch high/non-standard ports (shells, admin panels, DBs) | `nmap -sS -p- -T4 --max-retries 2 -iL inventory/interesting.txt -oA scans/tcp/full` | extra open ports | re-run Stage B on new ports |
| D | Selective UDP | `nmap -sU` top UDP | `nmap -sU -p53,67,69,123,137,161,500,514,1434,5353` | UDP hides DNS/SNMP/TFTP/IKE/NetBIOS — high-value, often unmonitored | `nmap -sU --top-ports 50 -T4 -iL discovery/live-all.txt -oA scans/udp/top50` | open/open|filtered | enum SNMP/DNS/TFTP/IKE |

## When to use which

- **Quick scan (A/A'):** always, first, on everything. It shapes the whole engagement.
- **Full TCP (C):** on hosts that look important — DCs, servers, anything with web/DB/admin
  ports, anything with an unusual banner. Not needed on every workstation.
- **UDP (D):** targeted. Full UDP is painfully slow and often `open|filtered` (ambiguous).
  Scan the **top ~50 UDP** everywhere; full UDP almost never worth it. Prioritize
  53/123/161/137/500/69.
- **When NOT to scan aggressively:** MGMT/OT/legacy/printer VLANs, during business hours on
  user nets, or any range the client flagged fragile. Use `--max-rate`, `--scan-delay`,
  `-T2`, and sequential execution. Aggressive timing on a fragile host = outage =
  POTENTIALLY DISRUPTIVE.

## "Interesting host" definition (what earns a full scan)

Add to `inventory/interesting.txt` any host with: 445/135/389/88 (Windows/AD),
any web port, any DB port, 22 with a weird banner, 3389/5985, a MGMT banner (iLO/iDRAC),
or a hostname implying a server. Full-TCP those.

## Timing & rate guidance

| Context | nmap timing | masscan rate | Notes |
|---------|-------------|--------------|-------|
| DMZ / robust servers | `-T4` | 1000–5000 | monitored but sturdy |
| Internal server VLAN | `-T4`, `--max-rate 2000` | 1000 | fine off-hours |
| User VLAN, business hours | `-T3`, `--max-rate 500` | 300 | avoid disruption |
| MGMT / OT / legacy / printers | `-T2`, `--scan-delay 50ms`, `--max-rate 50` | ≤100 | **POTENTIALLY DISRUPTIVE** — gentle, sequential |

## Interpreting nmap port states

| State | Means | Action |
|-------|-------|--------|
| `open` | service accepted connection | enumerate it |
| `closed` | host up, nothing listening | host is live (useful for discovery) |
| `filtered` | no response / dropped | firewall; try `-Pn`, different source, or note |
| `open\|filtered` | UDP ambiguous (no reply) | may still be open; probe with service tool |
| `unfiltered` | reachable but state unknown (ACK scan) | indicates firewall mapping |

## Parsing output into the tracker

```bash
# extract open ports from nmap greppable into services.csv rows
grep -h "/open/" scans/tcp/versions.gnmap | \
  awk -F'\t' '{ip=$2; sub("Host: ","",ip); print ip}' # then enrich per-port
# Or use the XML with a parser; keep raw .nmap/.xml/.gnmap for evidence.
```

Store all three nmap formats (`-oA`): `.nmap` (human), `.gnmap` (grep), `.xml` (tooling).

## Evidence
- `scans/quick/*`, `scans/tcp/*`, `scans/udp/*` — raw outputs (all three formats).
- Update `inventory/services.csv` with every open port + version.

## When to stop
- Every live host has a top-ports result; every interesting host has full-TCP + UDP-top.
- You have a per-service worklist. Move to enumeration (05).

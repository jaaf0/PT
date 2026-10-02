# 03 — Host Discovery

> **Objective:** from CIDRs, produce the set of *live* hosts — without wasting the
> window probing dead space and without being louder than necessary.
> **Risk:** SAFE DISCOVERY (within rate limits).

## WHY discovery before port scanning

Port-scanning a whole `/24` blindly is 254× more work than scanning the ~30 live hosts
on it. Discovery narrows the target set, speeds everything downstream, and reduces noise.
**Caveat:** firewalls drop discovery probes. "No response" ≠ "no host". So discovery is a
*prioritization* step, not a *deletion* step — see the decision tree.

## Techniques by network position

| Your position | Best first probe | Why |
|---------------|------------------|-----|
| **Same L2 segment (internal, on-VLAN)** | ARP | Can't be firewalled within a broadcast domain; definitive |
| **Routed internal** | ICMP + TCP-SYN to common ports | ICMP often allowed internally; TCP catches ICMP-filtered hosts |
| **External / through firewall** | TCP-SYN to 80/443/22 + a few UDP | ICMP usually blocked at perimeter |

## The decision tree

```
For each target:
  ARP (if on-link)
   ├─ replies            → LIVE (definitive) → inventory, go port-scan
   └─ not on-link / none → ICMP echo + timestamp + netmask
        ├─ replies        → LIVE → port-scan
        └─ silent         → TCP-SYN discovery to 21,22,80,135,139,443,445,3389,3306,8080
             ├─ any SYN/ACK or RST → LIVE (host up, port closed still = host present) → port-scan
             └─ silent             → UDP discovery to 53,123,161,137,500
                  ├─ response → LIVE → port-scan
                  └─ silent   → MARK "filtered/unknown" (do NOT delete)
                               → note for firewall-aware deep scan later
```

## Step table

| Step | Objective | Primary Tool | Alternative | Why | Command | Expected | If Found | If Not Found | Evidence |
|------|-----------|--------------|-------------|-----|---------|----------|----------|-----------|----------|
| H1 | L2 host discovery | `arp-scan` | `nmap -PR` | ARP can't be filtered on-link | `arp-scan -I eth0 -f scope/targets-active.txt` | MAC+IP per live host | add LIVE + MAC (vendor hints OS/device) | host not on your L2 | `discovery/arp.txt` |
| H2 | Fast L3 sweep | `fping` | `nmap -sn` | fping is fast & scriptable for large sets | `fping -a -g 10.10.10.0/24 2>/dev/null` | list of responders | LIVE | silent → H3 | `discovery/fping-<cidr>.txt` |
| H3 | Multi-probe sweep | `nmap -sn` | `masscan --ping` | nmap combines ICMP+ARP+TCP-ACK+timestamp | `nmap -sn -PE -PP -PS21,22,80,443,445,3389 -PA80 -PU161 -iL scope/targets-active.txt -oA scans/quick/ping` | "Host is up" lines | LIVE | silent → H4 | `scans/quick/ping.*` |
| H4 | Beat ICMP filtering | `nmap -Pn` targeted TCP | `masscan` | treat as up, probe TCP directly on key ports | `nmap -Pn -sS -p135,139,445,80,443,22,3389 -iL discovery/silent.txt -oA scans/quick/tcp-disc` | open/closed = host present | LIVE | all filtered | `scans/quick/tcp-disc.*` |
| H5 | Passive discovery | `wireshark`/`tcpdump`+`responder -A` (analyze-only) | `netdiscover -p` | zero active probes; sees broadcast/multicast chatter | `tcpdump -ni eth0 'arp or port 137 or port 5353'` | hosts announcing themselves | LIVE (stealth) | nothing seen | `discovery/passive.pcap` |

> **Responder in analyze-only (`-A`) mode is passive** (SAFE DISCOVERY). Responder in
> *poisoning* mode (answering LLMNR/NBT-NS/mDNS) is **REQUIRES EXPLICIT RoE APPROVAL** —
> it is an active MITM that can capture credentials and disrupt name resolution. Covered in `20`.

## DNS-based discovery (cheap, quiet wins)

| Objective | Tool | Command | Yields |
|-----------|------|---------|--------|
| Reverse-resolve the ranges | `dnsx` / `nmap --dns-servers` | `prips 10.10.10.0/24 \| dnsx -ptr -resp-only` | hostnames → hints at role (DC01, SQL02, VPN) |
| Find the internal DNS server | from DHCP/`resolv.conf`/nmap 53 | — | the DNS server is often a DC |
| Zone transfer (if authorized) | `dig AXFR` | `dig AXFR acme.local @10.10.10.10` | full internal host list if misconfigured (see `12-dns.md`) |

Reverse DNS alone can reveal naming conventions that tell you which boxes are DCs,
SQL, file servers, and VPN gateways — pure SAFE DISCOVERY gold.

## Scaling to hundreds of hosts

- **Stage 1 (broad, quiet):** `fping`/`nmap -sn` across *all* CIDRs → `discovery/live-all.txt`.
- **Stage 2 (recover filtered):** `nmap -Pn` TCP-disc only on the silent set.
- **Split by `/24` and run in parallel** (host discovery is SAFE to parallelize — see `33`):
  ```bash
  cat scope/cidrs-split.txt | xargs -P 8 -I{} sh -c \
    'fping -a -g {} 2>/dev/null > discovery/live-$(echo {} | tr "/." "__").txt'
  cat discovery/live-*.txt | sort -u > discovery/live-all.txt
  wc -l discovery/live-all.txt
  ```
- **Rate-limit** on fragile/MGMT nets: add `nmap --max-rate 50 --scan-delay 20ms`.

## Decision output

Write the live set to `inventory/hosts.csv` (status=live) and `discovery/live-all.txt`.
That file is the **only** input to port discovery (04). Keep the "filtered/unknown" set in
`discovery/filtered.txt` — revisit with firewall-aware scans before declaring a range dead.

## When to stop
- All in-scope CIDRs have a live-set and a filtered-set.
- Don't loop forever trying to wake silent hosts — note them and move on; port discovery
  with `-Pn` will give them a second chance.

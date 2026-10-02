# 21 — Lateral Movement

> **Objective:** use access/credentials from one host to reach and compromise others, building a
> documented chain toward the objective. **Risk:** frequently **REQUIRES EXPLICIT RoE APPROVAL**
> — crossing segments and executing on new hosts has the highest disruption/detection profile.

## WHY lateral movement (and when NOT to)

A single compromised host rarely *is* the business risk; the risk is what that host lets you
reach. Lateral movement proves the real blast radius. But every hop is a new host you're acting
on — so each hop must be **in scope, authorized, safe, and necessary to prove impact**. Don't
hop for sport; hop to prove a path.

## The four gates before every hop

```
For each candidate next host:
  IN SCOPE?      is it on the in-scope list / allowed segment?      no → STOP (§00)
  AUTHORIZED?    does RoE permit lateral movement to it?            no → report reachability only
  SAFE?          is the method non-destructive on that host?        no → gate/skip
  NECESSARY?     does this hop prove new impact / advance the goal?  no → don't bother
  → all yes → proceed, document the hop
```

## The chain pattern

```
Initial host
 → harvest creds/keys/tickets (§08/§09/§20)
 → internal discovery from this vantage (new subnets, §03/§04 from inside)
 → identify reachable hosts where creds work (nxc sweep)
 → authenticate (PtH/PtT/creds — §20)
 → new access → privesc (§19) → harvest more creds
 → repeat toward the critical asset
```

## Execution methods (prefer the quieter/safer)

| Method | Tool | Notes / noise |
|--------|------|---------------|
| WinRM | evil-winrm / nxc winrm | cleanest, "expected" admin channel (§15) |
| WMI exec | impacket-wmiexec | fileless-ish, moderate |
| SMB service exec | impacket-psexec / smbexec | reliable but **loud** (creates service) — EDR-visible |
| Scheduled task | impacket-atexec | moderate |
| SSH / keys | ssh with harvested keys | Linux lateral (§13) |
| RDP | xfreerdp (owned creds/PtH) | interactive, visible to any console user |
| DCOM/MMC | impacket-dcomexec | niche |

Prefer WinRM/WMI over psexec when possible; log whichever you use as a §24 detection datapoint.

## Internal discovery from a foothold
```bash
# From the compromised host's vantage, find new reachable segments:
ip a / ipconfig /all; route print; arp -a        # new subnets
nxc smb <new_subnet> -u <owned> -p <pass>        # where do my creds work?
# (treat the new subnet as targets — re-check it's in scope FIRST)
```

## Pivoting / tunneling (to reach non-routable segments)
| Tool | Use | Risk |
|------|-----|------|
| chisel / ligolo-ng | TCP tunnel/SOCKS through a foothold | CONTROLLED; it's a channel, document it |
| sshuttle | route a subnet over SSH | CONTROLLED |
| ssh -L/-D | port-forward/SOCKS | CONTROLLED |

Pivoting itself is a tool, not an attack — but reaching a **new segment** = re-apply the four
gates (and often segmentation findings, §22).

## Decision flow
```
owned cred works on many hosts (no LAPS/shared local admin) → systemic finding + broad lateral
reachable DC → §07 (don't exploit beyond proving the path)
new segment reachable that SHOULDN'T be → that's a segmentation finding too (§22)
reached critical asset / domain admin → STOP escalating → prove impact (§25) → evidence
```

## Document EVERY hop (this is the attack path)
For each hop record in `attack-paths/paths.csv`: source host, credential used (ref), method,
destination host, what it granted, timestamp. This table *is* your attack-path narrative (§25).

## Evidence
`lateral-movement/<path_id>/` — the sweep output, the exec command, `whoami` on the new host,
and the updated `paths.csv` row. Screenshot each new foothold's context.

## When to stop
Objective reached, or no new in-scope/authorized/safe/necessary hop remains. Don't sprawl across
the whole estate to "collect" hosts — a proven path to the crown jewels is the deliverable.

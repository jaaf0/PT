# 37 — Final Master Checklist

The follow-along list for the whole engagement. Work top to bottom; each item links to its chapter.
Copy this into `notes/checklist.md` and tick as you go.

## Pre-engagement (§00–01)
```
[ ] Signed authorization letter on file
[ ] RoE confirmed (techniques allowed/forbidden, in writing)
[ ] In-scope CIDRs/IPs/domains/URLs imported (scope/in-scope.txt)
[ ] Out-of-scope exclusions imported (scope/out-of-scope.txt)
[ ] Account-lockout policy obtained (BEFORE any auth testing)
[ ] Testing windows + blackout periods agreed
[ ] Source/egress IPs shared with client
[ ] SOC notification posture decided (announced/semi/blind)
[ ] Emergency contacts + emergency-stop procedure documented
[ ] Sensitive-data handling + retention + destruction agreed
[ ] Engagement tree created (init-engagement.sh)
[ ] CIDRs normalized, duplicates/overlaps removed, split if large
[ ] Networks categorized (server/user/DMZ/MGMT/OT) + sensitivity
[ ] Target inventory + asset-ID scheme created
```

## Discovery (§03–05)
```
[ ] Host discovery completed (ARP/ICMP/TCP/UDP); live-all.txt built
[ ] Filtered/silent hosts noted (not deleted)
[ ] Port discovery: quick sweep on all live hosts
[ ] Version detection on open ports
[ ] Full-TCP on interesting hosts; selective UDP top-ports
[ ] services.csv populated
[ ] Service enumeration completed per port
```

## Classification
```
[ ] Web targets identified (§10/§11)
[ ] SMB targets identified (§06)
[ ] AD / Domain Controllers identified (§07)
[ ] Windows hosts identified (§08)
[ ] Linux hosts identified (§09)
[ ] Databases identified (§16)
[ ] Network devices / VPN / appliances identified (§23)
```

## Assessment (§17, §06–16, §10–11)
```
[ ] Vulnerability scanning completed (credentialed where possible)
[ ] Scanner findings manually validated (fp-log maintained)
[ ] Web/API manual testing completed (authz/injection/logic)
[ ] SMB/AD enumeration completed per access level
[ ] DNS/SSH/RDP/WinRM/DB enumeration completed
```

## Exploitation & escalation (§18–21)
```
[ ] Exploitation decisions gated (§18) and logged
[ ] Controlled exploitation performed where authorized + valuable
[ ] Credentials harvested, validated, and documented securely (refs only)
[ ] Offline cracking run (no online guessing without approval)
[ ] Privilege escalation assessed (Windows + Linux)
[ ] Lateral movement assessed (4 gates per hop)
[ ] Any RoE-gated technique (spray/relay/DoS-capable exploit) has written approval
```

## Analysis (§22, §24, §25, §27)
```
[ ] Segmentation tested; matrix built
[ ] SOC/EDR/SIEM/WAF detection observations documented (+ MITRE mapping)
[ ] Attack paths constructed (findings → paths → impact)
[ ] Choke-point findings identified
[ ] Severities assigned with rationale (not raw scanner labels)
```

## Evidence & reporting (§26, §28)
```
[ ] Evidence collected per finding (reproducible by a peer)
[ ] command-log.txt / cleanup-log.csv / data-access-log.csv maintained
[ ] Findings written (title/severity/evidence/reproduction/impact/root cause/recommendation)
[ ] Recommendations written (prioritized, actionable)
[ ] Attack-path diagrams produced
[ ] Report drafted, QA-reviewed, client-reviewed, finalized
```

## Close-out
```
[ ] Cleanup completed and verified against cleanup-log.csv
    (shells, uploaded tools, created accounts, test files, enabled features all removed)
[ ] Final report delivered securely
[ ] Readout meeting held (exec + technical)
[ ] Retest scope/timeline agreed
[ ] Evidence retention/destruction executed per RoE
```

## Global reminders (apply at every step)
```
[ ] Every target checked against out-of-scope before touching it
[ ] Every command logged with UTC timestamp + source IP
[ ] Prefer least-disruptive technique that answers the question
[ ] Stop + notify POC on ANY instability, lockout, or out-of-scope reach
[ ] No persistence / no control-tampering / no DoS / no bulk exfil without written approval
[ ] Stop escalating once objective impact is proven
```

# 33 — Parallelization Strategy

With 50+ CIDRs you must parallelize to finish in the window — but only the *safe* activities.
Classify every activity into one of three buckets.

## SAFE TO PARALLELIZE (fan out freely, within rate limits)
Read-only, low-state-change, per-host-independent work:
- Host discovery (fping/nmap -sn) across CIDRs — split by /24, `xargs -P`.
- Port discovery (masscan/nmap quick) — independent per host.
- Service/version detection (nmap -sV).
- Banner grabbing, TLS scans (testssl), whatweb/httpx fingerprinting.
- Unauthenticated enumeration (SMB null-session enum, LDAP anon, DNS, SNMP read).
- **Offline hash cracking** (fully parallel, zero target impact).
- nuclei (with sane concurrency/rate), reverse DNS.

```bash
# Example: parallel discovery by /24
cat scope/cidrs-split.txt | xargs -P 8 -I{} sh -c \
 'nmap -sn {} -oG discovery/sn-$(echo {}|tr "/." "__").gnmap >/dev/null'
```
Keep per-host rate limits even when parallel — parallelism multiplies total load on shared
infrastructure (switches, firewalls, the SIEM).

## SEQUENTIAL (one at a time, paced, watched)
State-touching or risk-bearing work where you must observe each result before the next:
- **Authenticated** enumeration and **credential reuse** sweeps (watch for lockouts).
- Exploitation (§18) — one target, confirm stability before moving on.
- Privilege escalation that restarts services.
- Lateral movement hops (§21) — each is a decision point.
- Scanning **fragile/MGMT/OT/legacy** segments — gentle and serial.
- DB access, web manual testing on production apps.

## REQUIRES APPROVAL (never parallelize; often never without written sign-off)
- **Password spraying** — must be paced *and* serialized against the lockout window; parallel
  spraying is how you lock out an entire org. **RoE-gated.**
- Brute force (forbidden by default).
- Responder poisoning / NTLM relay / coercion — single, time-boxed, authorized. **RoE-gated.**
- Any exploit with crash/DoS potential (EternalBlue/BlueKeep/appliance RCE/kernel LPE). **RoE-gated.**
- Anything that modifies production, creates persistence, or tampers with security controls.

## Rule of thumb
```
Read-only + independent + no lockout risk  → PARALLEL
Touches auth / state / fragile systems     → SEQUENTIAL (paced, observed)
Can lock out / disrupt / needs sign-off    → REQUIRES APPROVAL (serial, time-boxed)
```
Parallelize discovery to *buy time* for the slow, careful, sequential work that actually finds
and proves the impactful issues.

# 00 — Rules of Engagement (RoE)

> **You do not touch a single packet until this section is complete and the answers are in writing.**
> The RoE is both your authorization and your legal shield. A test outside scope is
> not a pentest — it is unauthorized access. The discipline here is what separates a
> consultant from a liability.

## WHY this phase exists

Three failure modes end engagements (and careers):

1. **Scope creep** — you scan/exploit an IP that turned out to be a third party's
   shared host, a managed service, or production you weren't cleared for.
2. **Availability impact** — a "harmless" scan locks out a service account or knocks
   over a fragile legacy box, and nobody knew who to call.
3. **Unprovable work** — you found something real but can't reproduce it or prove you
   stayed in bounds.

The RoE kills all three before they happen.

## The pre-flight questions (ask these before scanning)

Capture every answer in `scope/roe.md` with the date and the name of who confirmed it.

### Scope boundaries
- **Exact in-scope CIDRs / IPs / hostnames / URLs?** Get the authoritative list in
  machine-readable form (paste into `scope/in-scope.txt`).
- **Explicit out-of-scope IPs/ranges/hosts?** (`scope/out-of-scope.txt`) — e.g. DCs you
  may enumerate but not exploit, shared SaaS, HVAC/OT, a CEO laptop.
- **Domains & subdomains** in scope — and is subdomain discovery itself authorized?
- **Internal vs external vs DMZ vs management network** — which are you testing, and
  from where (assumed-breach internal box? external IP? both)?
- **Production vs test/staging** — is production in scope, or only a mirror?
- **Third-party / cloud assets** — are any targets hosted by AWS/Azure/GCP/Cloudflare?
  Cloud providers require their own authorization or have an accepted-testing policy.
  **Scanning a cloud asset you don't own may violate the provider's ToS** → confirm.

### Allowed vs forbidden techniques (get an explicit yes/no for each)
| Technique | Default stance | Needs |
|-----------|----------------|-------|
| Port/service scanning | usually allowed | rate limits, windows |
| Vulnerability scanning (authenticated/unauth) | usually allowed | credentials? windows? |
| **Brute force** | usually forbidden | **REQUIRES EXPLICIT RoE APPROVAL** — lockout risk |
| **Password spraying** | case-by-case | **REQUIRES EXPLICIT RoE APPROVAL** + lockout policy known |
| Credential testing (known/provided creds) | often allowed | which accounts, what privilege |
| Exploitation of confirmed vulns | case-by-case | per-vuln or blanket? non-destructive only? |
| Privilege escalation | usually allowed if access authorized | scope of hosts |
| Lateral movement | case-by-case | which segments, prove-impact only |
| Social engineering / phishing | separate scope | **REQUIRES EXPLICIT RoE APPROVAL** |
| Physical testing | separate scope | **REQUIRES EXPLICIT RoE APPROVAL** |
| **DoS / stress / fuzzing live services** | **FORBIDDEN** | do not perform |
| Accessing sensitive data (PII/PHI/secrets) | restricted | handling & proof-of-access rules |

### Operational logistics
- **Testing windows** — allowed days/hours; blackout periods (month-end, releases).
- **Source IPs** — the IP(s) you will test from (give the client your egress IPs so
  the SOC can allow-list or watch them). Note whether they should whitelist you.
- **SOC notification posture** — is this announced, semi-announced, or a true red-team
  (SOC blind)? This changes everything about noise tolerance.
- **Emergency contacts** — 24/7 phone + email for client POC and technical owner.
- **Emergency stop procedure** — the exact signal ("red button") that means stop now,
  and what you do when you receive it (cease activity, preserve state, call POC).
- **Data handling** — where loot/PII lives, encryption at rest, retention, destruction
  date, and whether screenshots may contain real data.
- **Cleanup requirements** — remove uploaded tools, created accounts, shells, scheduled
  tasks, test files. Document each artifact you create so you can remove it.
- **Evidence retention** — how long you keep evidence post-report, and secure deletion.

## Scope-validation checklist (`scope/checklist.md`)

```
[ ] Signed authorization letter on file (names the testing company + client signer)
[ ] In-scope CIDRs/IPs/domains/URLs received in writing
[ ] Out-of-scope exclusions received in writing
[ ] DMZ / internal / management / prod / test boundaries clarified
[ ] Third-party & cloud ownership confirmed (provider authorization where needed)
[ ] Testing windows + blackout periods agreed
[ ] Allowed/forbidden technique table signed off (esp. spraying/bruteforce/exploit/DoS)
[ ] Account-lockout policy obtained (threshold, window, reset) BEFORE any auth testing
[ ] Source/egress IPs shared with client
[ ] SOC notification posture decided (announced / semi / blind)
[ ] Emergency contacts (24/7) + emergency-stop signal documented
[ ] Sensitive-data handling + encryption + retention + destruction agreed
[ ] Cleanup expectations agreed
```

## Scope-enforcement discipline (do this every single scan)

- Keep `scope/in-scope.txt` and `scope/out-of-scope.txt` as the **only** target sources.
- **Every** tool invocation reads targets from the in-scope file and is filtered against
  the out-of-scope file. Build the habit:

```bash
# Produce a clean, deduped, exclusion-filtered working target list.
sort -u scope/in-scope.txt > /tmp/_in
# (expand CIDRs later; for exact-IP exclusion:)
grep -v -F -x -f scope/out-of-scope.txt /tmp/_in > scope/targets-active.txt
wc -l scope/targets-active.txt
```

- Point scanners at `scope/targets-active.txt`, never at a hand-typed range.

## WHEN additional authorization is required (stop-and-ask triggers)
- Any technique in the table marked **REQUIRES EXPLICIT RoE APPROVAL**.
- You discover a host/range/domain **not** on the in-scope list but clearly related
  (e.g., a trust to another domain, a reachable adjacent CIDR) → **do not touch it**;
  report it and ask whether to extend scope.
- You find evidence of a **prior real compromise** → stop, preserve, notify POC
  immediately (this is an incident, not your finding to exploit).
- Exploitation would modify production data or configuration.
- You can reach a **cloud/third-party** asset you weren't explicitly cleared for.

## WHEN to stop (globally)
- Emergency-stop signal received.
- You cause (or suspect you caused) an outage, lockout, or instability → stop that
  activity, log it, notify POC per the agreed procedure.
- You reach the edge of scope.
- The testing window closes.

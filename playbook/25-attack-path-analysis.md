# 25 — Attack Path Analysis

> **Objective:** transform individual findings into **narratives of compromise** that show real
> business impact — the thing executives and remediation teams actually act on.

## WHY: vulnerability ≠ attack path ≠ business impact

| Concept | Example | Who cares |
|---------|---------|-----------|
| **Individual vulnerability** | "SMB signing disabled on 40 hosts" | sysadmin |
| **Attack path** | "LLMNR poisoning → relay to a no-signing host → local admin → cached DA creds → DCSync" | security team |
| **Business impact** | "Full domain compromise → access to finance DB → ability to read/alter payroll" | executives/board |

A list of 60 medium findings doesn't move anyone. **One diagrammed path from "any user on the
network" to "domain admin / crown-jewel data" does.** Your job is to connect the dots.

## Building a path

```
1. Start from each ENTRY POINT (external web app, phishing-equivalent foothold, assumed breach,
   exposed service, guest VLAN).
2. For each, chain the findings that lead to the next privilege/host:
     entry → initial access → credential → new host → privesc → credential → ... → crown jewel
3. Record every hop in attack-paths/paths.csv (one row per path, hops in the fields).
4. Identify the SHORTEST and the HIGHEST-IMPACT paths — lead the report with those.
5. Map each hop to the finding(s) that enable it, so remediation of ONE hop breaks the path.
```

## Worked example (classic internal)

```
Internet / assumed-breach on USER VLAN
 → (F1) LLMNR/NBT-NS enabled → poisoning captures NetNTLMv2 [RoE-gated technique]
 → (F2) SMB signing disabled on SRV14 → relay → local admin on SRV14
 → (F3) no LAPS → shared local-admin hash → PtH sweep → admin on SRV14/SRV22/SRV31
 → (F4) DA logged into SRV22 → LSASS → domain admin credential
 → (F5) DCSync rights → dump NTDS → full domain compromise
 → Impact: read/modify all AD, access Finance DB (crown jewel) → confidentiality+integrity of payroll
```
Each `Fn` is a standalone finding; the **path** is the story; the **impact** is the business
consequence. Note that fixing **F2** *or* **F3** alone breaks this chain — that's the remediation
leverage you surface.

## External → internal example
```
Public web app (DMZ)
 → (F1) SSRF → cloud metadata → temp credentials
 → (F2) over-permissioned IAM role → read S3 backups → DB dump with hashes
 → (F3) hash reuse → VPN/SSO login → internal foothold
 → ... → internal AD path (above)
 → Impact: external attacker with no creds → internal domain + customer data
```

## Analysis questions for each path
- **Entry assumption:** what access does the attacker start with? (none/phish/guest/insider)
- **Prerequisites:** does each hop require something the previous hop provides? (true chain)
- **Choke points:** which single finding, if fixed, breaks the most paths? (remediation priority)
- **Likelihood:** how hard is each hop? (default creds = trivial; 0-day = unlikely)
- **Impact:** what does the end state let an attacker do to the *business*? (not "got DA" — "could
  alter financial records / exfiltrate PHI / halt operations")

## Decision flow
```
collection of findings → group by reachable chains → draw each path (§36 mermaid)
rank paths by (impact × likelihood) → report leads with top 1–3
for each path → identify choke-point finding → tag it "breaks path" in findings.csv (raises its priority)
path reaches crown jewel → STOP escalating that path → evidence the end-state impact
```

## Evidence
`attack-paths/paths.csv` (structured), a mermaid diagram per major path (`attack-paths/*.md`),
and cross-references from each hop to its finding ID and its evidence bundle. This section is the
spine of the report's "Attack Paths" chapter (§28).

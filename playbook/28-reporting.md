# 28 — Reporting

> **Objective:** deliver findings in a form each audience can act on — executives decide, security
> teams prioritize, admins remediate. The report is the product; everything else was preparation.

## WHY structure matters

Different readers need different things from the same engagement. A good report serves all three
without making any of them wade through the others' material.

## Report structure

| Section | Audience | Contents |
|---------|----------|----------|
| **Executive Summary** | leadership | business-level risk, 3–5 key points, overall posture, no jargon |
| **Scope** | all | exact in/out-of-scope, dates, testing type, assumptions |
| **Methodology** | technical | approach, standards (PTES/OSSTMM/OWASP), tools (high level) |
| **Limitations** | all | what you couldn't test & why (time, access, blackouts) — honesty protects you |
| **Attack Surface** | technical | hosts/services discovered, exposure overview |
| **Findings Summary** | all | table: ID, title, severity, affected count, status |
| **Attack Paths** | security | the §25 narratives + diagrams — the high-impact centerpiece |
| **Technical Findings** | admins | detailed per-finding (format below) |
| **Evidence** | admins | proof per finding (or referenced appendix) |
| **Business Impact** | leadership | what the findings mean for operations/compliance/revenue |
| **Remediation** | admins/security | prioritized, actionable fixes; quick wins vs strategic |
| **Retest** | all | what will be re-verified and when |
| **Appendix** | technical | raw data, tool versions, full host/service tables, methodology detail |

## Per-finding format

```
Title:            Concise, specific ("SMB Signing Not Required Enables NTLM Relay")
Finding ID:       F-014
Severity:         High  (with 1–2 sentence rationale, §27)
Affected Assets:  consolidated list (asset IDs / IPs / hostnames) + count
Description:      what it is, in plain language
Technical Details:how it works, why it's present (root cause)
Evidence:         command(s), output, screenshot refs (§26) — reproducible
Reproduction:     numbered steps a peer can follow
Impact:           what an attacker gains (tie to business where possible)
Root Cause:       the underlying misconfig/gap (so the fix addresses cause, not symptom)
Recommendation:   specific, actionable remediation (+ compensating controls if fix is slow)
References:       CVE/CWE/vendor docs/MITRE ATT&CK IDs
```

## Writing principles
- **Consolidate** duplicates: one finding, affected-assets list — not 40 copies.
- **Root cause over symptom:** "no LAPS → shared local admin" beats "admin hash reused on SRV22".
- **Actionable remediation:** name the setting/control, not "harden the system". Offer quick wins
  and strategic fixes separately; note compensating controls when a full fix is slow.
- **Lead with attack paths** (§25) in the technical narrative — they carry the impact.
- **Severity with rationale** (§27); never bare scanner labels.
- **Evidence every claim**; if you can't evidence it, it's an observation, not a finding.
- **State limitations honestly** — unscanned ranges, blackout windows, access you lacked.

## Deliverable hygiene
- Report may itself contain sensitive data → handle/encrypt/transmit per RoE; agree retention +
  destruction. Strip any real secrets from the body (reference, don't reproduce).
- Include an **evidence appendix or secure bundle**, and the **MITRE ATT&CK coverage/detection-gap
  table** (§24) if detection was in scope — clients love it.

## Draft → final flow
```
findings.csv (live) → draft per-finding writeups → peer/QA review → client draft review
→ incorporate clarifications (not scope disputes) → final report → readout meeting → retest plan
```
Store drafts in `reports/draft/`, final in `reports/final/`.

# 27 — Finding Severity & CVSS Limitations

> **Objective:** rate findings by **real risk in this environment**, not by a scanner's default
> label. Severity drives remediation order, so getting it right is a core consulting skill.

## WHY not just copy CVSS/scanner severity

CVSS base scores ignore *your* environment: a "Critical" on an isolated test box with no data may
be lower real risk than a "Medium" IDOR exposing all customer PII. Scanners also inflate (version
-only "criticals" that are patched) and can't see chains. **You re-rate with context.**

## Factors to weigh

| Factor | Question | Pushes severity ↑ |
|--------|----------|-------------------|
| Exploitability | how hard to exploit? | public exploit, no auth, reliable |
| Attack complexity | special conditions needed? | none |
| Authentication/privileges required | creds needed? | none / low-priv |
| Network exposure | where reachable from? | internet-facing > internal > isolated |
| Data sensitivity | what data/function is at risk? | PII/PHI/financial/credentials |
| Impact (CIA) | confidentiality/integrity/availability? | full, especially integrity of records |
| Lateral/chain potential | does it enable other paths? | choke point in a DA path (§25) |
| Business impact | consequence to operations/compliance | regulated data, revenue, safety |

## A practical rating rubric

| Severity | Rough meaning |
|----------|---------------|
| **Critical** | Unauth or trivial path to full compromise / mass sensitive-data access / crown jewels. Fix now. |
| **High** | Significant impact, realistic path (e.g. auth/privesc, broad data exposure, a key hop in a DA path). |
| **Medium** | Real issue needing specific conditions or limited impact (e.g. info disclosure, weak config enabling a step). |
| **Low** | Minor/hardening (weak TLS ciphers, verbose headers) — small direct risk. |
| **Informational** | No direct risk; good-practice note. |

## How to combine CVSS with context
- Start from CVSS base as an **anchor**, then apply **Environmental/Temporal** metrics (exploit
  maturity, where it sits in the network, data value). Document the adjustment reasoning.
- **Chain uplift:** a finding that is a choke point for a Critical attack path (§25) inherits
  priority even if its standalone CVSS is Medium — say so explicitly.
- **Downgrade stale "criticals":** version-only, patched, unreachable, or not-actually-exploitable
  → lower it and note why (prevents report noise and lost credibility).

## Decision flow
```
scanner severity → verify exploitability + reachability + data value → re-rate
standalone Medium that breaks a DA path → elevate (note chain role)
"Critical" that's unreachable/patched → downgrade with justification
multiple same-root findings → one consolidated finding, severity = worst realistic case
```

## Evidence/justification
For each finding record the severity **and one or two sentences of rationale** tying it to the
factors above. Reviewers trust ratings they can see the reasoning behind.

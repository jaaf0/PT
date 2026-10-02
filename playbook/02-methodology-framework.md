# 02 — Master Tool-Driven Methodology

This is the engine the whole playbook runs on. Internalize the loop, then every
service chapter is just the loop applied to a new port.

## The loop

```
OBSERVATION   What did I just see? (an open port, a banner, a response code)
   ↓
OBJECTIVE     What am I trying to learn or prove with the next action?
   ↓
PRIMARY TOOL  The default tool for this objective (not "a tool" — THE tool)
   ↓
COMMAND       Exact invocation, output written to the right folder
   ↓
EXPECTED OUT  What a normal result looks like
   ↓
INTERPRET     What this specific output means
   ↓
DECISION      IF A → X, IF B → Y, IF none → Z
   ↓
NEXT TOOL     What the decision hands you to
   ↓
VALIDATION    Manual confirmation that it's real (not a scanner guess)
   ↓
EVIDENCE      What to save, named by asset/finding ID
   ↓
NEXT PHASE    Where this feeds (privesc? lateral? finding? attack path?)
```

## How to read every table in this playbook

Each phase gives a table with these columns:

| Step | Objective | Primary Tool | Alternative | Why | Command/Usage | Expected Output | What to Look For | If Found | If Not Found | Next Step | Evidence | Risk |

- **Primary Tool** = your default. Use it unless you have a reason not to.
- **Alternative** = when the primary is unavailable/blocked/noisy, or to cross-check.
- **Why** = the reasoning — this is what you're here to learn.
- **Risk** = one of the four labels from the README.

## Tool tiers (so you never drown in 20 tools for one job)

| Tier | Meaning | Rule |
|------|---------|------|
| **PRIMARY** | Default, run first | One per objective |
| **ALTERNATIVE** | Fallback / cross-check | Use when primary blocked or to confirm |
| **MANUAL VALIDATION** | Human-in-the-loop confirmation | **Required** before any finding is "real" |
| **OPTIONAL** | Nice-to-have, specialized | Only when it earns its noise/time |

## The cardinal rules

1. **An open port is not a vulnerability.** It is a question. Enumerate before you judge.
2. **A scanner result is a hypothesis, not a finding.** Nothing becomes a finding until a
   human validates it (version check + config check + safe PoC).
3. **Noise is a budget.** Every scan spends detectability and risk. Spend it deliberately —
   broad+quiet first, deep+loud only where justified.
4. **Everything is logged and evidenced in real time.** If it isn't in `logs/command-log.txt`
   and `evidence/`, it didn't happen.
5. **Default to the least-disruptive technique that answers the question.** Escalate
   intrusiveness only when the safer method can't resolve it — and only within RoE.

## The macro flow (every engagement)

```
CIDR list
  → Scope validation (00)
  → CIDR normalization & inventory (01)
  → Host discovery (03)           SAFE DISCOVERY
  → Port discovery (04)           SAFE DISCOVERY
  → Service enumeration (05–16)   SAFE DISCOVERY → CONTROLLED VALIDATION
  → Vulnerability discovery (17)  SAFE DISCOVERY
  → Manual validation (17)        CONTROLLED VALIDATION
  → Exploitation decision (18)    gated
  → Controlled exploitation (18)  CONTROLLED / may need approval
  → Privilege escalation (19)
  → Credential analysis (20)
  → Lateral movement (21)         often REQUIRES EXPLICIT RoE APPROVAL
  → Attack-path analysis (25)
  → Impact validation
  → Evidence collection (26)      continuous, not a phase
  → Reporting (28)
```

Evidence collection and tracking (CSVs) run **continuously** across all phases — they
are not a step at the end.

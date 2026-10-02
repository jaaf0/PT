# 17 — Vulnerability Scanning & Validation

> **Objective:** use scanners to cast a wide net, then **validate everything by hand** before it
> becomes a finding. **Risk:** unauth scans SAFE→CONTROLLED; some plugins are intrusive
> (**POTENTIALLY DISRUPTIVE** — disable "safe checks off").

## WHY scanners, and why you can't trust them

Scanners cover breadth no human can match, but they: (1) guess from banners (version-only
findings that may be back-ported/patched), (2) produce false positives, (3) miss logic/chained
issues (false negatives), and (4) duplicate findings. Your value is **validation and context**,
not running the scan.

## Tool roles

| Tool | Role | When |
|------|------|------|
| **Nmap NSE** | targeted vuln scripts | quick, specific checks (`--script vuln`) |
| **Nessus / OpenVAS(Greenbone)** | broad network vuln scan | the main sweep across the estate |
| **Nuclei** | templated web/CVE checks | fast, low-noise, great for web + known CVEs |
| Web scanners (Nikto, Burp scanner, ZAP) | web-specific | per web app (§10) |
| **Manual** | validation + logic + chaining | always, before any finding is final |

## The validation pipeline (non-negotiable)

```
Scanner finding
  → Version/config verification  (is the version really vulnerable? back-ported patch?)
  → Manual validation            (reproduce the condition yourself, safely)
  → Exploitability assessment    (is there a real, reachable path to impact?)
  → Impact assessment            (what does it actually get an attacker — §25)
  → Evidence                     (capture reproducible proof)
  → Finding                      (write it up — §28)
```

## Running the sweep safely

```bash
# Nmap NSE targeted:
nmap -sV --script "vuln and safe" -p <ports> -iL hosts.txt -oA scans/nse-vuln
# Nuclei (web):
nuclei -l web/httpx.txt -severity low,medium,high,critical -o scans/nuclei.txt
# Nessus/OpenVAS: configure a scan policy with:
#  - SAFE CHECKS ON (do not enable DoS/destructive plugins)
#  - throttled concurrency on fragile/MGMT VLANs
#  - credentialed scan where RoE provides creds (far fewer FPs)
```

**Credentialed scans** (RoE-provided creds) are dramatically more accurate (they read actual
patch levels) — prefer them when authorized; they cut version-only false positives massively.

## Interpreting scanner output

| Signal | Reality | Action |
|--------|---------|--------|
| "Critical" by CVSS base | severity ≠ exploitability in *this* environment | re-rate with context (§27) |
| Version-only detection | may be patched/back-ported (RHEL/Ubuntu) | verify real patch state before claiming |
| Many hosts, same plugin | systemic issue (good) or one bad signature (FP) | validate on 2–3, generalize |
| "Info"/"Low" clustered | sometimes chainable into something real | skim for chain ingredients |
| DoS/"denial" plugin flagged | do NOT auto-exploit | note, validate non-destructively only |

## False positives vs false negatives
- **FP sources:** banner spoofing, back-ported patches, WAF-mangled responses, auth walls the
  scanner couldn't pass. → Always confirm the vulnerable *condition*, not just the version.
- **FN sources:** custom app logic, chained issues, auth-gated areas, rate-limited scans. → Your
  manual testing (§10/§11) catches what scanners miss. Don't equate "clean scan" with "secure".
- **Duplicates:** the same root cause reported per-port/per-host — consolidate into one finding
  with an affected-assets list (§28).

## Decision flow
```
scanner hit
  ├─ version-only, can't verify patch → mark "unconfirmed", attempt safe proof; low confidence
  ├─ reproducible condition + reachable → VALIDATE → finding → §18 if exploitation adds proof
  ├─ false positive → log to scans/fp-log.md (so you don't re-chase it)
  └─ disruptive-only check (DoS) → report as exposure w/o exploitation
```

## Evidence
`scans/` raw outputs; `scans/fp-log.md` (dismissed FPs + why); per-validated-finding proof in
`evidence/`. Never let a scanner's severity flow straight into the report — re-rate in §27.

# OWASP Top 10 (2021) — ERP Web Testing Guide

Companion to `tools/10-owasp.sh`. For each category: **WHEN** you test it, **WHAT** to inspect,
**WHICH TOOL**, **WHAT indicates it**, **HOW to validate safely**, **EVIDENCE**, and the **ERP note**.
Automated/safe parts are done by the script; the manual + gated parts are yours in Burp.

> Posture: SAFE DISCOVERY and CONTROLLED validation only. No data mutation, no brute/spray, no
> exploitation on production without `APPROVAL_REF` + window. Prefer the **test** node for noisier checks.
> This is the **Web** Top 10; for pure APIs (SAP OData/Fiori, EBS REST) also use `playbook/11` (API Top 10).

---

## A01 — Broken Access Control  *(most impactful for ERP)*
- **When:** any authenticated app, any object reference, any admin path.
- **What:** IDOR/BOLA (object IDs), vertical escalation (user→admin function), forced browsing to
  consoles, path traversal, CORS misconfig.
- **Tool:** Burp (two test accounts), script does CORS + forced-browsing hints.
- **Indicator:** account A reads/acts on account B's object; a normal user reaches an admin page/API;
  `Access-Control-Allow-Origin` reflects arbitrary origin **with** credentials.
- **Safe validation:** prove with **2–3 objects**, never mass-scrape. Read-only confirmation.
- **Evidence:** req/resp pair showing A's session returning B's data; screenshot.
- **ERP note:** check SAP `/sap/bc/webdynpro`, `/sap/bc/gui`, `/sap/bc/bsp`, ICF services;
  Oracle EBS `/OA_HTML/`; WebLogic `/console`; SAP OData `$`-queries for other keys. Exposed admin
  consoles reachable unauthenticated = critical.

## A02 — Cryptographic Failures
- **When:** every HTTPS endpoint; any page handling credentials/PII/financial data.
- **What:** TLS version/ciphers, cert validity, HSTS, cookie flags (Secure/HttpOnly/SameSite),
  sensitive data sent in the clear or in URLs.
- **Tool:** `testssl.sh` (script runs it → `A02-tls.txt`), Burp for cookies/data.
- **Indicator:** TLS1.0/1.1, weak/CBC/RC4 ciphers, expired/self-signed cert, missing HSTS, cookies
  without Secure/HttpOnly, tokens in query strings.
- **Safe validation:** read-only; the scan is non-intrusive.
- **Evidence:** `A02-tls.txt`, screenshot of cookie flags.
- **ERP note:** legacy SAP kernels/Java stacks often negotiate weak TLS on ICM; flag per listener.

## A03 — Injection (SQLi / LDAP / OS cmd / XSS)
- **When:** any parameter reaching a DB, directory, shell, or rendered output.
- **What:** SQLi, LDAP injection, command injection, reflected/stored XSS.
- **Tool:** Burp (manual); `sqlmap` at **low** `--level/--risk` only; never auto against prod.
- **Indicator:** DB errors, boolean/time differences, unencoded input echoed back.
- **Safe validation:** **time-based or benign** proof only (`;sleep 5`, `<b>pt</b>`,
  `alert(document.domain)` in your own session). **No** `--dump`, stacked queries, `--os-shell`,
  or anything mutating data — that's exploitation (`playbook/18`, gated).
- **Evidence:** request + differential response (timing/error); XSS screenshot.
- **ERP note:** ERP params are often financial/master-data — a mistaken write is real damage. Keep
  injection PoCs strictly non-destructive; do heavier confirmation on the **test** node.

## A04 — Insecure Design (business logic)
- **When:** multi-step workflows — PO approval, payment runs, pricing, discounts, provisioning.
- **What:** step-skipping, negative/overflow quantities, race conditions, authorization-by-obscurity.
- **Tool:** manual + Burp (Repeater/Turbo at low rate).
- **Indicator:** the app enforces a rule in the UI but not server-side; you complete a flow out of order.
- **Safe validation:** reproduce in a **client-provided test account**; don't post real transactions.
- **Evidence:** annotated sequence of requests showing the bypass.
- **ERP note:** highest-value ERP findings live here (e.g., approve your own PO). Coordinate closely —
  never trigger a real financial posting; use sandbox/test clients.

## A05 — Security Misconfiguration
- **When:** every app, every server.
- **What:** missing security headers, verbose errors/stack traces, directory listing, default pages,
  dangerous HTTP methods (TRACE/PUT/DELETE), **default credentials**, exposed admin/debug endpoints.
- **Tool:** script (`A05-misconfig.txt`) + Burp; single default-cred try only.
- **Indicator:** absent HSTS/CSP/X-Frame-Options, `Server`/`X-Powered-By` version leak, open listing,
  debug/actuator endpoints, SAP verbose `/sap/public/info`.
- **Safe validation:** read-only; a **single** default-cred attempt per account (no brute — lockout).
- **Evidence:** header diff, screenshot of exposed page/error.
- **ERP note:** classic SAP/EBS defaults (`SAP*`,`DDIC`,`sysadmin`) → **lockout risk** → treat any
  credential testing as gated (`playbook/20`). Exposed WebLogic/Spring actuator = fast win.

## A06 — Vulnerable & Outdated Components
- **When:** after fingerprinting (`tools/05-web.sh`, `03-enum.sh`).
- **What:** known-CVE framework/app/server versions (SAP kernel, Struts/EBS, WebLogic, libs).
- **Tool:** `nuclei` (safe tags only → `A06-nuclei.txt`), `whatweb`, version→CVE lookup.
- **Indicator:** a version with a public CVE.
- **Safe validation:** **confirm the version and that it's reachable/really vulnerable** before
  claiming (back-ports patch silently). Running the actual exploit = `playbook/18` (gated; appliance/
  ERP exploits can crash services).
- **Evidence:** version banner + CVE reference + nuclei output.
- **ERP note:** Struts-on-EBS and WebLogic deserialization CVEs are high-impact but destructive to
  PoC — validate by version, exploit only with approval on a safe window/test node.

## A07 — Identification & Authentication Failures
- **When:** login, session, password reset, MFA, token handling.
- **What:** weak session IDs, no rotation on login, missing MFA, weak lockout, JWT flaws
  (`alg:none`, weak secret, no `exp`), credential stuffing exposure.
- **Tool:** Burp; `jwt_tool` for tokens (crack HS256 **offline**).
- **Indicator:** predictable/non-rotating session, token tamperable, no lockout.
- **Safe validation:** observe session/token behavior; tamper **your own** token; crack offline.
  **No brute force or password spraying** here — that's gated (`playbook/20`), and ERP lockout hits
  real users.
- **Evidence:** session/token analysis, JWT tamper req/resp.
- **ERP note:** confirm the lockout policy **before** any auth test; a careless probe locks named users.

## A08 — Software & Data Integrity Failures
- **When:** anything deserializing data, auto-updating, or running CI/CD.
- **What:** insecure deserialization (Java/.NET — pervasive in ERP), unsigned/auto updates,
  dependency/pipeline tampering, unverified plugins.
- **Tool:** Burp (identify serialized blobs: `rO0`, `AC ED 00 05`, ViewState), manual.
- **Indicator:** serialized objects accepted from the client; update channels without signatures.
- **Safe validation:** **identify** the sink and prove controllability with a benign marker; full
  gadget-chain RCE = `playbook/18` (gated — can crash the JVM/host).
- **Evidence:** the serialized payload location + benign PoC note.
- **ERP note:** Java deserialization in SAP/WebLogic is a known RCE class — demonstrate carefully,
  never fire a destabilizing gadget on production.

## A09 — Security Logging & Monitoring Failures
- **When:** throughout — it's measured by what your other actions did/didn't trigger.
- **What:** were your scans/logins/injections logged and alerted? any SOC response/block?
- **Tool:** your detection log (`playbook/24`), client SIEM/EDR debrief.
- **Indicator:** impactful actions produce no telemetry/alert.
- **Safe validation:** observational; **do not** tamper with logging to test it (gated/destructive).
- **Evidence:** `notes/detection-log.csv` mapping action→technique→detected? (MITRE IDs).
- **ERP note:** a powerful exec finding — "payroll-data access generated no alert".

## A10 — Server-Side Request Forgery (SSRF)
- **When:** any feature that fetches a URL (webhooks, import-from-URL, PDF/image render, link preview).
- **What:** server fetches attacker-controlled URLs; reaches internal services / cloud metadata.
- **Tool:** Burp + your own listener / Collaborator.
- **Indicator:** your listener gets a hit; internal/`169.254.169.254` responses returned.
- **Safe validation:** point at **your listener** or a benign internal check; read-only. Note internal
  reachability — don't pivot/attack internal infra under the SSRF without separate authorization.
- **Evidence:** request + your listener log / metadata response (redact secrets).
- **ERP note:** ERP integrations (IDoc/webservice connectors, report fetchers) are common SSRF sinks;
  internal SAP landscapes are highly interconnected, so SSRF impact can be large — report reach, gate exploitation.

---

## Run order
```bash
./tools/05-web.sh                 # builds engagement/web/urls.txt (git-ignored)
./tools/10-owasp.sh               # safe automated checks + per-app CHECKLIST.md
# then work engagement/web/owasp/CHECKLIST.md manually in Burp, app by app
```
Each confirmed issue → validate (`playbook/17`) → severity with rationale (`playbook/27`) →
finding (`playbook/28`) → does it extend an attack path? (`playbook/25`).

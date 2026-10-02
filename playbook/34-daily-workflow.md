# 34 — Daily Workflow (2–3 week engagement)

A realistic cadence. Phases **overlap** — discovery keeps running while you manually test; reporting
is drafted continuously, not crammed at the end. Adjust to scope size and findings.

## Week 1 — Discovery, enumeration, early footholds

**Day 1 — Setup & scope lock**
- Confirm RoE (§00); import scope; run `init-engagement.sh`; normalize CIDRs (§01).
- Share egress IPs with client; confirm windows, lockout policy, emergency contacts.
- Kick off **parallel host discovery** (§03) across all CIDRs (background).

**Day 2 — Port & service discovery**
- Quick port sweep (§04) on live hosts; version scan; selective UDP.
- Build `interesting.txt`; start full-TCP on key hosts (background).
- Begin categorizing: web, SMB/AD, DB, devices. Populate `services.csv`.

**Day 3 — Service enumeration + vuln scan kickoff**
- Per-service enumeration (§05–16): SMB null sessions, LDAP/AD terrain, web fingerprinting, DNS.
- Launch **credentialed vuln scan** (§17) if creds provided (runs in background for days).
- First **easy wins**: anon shares, default creds, exposed panels, Redis/NFS misconfig.

**Day 4 — AD mapping + web deep-dive begin**
- If domain: get any cred (AS-REP/anon LDAP/readable share) → BloodHound (§07).
- Start manual web testing on priority apps (§10) in Burp.
- Begin offline cracking of any captured hashes (continuous background).

**Day 5 — Foothold consolidation**
- Validate credentials; reuse-sweeps (§20, paced).
- First privesc attempts (§19) on footholds; harvest creds.
- Mid-engagement check-in with client POC; report any criticals *immediately* (don't wait for the report).

## Week 2 — Exploitation, privesc, lateral movement, attack paths

**Days 6–8 — Deepen access**
- Controlled exploitation of validated vulns (§18); privesc to SYSTEM/root (§19).
- Kerberoast/ADCS/DCSync-rights analysis (§07); crack + reuse loop.
- Lateral movement (§21) along BloodHound paths — each hop gated (§21 four gates).
- Continue web/API manual testing and business-logic testing (§10/§11).

**Days 9–10 — Prove impact + segmentation**
- Drive the top attack paths to the crown jewels; **stop escalating once impact is proven**.
- Run segmentation matrix (§22) across source/dest segments.
- Detection/response notes throughout (§24); network-device review (§23).
- Start drafting findings as they solidify (don't batch to the end).

## Week 3 — Validation, evidence, reporting

**Days 11–12 — Validate & evidence**
- Re-validate every finding; clear false positives (§17); finalize severities (§27).
- Complete evidence bundles (§26); ensure each finding is reproducible.
- Build attack-path diagrams (§25/§36).

**Days 13–14 — Report & cleanup**
- Write the report (§28): exec summary, attack paths, technical findings, remediation.
- **Cleanup**: remove all created artifacts (shells, accounts, test files, enabled features);
  verify against `cleanup-log.csv`.
- Peer/QA review of the report.

**Final day — Delivery & readout**
- Deliver report securely; conduct readout meeting (exec + technical tracks).
- Agree retest scope/timeline; confirm evidence retention/destruction per RoE.

## Overlap principle
```
Discovery ───────────────▶ (runs on, as new hosts appear)
   Enumeration ───────────────▶
      Vuln assessment ─────────────▶ (scans run for days in background)
         Manual testing ──────────────────▶
            Exploitation/privesc ──────────────▶
               Lateral/attack-paths ──────────────▶
Evidence  ●───●───●───●───●───●───●───●───●───●  (continuous, every day)
Reporting             ◆draft◆──draft──draft──────▶ FINAL
```
If you're waiting on a background scan, you should be manually testing something. Dead time is the
enemy of a fixed window.

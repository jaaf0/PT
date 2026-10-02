# 11 — API Testing

> **Observation:** REST/GraphQL/SOAP endpoints (from web discovery, JS files, mobile apps, or
> `/api`, `/v1`, `/swagger`). **Objective:** find broken authz, excessive data exposure, and
> logic flaws — the OWASP API Top 10 reality. **Risk:** CONTROLLED; same no-destruction rules as web.

## WHY APIs deserve their own chapter

APIs expose object-level operations directly, often with weaker authz than the UI (the UI hides
a button; the API doesn't). BOLA (broken object-level authz) is the #1 API risk and is trivial
to test but high impact. Swagger/OpenAPI frequently hands you the entire attack surface.

## Workflow

```
discover endpoints → find spec (swagger/openapi/graphql introspection) → auth model
→ test authz (BOLA/BFLA) → input validation → rate limits → JWT/OAuth/keys
→ sensitive data → methods → error handling → business logic
```

| Step | Objective | Tool | Command / action | Look for |
|------|-----------|------|------------------|----------|
| A1 | Find endpoints | katana/gau + Burp | crawl JS; `ffuf .../api/FUZZ` | route lists, versioned paths |
| A2 | Find the spec | browser/curl | `/swagger.json`,`/openapi.json`,`/api-docs`,`/graphql` (introspection) | full endpoint+schema map |
| A3 | Import spec → Burp | Burp + openapi parser | load spec, generate requests | every operation testable |
| A4 | Auth model | Burp | inspect tokens/keys/cookies | JWT? API key in header/query? OAuth? |
| A5 | **BOLA/IDOR** | Burp (2 accounts) | request user B's object id with user A's token | other users' data returned |
| A6 | **BFLA** (function-level) | Burp | call admin endpoints as normal user; change method | privileged action succeeds |
| A7 | Mass assignment | Burp | add extra JSON fields (`"role":"admin"`,`"isAdmin":true`) | privilege bump accepted |
| A8 | Excessive data exposure | Burp | read full objects | API returns more fields than UI (PII, hashes) |
| A9 | Input validation | Burp/sqlmap | inject into JSON/params | injection, type confusion |
| A10 | Rate limiting | Burp (throttled) | small controlled burst | no throttle on sensitive ops |
| A11 | JWT | jwt_tool | `alg:none`, weak secret, no `exp`, kid injection | forge/escalate token |
| A12 | OAuth | Burp | redirect_uri, state, scope, token leakage | ATO path |
| A13 | API keys | Burp/trufflehog | keys in JS/git/responses | valid key → access (validate minimally) |
| A14 | HTTP methods | curl | try `PUT/DELETE/PATCH` on read endpoints | unintended write/delete (don't actually destroy) |
| A15 | Error handling | Burp | malformed input | stack traces, internal paths, SQL errors |
| A16 | Business logic | manual | sequence/qty/price/workflow abuse | logic bypass (highest value) |

## How Burp fits
- **Proxy** the client (web/mobile) → populate sitemap with real traffic.
- **Repeater** for authz testing (swap tokens/IDs).
- **Intruder** (throttled) for ID ranges in BOLA (enumerate a *few* to prove, not to scrape).
- **Match/Replace** rules to auto-downgrade a token and detect missing authz.
- **Organizer/Logger** to keep request/response evidence per finding.

## Safe validation rules
- Prove BOLA/BFLA with the **minimum** objects (2–3), never a full enumeration/exfil.
- For destructive methods (DELETE/PUT), prefer a **test object you created**; never delete real
  records to "prove" it — a `405→200` on an unauthorized method call plus a dry-run is enough,
  and full exploitation is §18.
- Rate-limit testing = a small burst, never a brute force (lockout/DoS risk).

## Decision flow
```
BOLA confirmed → reaches PII/financial data? → high/critical finding → §25 impact
Mass assignment → role escalation? → test to admin in a throwaway account → finding
JWT weak secret → crack offline → forge within YOUR account → authz bypass finding
API key found → minimal validation (one benign call) → §20 track → scope impact
```

## Evidence
`web/<target>/api/` — spec file, Burp project, request/response pairs per finding, the two
account tokens used for BOLA proof (store tokens in `loot/`, not the repo).

# 22 — Network Segmentation Testing

> **Objective:** verify that network segmentation enforces the access controls the client
> believes are in place — i.e., which segments can reach which, on what ports.
> **Risk:** SAFE DISCOVERY (connectivity probing) — but only within authorized source positions.

## WHY

Segmentation is a core compensating control (PCI, zero-trust, OT isolation). "Flat networks"
turn one foothold into total compromise. Testing it means systematically probing *expected* vs
*observed* reachability from each source segment to each destination.

## Method: the reachability matrix

From a host/position in each **source** segment, probe each **destination** segment on key ports.

```bash
# From a foothold/jumpbox in SOURCE segment, probe DEST segment:
nmap -Pn -sS -p22,80,135,139,389,443,445,1433,3306,3389,5985 --max-rate 200 \
  -iL dest-hosts.txt -oA segmentation/src-<S>-to-dst-<D>
# Record: for each (src,dst,port) → reachable? (open/filtered)
```

## The matrix schema (`segmentation/matrix.csv`)

```
source_seg,dest_seg,port,proto,expected,observed,result,notes
USER,SERVER,445,tcp,allow,open,PASS,
USER,MGMT,443,tcp,deny,open,FAIL,"user VLAN can reach OOB mgmt — segmentation failure"
DMZ,SERVER,1433,tcp,deny,open,FAIL,"DMZ web can reach internal SQL directly"
USER,OT,502,tcp,deny,filtered,PASS,
```

| Column | Meaning |
|--------|---------|
| expected | what the client's policy/firewall rules *should* allow/deny |
| observed | what you actually saw (open/filtered) |
| result | PASS (observed matches expected) / FAIL (unexpected reachability) |

## Interpreting results
- **Observed `open` where `expected deny` = segmentation failure** → finding. Severity scales
  with destination sensitivity (USER→MGMT/OT/DC far worse than USER→print).
- **`filtered` where `deny` expected = PASS** (control working).
- **`open` where `allow` expected = PASS** (intended).
- Distinguish **intended communication** (documented business need) from **failure** (no rule
  should permit it) by checking against the client's firewall ruleset/policy — ask for it.

## Decision flow
```
unexpected reachability to sensitive segment (MGMT/OT/DC/PCI) → high-severity segmentation finding
  → does it enable a new attack path? → feed §21/§25
flat network (everything reaches everything) → systemic architectural finding
OT/ICS reachable from IT → critical safety finding → REPORT, do NOT probe OT devices actively
  (OT is fragile; active scanning can disrupt — REQUIRES EXPLICIT RoE APPROVAL for anything beyond
   a connectivity check)
```

## Safety
- Connectivity probing is light, but **throttle** and treat MGMT/OT gently. Reaching OT is a
  finding by itself — do not enumerate/scan OT devices without explicit approval.

## Evidence
`segmentation/matrix.csv`, the per-pair nmap outputs, and a rendered matrix/diagram (§36) for
the report. Note your source position for each probe (it's meaningless without it).

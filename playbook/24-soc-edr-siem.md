# 24 — SOC / EDR / SIEM / IDS-IPS / WAF Validation

> **Objective:** where the client wants it, measure the **detection & response** capability —
> did your actions generate telemetry, alerts, blocks, or a SOC response? This turns a pentest
> into a purple-team data source. **Risk:** observational; stays within RoE noise posture.

## WHY

Finding vulns tells the client what to fix; detection validation tells them whether they'd
*catch* a real attacker. For announced/collaborative engagements this is often as valuable as
the findings themselves.

## What to record (per notable action)

Maintain `notes/detection-log.csv`:
```
time_utc,action,host,technique_id,expected_telemetry,alert_generated,blocked,soc_responded,notes
2026-10-02T14:30Z,"LSASS dump",SRV14,T1003.001,"EDR cred-access alert",yes,no,no,"no SOC call in 1h"
2026-10-02T15:10Z,"psexec lateral",SRV22,T1021.002,"service-install 7045",unknown,no,no,
2026-10-02T15:40Z,"Kerberoast",DC01,T1558.003,"4769 RC4 TGS",?,no,no,
```

Map actions to **MITRE ATT&CK** technique IDs so the client can check their coverage matrix.

## Control-by-control

| Control | What to test (within RoE) | Signal of working control |
|---------|---------------------------|---------------------------|
| **EDR** | run known-flagged behaviors (LSASS access, in-memory tooling, PtH) | alert/kill/quarantine; your tool blocked |
| **SIEM** | perform loggable events (4625 bursts, 4688 odd procs, 4769 roast) | ask SOC if events/alerts fired |
| **IDS/IPS** | scanning, exploit sigs | RST/drop, alert, your source blocked |
| **WAF** | web payloads (§10) | 403/challenge/blocked payloads |
| **Firewall** | segmentation probes (§22) | drops, logged connections |

## Method (announced vs blind)
- **Announced / purple:** coordinate with SOC; timestamp each action; compare their detections to
  your log in a debrief. Highest learning value.
- **Blind (red-team):** stay within agreed noise; note whether you observed blocks/responses.
  **Do not attempt to disable, uninstall, or tamper with EDR/SIEM/logging** unless explicitly
  authorized — that is destructive and `REQUIRES EXPLICIT RoE APPROVAL`.

## Decision flow
```
action blocked by EDR/WAF/IPS → note as control WORKING → try an alternate (quieter) technique
action succeeded + no alert → DETECTION GAP finding (as valuable as a vuln)
SOC responds (you get a call / host isolated) → follow emergency procedure (§00); it's working
log tampering tempting → STOP; it's gated and destructive — report the gap instead
```

## Evidence
`notes/detection-log.csv`, screenshots of WAF/IPS blocks, the SOC debrief notes, and a coverage
summary (techniques tried vs detected) for the report (a gap table is powerful executive content).

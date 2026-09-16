# Password Spray Detection (Windows 4625 Correlation)

Detects likely password spraying based on bursts of failed logons (Event ID 4625) from a single source IP
attempting multiple usernames within a short time window.

This detection focuses on correlation logic (time-window + thresholds) rather than single-event matching.

## What this detects
- One source IP generates failed logons for many distinct users within N minutes
- Optional: highlights when attempts spread across multiple hosts

## Why it matters
Password spraying is common because it avoids account lockouts by trying a small number of passwords
across many accounts. Early detection can prevent account compromise.

## Data required
- Windows Security Event ID 4625 (failed logon)
- Fields commonly used:
  - src_ip (Source Network Address / IpAddress)
  - user (TargetUserName / Account Name)
  - host (destination)
  - LogonType, FailureReason/Status/SubStatus (optional context)

## How to validate (safe)
Generate a handful of failed logons against multiple test accounts from one source. Two options:
- **Live**: RDP/SMB auth attempts, or a local script trying multiple usernames with a wrong password against a lab VM
- **Simulated (used here)**: synthetic 4625 events pushed straight into Splunk via HTTP Event Collector (HEC) — see `evidence/` for the generation script and results. This avoids touching real auth infrastructure while still exercising the exact field shape (`EventCode`, `TargetUserName`, `IpAddress`) the correlation search expects.

You do NOT need to lock accounts; keep counts small and use lab accounts.

## Files in this detection package
- logic.md — thresholds + correlation approach
- mitre.md — MITRE mapping + rationale
- tuning.md — reduce noise (service accounts, scanners, misconfigs)
- query.spl — SPL correlation search (validated)
- query_v2.spl — sliding-window fix for block-edge evasion; **pending validation**
- playbook.md — triage: decision process, pivots, escalation thresholds, response
- evidence/ — HEC simulation script, raw ingested events, correlation search output, and validation notes

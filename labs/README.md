# windows-event-labs
Hands-on Windows security logging labs focused on SOC triage using Windows Security logs + Sysmon.

## Goals
- Understand high-signal Windows Event IDs (Security + Sysmon)
- Practice process + network correlation (who did what, from where, to where)
- Produce clean evidence screenshots and repeatable lab steps

## Labs
- [Lab 01: Sysmon Event ID 1](labs/lab-01-sysmon-process-create) — Process Create (process tree + command-line analysis)
- [Lab 02: Sysmon Event ID 3](labs/lab-02-sysmon-network-connect) — Network Connect (process ↔ destination correlation)
- [Lab 03: Windows Security 4624/4625](labs/lab-03-windows-logon-events) — Logon Success/Failure (brute-force patterns)

## Also here
- [`resources/`](resources) — Windows/Sysmon Event ID cheatsheet + screenshot conventions used across every lab
- [`writeups/`](writeups) — standalone notes from real troubleshooting/admin work (e.g. recovering Splunk admin access)

## Environment
- Windows 10/11 VM
- Sysmon installed with a community config (SwiftOnSecurity or similar)
- Event Viewer (baseline) and optional Splunk later

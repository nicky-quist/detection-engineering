# Detection Engineering

Detections built as a full chain: **a lab that generates the telemetry → an SPL detection validated against that telemetry → a triage playbook for the alert it raises**, all in one folder per technique so the three can't drift apart.

Most detection repos stop at the query. The query is the easy part. What makes a detection usable is knowing what telemetry it needs and how to produce it safely, what its false positives look like, and what an analyst does when it fires at 03:00. A threshold in the SPL and an escalation threshold in the playbook that disagree with each other is a bug, even if both look reasonable alone.

## Detections

| Technique | Lab (telemetry) | Detection | Playbook | Validated with |
|---|---|---|---|---|
| T1110.003 Password Spraying | [Lab 03 — 4624/4625](labs/lab-03-windows-logon-events) | [`password-spray-4625`](detections/password-spray-4625) | [playbook](detections/password-spray-4625/playbook.md) | Simulated 4625s via Splunk HEC |
| T1059.001 PowerShell | [Lab 01 — Sysmon EID 1](labs/lab-01-sysmon-process-create), [Lab 02 — Sysmon EID 3](labs/lab-02-sysmon-network-connect) | [`suspicious-powershell`](detections/suspicious-powershell) | [playbook](detections/suspicious-powershell/playbook.md) | Live Sysmon EID 1 event |
| T1136.001 Create Local Account | [Lab 05 — 4720/4732/4624](labs/lab-05-local-admin-creation) | [`local-admin-creation`](detections/local-admin-creation) | [playbook](detections/local-admin-creation/playbook.md) | Live 4720 → 4732 → 4624 sequence |

Every `query.spl` has been run against real or safely simulated event data, and each detection's `evidence/` shows it firing.

### Open: two defects found in review

Reading the validated queries line by line turned up two logic defects that the original validation didn't cover:

- **`password-spray-4625`** groups events into fixed 10-minute clock blocks, so a spray split across a block edge never reaches the threshold in either block. Pacing about 5 users per 10 minutes evades it entirely.
- **`local-admin-creation`** measures severity to the *last* logon in the search window, so the longer an attacker uses the account, the lower it scores. It also never checks that the steps happened in order.

Each has a corrected `query_v2.spl` that is **pending validation**. The v1 queries stay the detections of record until the fixes are proven in Splunk. [`validation/`](validation) has a scenario generator that reproduces both defects over HEC, with positive controls, and the expected result for every query/scenario pair.

## Also here

- **[`labs/`](labs)** — hands-on Windows Security, Sysmon, and network labs, including [Lab 04](labs/lab-04-recon-nmap-end-to-end): one Nmap scan followed through four layers (attacker, packets, Suricata, Splunk) to show what each layer does and doesn't see
- **[`investigations/`](investigations)** — the PCAP investigation method and case template: triage, flow analysis, timeline, IOCs, SIEM pivot, findings
- **[`resources/`](resources)** — Windows/Sysmon Event ID cheatsheet and screenshot conventions
- **[`writeups/`](writeups)** — notes from real troubleshooting (e.g. recovering Splunk admin access)
- **[`docs/playbook-format.md`](docs/playbook-format.md)** — the seven-section structure every playbook follows

## Layout

```
detections/<name>/
├── README.md       what it detects, why it matters, data required
├── query.spl       the validated correlation search
├── query_v2.spl    (where present) a fix pending validation
├── logic.md        detection logic and field quirks found during validation
├── mitre.md        ATT&CK mapping and rationale
├── tuning.md       false-positive sources and tuning knobs
├── playbook.md     triage: decision process, pivots, escalation, response
└── evidence/       validation notes and screenshots
labs/               procedures that generate each detection's telemetry
validation/         scenario tests for query changes
investigations/     PCAP case method and template
```

## Status, honestly

| Area | State |
|---|---|
| Three detections, their labs and playbooks | Complete, with evidence |
| `query_v2.spl` fixes | Written, self-checked, **not yet run in Splunk** |
| Lab 04 (Nmap end to end) | Procedure and detection logic written; **no captured evidence yet** |
| `investigations/` | Method and template only; **no completed case yet** |

## Roadmap

- Validate both `query_v2.spl` fixes and promote them
- A completed PCAP case in `investigations/`, run through the full method against a public capture
- Capture Lab 04 evidence: PCAP, Suricata `eve.json`, Splunk correlation output
- Service creation persistence (7045): user-writable paths, uncommon binaries
- Failed logons followed by success: credential-stuffing follow-through, distinct from spraying
- Suspicious outbound DNS: rare domains, high NXDOMAIN rate

---

*This repository consolidates what were previously five separate repos: `splunk-detections`, `soc-triage-playbooks`, `windows-event-labs`, `nmap-log-analysis`, and `pcap-investigations`. Their full commit history is preserved here.*

# PCAP Investigations

Network investigation case studies: given a packet capture, work it the way a SOC analyst would — identify the suspicious activity, build a timeline, pull IOCs, and connect it back to a SIEM-side detection.

## Methodology

Every case follows the same structure, documented end-to-end rather than just showing a final answer:

1. **Initial triage** — what drew attention to this traffic (alert, anomaly, manual hunt)
2. **Protocol/flow analysis** — Wireshark/tshark breakdown of the relevant conversations
3. **Timeline** — sequence of events with timestamps
4. **IOCs** — IPs, domains, hashes, JA3/JA4, user-agents, anything reusable for detection
5. **SIEM pivot** — how this traffic would appear in Splunk/Suricata logs, and what detection would have caught it (cross-referenced against [`splunk-detections`](https://github.com/nicky-quist/splunk-detections) where applicable)
6. **Findings** — root cause, scope, and recommended response

## Structure

```
cases/
└── <case-name>/
    ├── README.md       # full writeup following the methodology above
    ├── timeline.md
    ├── iocs.md
    └── screenshots/
```

See [`cases/TEMPLATE`](cases/TEMPLATE) for the blank structure used to start a new case.

## Status

Scaffolding in place; first case write-up in progress. Planned sources: public training captures (e.g. malware-traffic-analysis.net) and PCAPs pulled from my own [LetsDefend](https://app.letsdefend.io/user/quist) / [Hack The Box](https://profile.hackthebox.com/profile/019c498b-e549-7061-b8cd-6586b4980ed0) lab work.

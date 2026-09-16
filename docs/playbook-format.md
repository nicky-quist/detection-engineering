# SOC Triage Playbooks

Alert triage checklists: a 5-minute decision process, copy/paste SIEM pivots, escalation thresholds, and response actions — for the alert types I've built detections for.

Each playbook is paired with the detection that generates the alert, so the logic behind the pivot and the logic behind the escalation threshold stay consistent with each other.

## Playbooks
| Playbook | Paired detection |
|---|---|
| [`suspicious-powershell.md`](playbooks/suspicious-powershell.md) | [`splunk-detections/suspicious-powershell`](https://github.com/nicky-quist/splunk-detections/tree/main/detections/suspicious-powershell) |
| [`password-spray.md`](playbooks/password-spray.md) | [`splunk-detections/password-spray-4625`](https://github.com/nicky-quist/splunk-detections/tree/main/detections/password-spray-4625) |

## Format
Every playbook follows the same shape:
1. **Alert intent** — what the alert means and why it fires
2. **Required evidence** — the fields an analyst needs before triaging
3. **Triage** — a fast, structured decision process
4. **Immediate pivots** — copy/paste SIEM searches to answer the next question
5. **Escalation thresholds** — a table mapping signal combinations to disposition
6. **Response actions** — concrete containment/remediation steps if escalated
7. **Closing the alert** — what to document so the next analyst (or the detection itself) benefits

## Roadmap
- Local admin creation + first-logon correlation (pairs with `splunk-detections/local-admin-creation`)
- Service creation persistence
- Suspicious outbound DNS

# Local Admin Creation + First-Logon Correlation

Detects the sequence of a local account being created, added to the local Administrators group, and then logged into — a common pattern for adversaries establishing access that doesn't rely on domain credentials.

## What this detects
A single account (`sid`) observed going through, in order:
1. Account creation (4720)
2. Addition to the local Administrators group (4732, `TargetSid=S-1-5-32-544`)
3. First logon (4624)

Severity is scored by how tightly clustered the sequence is — a fast create → elevate → logon chain is more suspicious than one spread over hours.

## Why it matters
Routine provisioning also creates local admins, but rarely all three steps in a short window on the same SID. Adversaries doing this manually or via a script tend to compress the whole chain, and using a local account avoids domain-level detections and lockout policies.

## Data required
- Windows Security Event ID 4720 (user account created)
- Windows Security Event ID 4732 (member added to a security-enabled local group)
- Windows Security Event ID 4624 (successful logon)

## Files in this detection package
- `logic.md` — field quirks discovered during validation (SID vs. username correlation)
- `mitre.md` — MITRE mapping + rationale
- `tuning.md` — validation results and severity thresholds
- `query.spl` — SPL correlation search (validated)
- `query_v2.spl` — fixes severity decay and step ordering; **pending validation**
- `playbook.md` — triage: decision process, pivots, escalation thresholds, response
- `evidence-local-admin-creation-splunk-results.jpeg` — validated results from a live test (create → elevate → logon)

## Recommended investigation pivots
- Who created the account, and was it authorized change/provisioning?
- Source host/IP of the first logon — expected admin workstation or something new?
- Any activity immediately following first logon (lateral movement, credential access, persistence)?

## Response guidance
If not tied to an approved provisioning ticket:
- Disable the account pending investigation
- Review the creating account's recent activity for other unauthorized changes
- Check for the same pattern on other hosts (may indicate scripted/repeated deployment)

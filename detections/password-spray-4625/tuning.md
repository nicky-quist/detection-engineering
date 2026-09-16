# Tuning & False Positives

## Common false positives
- Vulnerability scanners / pentest tools
- Misconfigured services repeatedly attempting auth
- Users forgetting passwords (usually 1 user, not many)
- MFA / SSO / sync issues causing bursts

## Recommended tuning steps
1) Baseline:
   - Typical number of 4625s per hour/day
   - Typical top source IPs for failures

2) Filter noise:
   - Exclude known scanner IPs
   - Exclude known management/bastion hosts if expected
   - Exclude service accounts if they cause recurring issues (but investigate first)

3) Raise confidence:
   - Require distinct users >= X
   - Require attempts across >= 2 hosts
   - Require Status/SubStatus indicates "bad password" more than "user doesn't exist"

## Known limitation: fixed time blocks
`query.spl` uses `bucket _time span=10m`, which splits time into fixed clock blocks. A spray that crosses a block edge is divided, and neither half may reach the threshold, so a spray paced at about 5 users per 10 minutes is never detected. [`query_v2.spl`](query_v2.spl) replaces the fixed blocks with a sliding window and is **pending validation**; see [`validation/`](../../validation).

## Tuning knobs
- Time window: 5m / 10m / 15m
- Threshold attempts: 8 / 15 / 25
- Distinct users: 6 / 10 / 15
- Distinct hosts: 1 / 2 / 3

## Escalation guidance
Escalate quickly if:
- Same src_ip is spraying multiple hosts
- Followed by a successful logon (4624) from same src_ip
- Followed by privilege activity (4720/4728/4672 etc.)

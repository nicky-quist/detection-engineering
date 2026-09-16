# Playbook: Password Spray (Windows 4625 Correlation)

## Alert intent
One source generating failed logons (4625) against many distinct usernames in a short window — an attempt to avoid lockouts by trying few passwords across many accounts rather than many passwords against one account.

## Required evidence
- Source IP
- Distinct usernames targeted, and count of failures per user
- Destination host(s)
- Time window and burst pattern
- Status/SubStatus codes (bad password vs. account doesn't exist vs. locked out)

## Triage (5-minute decision)
### 1) Confirm the pattern
Real spraying looks like: one `src_ip`, `distinct_users >= 6`, `failures >= 8`, within a 10-minute window (see [`query.spl`](query.spl) for the correlation search and [`tuning.md`](tuning.md) for the thresholds).

### 2) Rule out common false positives first
- Vulnerability scanner or pentest IP (check against known scanner list)
- Misconfigured service repeatedly authenticating with a stale credential (usually **one** user, not many — should not match the pattern)
- SSO/MFA sync issue causing bursts across otherwise normal logins

### 3) Check Status/SubStatus
- `0xC000006A` (bad password) across many users → consistent with spraying
- `0xC0000064` (user does not exist) → consistent with username enumeration, treat as reconnaissance
- `0xC0000234` (account locked out) → spray already causing operational impact, escalate priority

## Immediate pivots (Splunk) — copy/paste searches

### Pivot 1 — Did the source IP get in anywhere? (highest priority check)
```spl
index=* sourcetype=WinEventLog:Security EventCode=4624
| eval src_ip=coalesce(src_ip, Source_Network_Address, IpAddress)
| where src_ip="<PUT_SRC_IP_HERE>"
| table _time src_ip user host LogonType
| sort 0 _time
```
If this returns **any** result, treat as a likely compromise, not just a spray attempt — jump straight to escalation.

### Pivot 2 — Full scope: every user/host this source touched
```spl
index=* sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval src_ip=coalesce(src_ip, Source_Network_Address, IpAddress)
| eval user=lower(coalesce(user, TargetUserName, Account_Name))
| where src_ip="<PUT_SRC_IP_HERE>"
| stats count by EventCode user host
| sort - count
```

### Pivot 3 — Follow-on privileged activity for any user that succeeded
```spl
index=* sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4728 OR EventCode=4672)
| where user="<PUT_USER_HERE>"
| table _time EventCode user host
```

## Escalation thresholds
| Signal combination | Disposition |
|---|---|
| Spray pattern with a subsequent 4624 success from the same source | **Escalate immediately** — treat as active compromise, not just an attempt |
| Spray pattern, `distinct_users >= 12` or spread across 3+ hosts, no success | **Escalate** — high-confidence targeted spray, block source, force-monitor targeted accounts |
| Small burst (6-8 users), single host, no success | **Monitor** — could be early-stage spray, re-check in next window before closing |
| Single user, repeated bad-password failures | **Close as benign** — user error or stale saved credential, not a spray |

## Response actions (if escalated)
1. Block the source IP at the perimeter
2. Force password reset / session revocation for any targeted account with a subsequent success
3. Verify no "Accepted password" entries follow for any targeted account
4. Check whether MFA would have stopped a successful spray hit — flag accounts without MFA enrolled
5. Feed the source IP and targeted-account list back into detection tuning if this is a recurring source

## Closing the alert
Document: final disposition, whether any account showed a successful logon, and any perimeter/account changes made. If this is the third+ spray from the same IP range, flag it for a standing block rather than re-triaging from scratch each time.

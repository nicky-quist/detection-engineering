# Playbook: Local Admin Creation + First Logon

## Alert intent
A local account was created, added to the local Administrators group (`S-1-5-32-544`), and then logged into, all on one SID and in a short window. Adversaries compress that chain because a local admin account gives them access that doesn't depend on domain credentials and doesn't hit domain lockout policy. Legitimate provisioning also creates local admins, but rarely does all three steps within minutes.

## Required evidence
- Account SID and username
- Host the account was created on
- **Who created it**: `SubjectUserName` / `SubjectUserSid` on the 4720
- Time of each step: created, added to Administrators, first logon, and the span between them
- Logon type and source address of the first logon
- Whether a change or provisioning ticket covers the account

## Triage (5-minute decision)
### 1) Confirm the chain is real
Join on **SID, not username**. 4732 frequently leaves `MemberName` empty, and only `MemberSid` is reliable (see [`logic.md`](logic.md)). Confirm the 4732 is for `TargetSid=S-1-5-32-544` specifically. Every new account also gets a 4732 for the default Users group, and that one means nothing.

### 2) Check the creator before anything else
The creating account matters more than the new one:
- A known admin on their usual workstation during business hours → likely provisioning, so look for the ticket
- A service account, a standard user, `SYSTEM` via an unexpected parent, or an admin at 03:00 → the creator may already be compromised, and the new account is the persistence

### 3) Read the span correctly
Severity is scored on the span from creation to first logon: ≤15 min is high, ≤30 min is medium. The validation test ran at 16 minutes and scored medium. A human admin clicking through a GUI can land anywhere in that range, so the span alone is not a verdict. Weigh it with the creator and the logon type.

> **Known limitation of the current query.** `span_min` is measured to the *last* 4624 in the search window, not the first. An account that keeps logging in will look older and slower than it really is, so its severity drops the more an attacker uses it. Check the raw 4624s yourself before trusting a `low`. [`query_v2.spl`](query_v2.spl) fixes this and is pending validation. See [`validation/`](../../validation).

## Immediate pivots (Splunk) — copy/paste searches

### Pivot 1 — Who created the account, from where?
```spl
index=* sourcetype=*wineventlog*security* EventCode=4720
| where TargetUserSid="<PUT_SID_HERE>"
| table _time host SubjectUserName SubjectUserSid SubjectDomainName TargetUserName
```

### Pivot 2 — What did the creator do in the hour around it?
```spl
index=* sourcetype=*wineventlog*security* (EventCode=4720 OR EventCode=4722 OR EventCode=4724 OR EventCode=4732 OR EventCode=4728 OR EventCode=4688)
| where SubjectUserSid="<PUT_CREATOR_SID_HERE>"
| table _time host EventCode TargetUserName NewProcessName CommandLine
| sort 0 _time
```
Look for several accounts created in a row (4720), passwords reset on other accounts (4724), domain group changes (4728), or tooling launched just before the create (`net.exe user /add`, `net localgroup administrators /add`, PowerShell `New-LocalUser`).

### Pivot 3 — What did the new account do once it logged in?
```spl
index=* sourcetype=*wineventlog*security* (EventCode=4624 OR EventCode=4688 OR EventCode=4672)
| eval sid=coalesce(TargetUserSid, SubjectUserSid)
| where sid="<PUT_SID_HERE>"
| table _time host EventCode LogonType IpAddress NewProcessName CommandLine
| sort 0 _time
```
4672 (special privileges assigned at logon) confirms the account used its admin rights. Logon type 10 (RDP) or 3 (network) from an unfamiliar source is more concerning than type 2 at the console.

### Pivot 4 — Is this happening on other hosts?
```spl
index=* sourcetype=*wineventlog*security* EventCode=4732 TargetSid="S-1-5-32-544"
| stats dc(host) as hosts values(host) as host_list values(SubjectUserName) as added_by by MemberSid
| where hosts > 1
```
The same creator adding admins on several hosts in a short period suggests a script or a hands-on intrusion moving host to host.

## Escalation thresholds
| Signal combination | Disposition |
|---|---|
| Creator is not an authorized admin, **or** the account ran discovery or credential tooling after logon | **Escalate immediately.** Treat as active intrusion with persistence |
| Chain within 15 min, no ticket, first logon over RDP/network from a non-admin workstation | **Escalate.** Disable the account while the creator is investigated |
| Same creator adding local admins on multiple hosts, no ticket | **Escalate.** Likely scripted deployment by an attacker, so scope every host |
| Authorized admin, matching ticket, console logon, nothing notable afterwards | **Close as benign.** Provisioning |
| Authorized admin, no ticket yet, otherwise clean | **Hold.** Ask the admin and the change owner before closing; don't escalate on a missing ticket alone |

## Response actions (if escalated)
1. Disable the new account (don't delete it: the SID, profile, and artifacts are evidence)
2. Investigate the **creator** account as compromised: reset its credentials and revoke its sessions
3. Pull the process tree around the 4720 on the host to find what actually ran the create
4. Run Pivot 4 across the estate and repeat steps 1–3 for every host it returns
5. Hunt for other persistence the same actor may have added: services (7045), scheduled tasks (4698), Run keys
6. If the local admin password is shared across hosts, rotate it (LAPS should make this a non-issue)

## Closing the alert
Record the disposition, the creator, and the ticket number if benign. If a legitimate provisioning workflow keeps tripping this, don't tune by excluding the creator outright, because that hides exactly the case where the creator is compromised. Scope the exclusion to that creator **and** the provisioning host **and** a naming convention for the new account, and note it in [`tuning.md`](tuning.md).

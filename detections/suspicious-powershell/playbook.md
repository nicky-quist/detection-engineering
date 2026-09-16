# Playbook: Suspicious PowerShell (Encoded/Obfuscated/Download)

## Alert intent
Detect potentially malicious PowerShell execution patterns commonly used for staging, payload retrieval, and fileless execution.

## Required evidence
- Hostname
- Username
- Parent process (image + command line if available)
- PowerShell command line
- Time of execution
- Any outbound network activity shortly after execution (proxy/DNS/EDR net events)

## Triage (5-minute decision)
### 1) Confirm the signal
High confidence if you see any of these:
- `-enc` / `-encodedcommand`
- `-w hidden` / `-windowstyle hidden`
- `-executionpolicy bypass`
- `IEX` / `Invoke-Expression`
- `DownloadString`, `WebClient`, `Invoke-WebRequest (iwr)`, `Invoke-RestMethod (irm)`, `Start-BitsTransfer`

### 2) Check parent process (most important)
**Suspicious parents:**
- `winword.exe`, `excel.exe`, `outlook.exe`
- browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`)
- `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`

**More likely benign:**
- `explorer.exe` (interactive admin usage)
- known deployment tools (SCCM/Intune/PDQ/Tanium/etc.)

### 3) User/host context
- Is the user an admin, IT automation account, or standard user?
- Is this host a server, admin workstation, or standard endpoint?
- Has this host/user generated similar alerts before?

## Immediate pivots (Splunk) — copy/paste searches

> Note: field names vary by environment. These searches use `coalesce()` so they work with Sysmon (EventCode=1), Security 4688, or EDR-like fields.

### Pivot 1 — Same host: all PowerShell executions (last 24h)
```spl
(index=* (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 OR sourcetype="WinEventLog:Security" EventCode=4688))
| eval Image=coalesce(Image, NewProcessName, ProcessName, process_path)
| eval CommandLine=coalesce(CommandLine, ProcessCommandLine, Process_Command_Line, command_line)
| eval ParentImage=coalesce(ParentImage, Creator_Process_Name, ParentProcessName, parent_process)
| where host="<PUT_HOST_HERE>" AND (like(lower(Image), "%\\powershell.exe") OR like(lower(Image), "%\\pwsh.exe"))
| table _time host user ParentImage Image CommandLine
| sort 0 _time
```

### Pivot 2 — Same user: activity across all hosts (last 24h)
```spl
(index=* (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 OR sourcetype="WinEventLog:Security" EventCode=4688))
| eval User=coalesce(User, user, AccountName, SubjectUserName)
| where User="<PUT_USER_HERE>"
| table _time host User Image CommandLine
| sort 0 _time
```

### Pivot 3 — Network activity from the host shortly after execution
```spl
index=* sourcetype=*proxy* OR sourcetype=*dns* OR sourcetype=*firewall*
| where host="<PUT_HOST_HERE>"
| table _time host dest_ip dest_port url domain action
| sort 0 _time
```

## Escalation thresholds
| Signal combination | Disposition |
|---|---|
| Encoded command + download cradle (IEX/WebClient/iwr/irm) | **Escalate immediately** — high-confidence loader pattern |
| Hidden window + execution policy bypass, no download indicator | **Escalate** — likely staging, confirm parent process |
| Single flag only (e.g. `-NoProfile`), known admin parent/account | **Close as benign** — document and move on |
| Any flag + parent is Office app or browser | **Escalate immediately** regardless of other context — classic macro/phishing execution chain |
| Suspicious flags but from a known deployment tool parent (SCCM/Intune/PDQ) | **Verify against change record**, close if confirmed, escalate if not |

## Response actions (if escalated)
1. Isolate the host (EDR containment) if malicious intent is likely
2. Capture the full process tree and command line (decode any `-EncodedCommand` payload)
3. Collect PowerShell script block logs if enabled
4. Hunt the same command-line pattern and any extracted IOCs across the environment
5. Check for persistence (Run keys, scheduled tasks) and lateral movement from the host
6. If confirmed malicious, feed the IOCs and pattern back into this detection's [`tuning.md`](tuning.md)

## Closing the alert
Document: final disposition (true positive / false positive / benign-confirmed), evidence reviewed, and any tuning change made as a result. A closed alert that doesn't reduce future noise or improve detection is a missed opportunity, not just a completed ticket.

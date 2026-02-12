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

## Immediate pivots (Splunk)
Use these pivots even if you don’t have Sysmon everywhere.

### Pivot A — other PowerShell executions on the same host (last 24h)
Search for the same host + powershell and review command lines.

### Pivot B — same command-line indicators org-wide (last 24h)
Search for `-enc` / `downloadstring` / `invoke-webrequest` patterns across all hosts.

### Pivot C — follow-on behavior (last 30 min)
Look for:
- new processes spawned after PowerShell (cmd, rundll32, mshta, regsvr32, wscript/cscript)
- any network connections (proxy/DNS) after execution
- file writes to Temp/AppData/Downloads (if you ingest that telemetry)

## Decision points
### Mark as False Positive if:
- Known admin automation account + known management parent process
- Script path + behavior matches documented IT task
- No suspicious follow-on behavior and command is explainable

### Escalate to Incident if:
- Encoded/hidden + download cradle combo
- Office/browser as parent process
- External network retrieval + new executable/script dropped
- PowerShell spawns LOLBins or suspicious children
- Repeated hits across multiple hosts/users

## Containment / response (if confirmed suspicious)
- Isolate host in EDR (if available)
- Block known-bad domain/IP/hash (per your process)
- Acquire process tree + full command line + any script content
- Hunt for same indicators across enterprise

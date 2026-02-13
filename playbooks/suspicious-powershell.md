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

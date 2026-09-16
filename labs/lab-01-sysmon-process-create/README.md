# Lab 01 — Sysmon Event ID 1 (Process Create)
Goal: Learn how to investigate suspicious process execution using Sysmon Process Create events.

## What you’ll learn
- How to read `Image`, `CommandLine`, `ParentImage`, `User`, `Hashes`
- How to build a simple process tree story (parent → child)
- What “normal” vs “suspicious” execution looks like

## Setup
- Windows VM
- Sysmon installed
- Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational

## Steps
### 1) Generate baseline events
Open PowerShell and run:
- `notepad.exe`
- `calc.exe`
- `whoami`
- `ipconfig /all`

### 2) Generate “suspicious-ish” test events (safe)
Run these commands to create realistic telemetry:
- `powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Select -First 5"`
- `powershell -NoProfile -Command "IEX('Write-Output test')"` (benign but looks like IEX usage)
- `cmd.exe /c ping 8.8.8.8`

### 3) Collect evidence in Event Viewer
Filter Sysmon logs for **Event ID 1**.
Capture screenshots of 3 events:
- one normal app (e.g., notepad)
- one PowerShell event
- one cmd.exe event

For each screenshot, make sure the fields are visible:
- Image
- CommandLine
- ParentImage
- User
- Hashes (if present)

Save to: `evidence/`
Recommended filenames:
- `01-notepad-process-create.png`
- `02-powershell-process-create.png`
- `03-cmd-process-create.png`

## Notes (what to write under each screenshot)
For each event, answer:
- What executed? (Image)
- Who ran it? (User)
- From what parent process? (ParentImage)
- What exactly ran? (CommandLine)
- Why is it normal or suspicious?

## Key takeaways
- CommandLine + ParentImage usually tell the story.
- PowerShell with flags like `-enc`, `IEX`, `DownloadString`, `Bypass` are common detection signals.

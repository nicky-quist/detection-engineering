# Lab 03 — Windows Security Events 4624/4625 (Logon Success/Failure)
Goal: Understand logon telemetry and recognize brute force / password spray patterns.

## Setup
Event Viewer → Windows Logs → Security

## Steps
### 1) Generate 4625 failures (safe)
- Lock the screen and intentionally type a wrong password 3–5 times
OR
- Try logging in with a wrong password for a local account

### 2) Generate a 4624 success
- Log in normally after failures

### 3) Collect evidence
Filter Security log for:
- Event ID **4625** (failed)
- Event ID **4624** (success)

Capture 2 screenshots:
- one 4625 failure event showing:
  - Account Name
  - Failure Reason / Status
  - Logon Type
  - Workstation Name / Source Network Address (if present)
- one 4624 success event showing:
  - Account Name
  - Logon Type
  - Authentication details

Save to: `evidence/`
- `01-4625-failed-logon.png`
- `02-4624-success-logon.png`

## Notes (what to write)
- Explain **Logon Type** (interactive vs remote vs service)
- Describe what a brute force pattern would look like:
  - many 4625s for same account
  - many 4625s across many accounts from one source (spray)
  - followed by 4624 success

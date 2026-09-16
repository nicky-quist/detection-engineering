# Splunk Admin Password Reset (Windows)

## Goal
Restore admin access to Splunk Enterprise without reinstalling.

## Steps (Splunk 7.1+)
1. Stop Splunk (`splunk.exe stop`)
2. Backup `C:\Program Files\Splunk\etc\passwd` → `passwd.bk`
3. Create `C:\Program Files\Splunk\etc\system\local\user-seed.conf`:
   ```ini
   [user_info]
   PASSWORD = <new_password>
Start Splunk (splunk.exe start)

Login to http://localhost:8000 as admin

Remove/rename user-seed.conf after successful login

Notes / gotchas
Save file as All Files (.) to avoid user-seed.conf.txt

Ensure correct directory: etc\system\local\

Password complexity enforced in newer Splunk versions

Validation
Successful login to Splunk Web

splunk.exe status reports splunkd running
---

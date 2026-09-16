# Lab 05 — Local Admin Creation (4720 / 4732 / 4624)
Goal: Generate the create → elevate → log on sequence that [`local-admin-creation`](../../detections/local-admin-creation) detects, and see the field quirks that shaped its correlation logic.

## Setup
- A **lab** Windows 10/11 VM you can snapshot. Take the snapshot first.
- Audit policy must record account management and logons. Check from an elevated prompt:
  ```
  auditpol /get /subcategory:"User Account Management","Security Group Management","Logon"
  ```
  All three should show `Success`. If not:
  ```
  auditpol /set /subcategory:"User Account Management" /success:enable
  auditpol /set /subcategory:"Security Group Management" /success:enable
  auditpol /set /subcategory:"Logon" /success:enable
  ```
- Event Viewer → Windows Logs → Security, or Splunk if the VM forwards its Security log

## Steps
Run from an **elevated** prompt. Note the time before each step, since the detection's severity depends on the gaps.

### 1) Create the account → 4720
```
net user labtest01 <a-lab-only-password> /add
```

### 2) Add it to local Administrators → 4732
```
net localgroup Administrators labtest01 /add
```
Creating the account already produced a 4732 for the **Users** group. This one is for **Administrators**. Compare the two.

### 3) Log on as the account → 4624
Sign out and log in as `labtest01`, or from the existing session:
```
runas /user:labtest01 cmd
```

### 4) Collect evidence
Filter the Security log for 4720, 4732, and 4624, and capture:
- the **4720** showing the new account's SID and `Subject` (who created it)
- **both 4732s**, side by side, showing the group SID for Users (`S-1-5-32-545`) and Administrators (`S-1-5-32-544`)
- the **4624** for `labtest01`, showing Logon Type

Save to: `evidence/`
- `01-4720-account-created.png`
- `02-4732-users-vs-administrators.png`
- `03-4624-first-logon.png`

### 5) Run the detection
Run [`query.spl`](../../detections/local-admin-creation/query.spl) over a range covering the steps and screenshot the result as `04-detection-hit.png`. Record the observed span. The existing validation measured 16 minutes and scored `medium`.

### 6) Clean up
```
net user labtest01 /delete
```
Or revert to the snapshot.

## Notes (what to write)
- **Why the query joins on SID, not username.** Look at `Member: Account Name` on the 4732. It's often blank or `-`, while `Member: Security ID` is always filled in. A username join would silently miss the elevation step.
- **Why it filters `TargetSid=S-1-5-32-544`.** Without that filter, the automatic Users-group 4732 from step 1 would count as "elevation", and every new account would look like a new admin.
- **Read the span against the defect.** Log on as `labtest01` a second time, 20+ minutes later, and re-run the query. The span grows and the severity drops even though nothing about the original chain changed. That's the defect that [`query_v2.spl`](../../detections/local-admin-creation/query_v2.spl) fixes; see [`validation/`](../../validation).
- Which Logon Type did step 3 produce, and why would 10 (RDP) or 3 (network) be more concerning than 2 (interactive)?

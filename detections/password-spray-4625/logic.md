# Detection logic

## Core idea
Password spraying is typically:
- One source (IP / workstation) 
- Many distinct usernames
- Within a short time window
- Often with consistent failure codes

## Default correlation rule (starter)
Within 10 minutes:
- src_ip has >= 8 failed logons (4625)
- AND distinct users >= 6

These are starter thresholds for a lab / small environment.
In production, tune based on baseline volumes and lockout policy.

## Helpful context fields
- LogonType:
  - 3 = network (SMB)
  - 10 = remote interactive (RDP)
- Status/SubStatus:
  - 0xC000006A = bad password
  - 0xC0000064 = user does not exist
  - 0xC0000234 = account locked out

## Severity guidance
HIGH when:
- distinct users is high (12+, matching `query.spl` and the playbook)
- attempts hit multiple hosts
- failures indicate "bad password" more than "user doesn't exist"
- happens outside business hours

MED when:
- small number of users but repeated bursts
- likely misconfiguration (single service account typo) until confirmed

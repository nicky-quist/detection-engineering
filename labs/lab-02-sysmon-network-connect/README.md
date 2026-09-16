# Lab 02 — Sysmon Event ID 3 (Network Connect)
Goal: Correlate network activity to the exact process that initiated it.

## What you’ll learn
- How to read `Image`, `DestinationIp`, `DestinationHostname` (if present), `DestinationPort`, `Protocol`
- Why process-to-network correlation matters in SOC triage

## Steps
### 1) Generate network telemetry
Run these from PowerShell:
- `ping 1.1.1.1`
- `nslookup google.com`
- `curl https://example.com` (Windows 10/11 usually has curl)

Optional:
- Open a browser and visit `https://example.com`

### 2) Collect Event ID 3 evidence
Event Viewer → Sysmon Operational → filter **Event ID 3**.

Capture screenshots for:
- ping (ICMP might not always show as Sysmon network connect — if not, use curl/browser)
- nslookup (may show DNS related events separately; if you have Event ID 22 enabled, grab it too)
- curl or browser connection

Save to: `evidence/`
- `01-curl-network-connect.png`
- `02-browser-network-connect.png`
- `03-nslookup-or-dns.png` (if applicable)

## Mini write-up
For each screenshot:
- What process initiated the connection? (Image)
- Where did it connect? (Destination)
- What port/protocol?
- Is it expected for this process?

## Key takeaways
- “Bad IP” alone isn’t enough — the initiating process is what lets you respond.

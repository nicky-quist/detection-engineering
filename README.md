# nmap-log-analysis

SOC project: detect reconnaissance activity end-to-end, across the whole telemetry chain — from the raw scan, to the packets, to the IDS alert, to the SIEM correlation. The goal is to see the same event from four different vantage points and understand what each layer actually gives an analyst.

## Why this project
Most "detect an Nmap scan" writeups stop at one tool. This walks the full chain on purpose:
1. **Nmap** generates the recon traffic (attacker's view)
2. **Wireshark** captures and inspects the raw packets (ground truth)
3. **Suricata** raises an IDS alert on the traffic (detection layer)
4. **Splunk** correlates the alert with other telemetry (SOC/response layer)

Understanding what each layer sees — and what it misses — matters more than any single detection.

## Lab

### 1. Generate the traffic
```bash
# TCP SYN scan (half-open, less likely to log on the target than a full connect scan)
nmap -sS -p 1-1000 <target-ip>

# TCP connect scan (completes the handshake — noisier, easier to correlate to target-side logs)
nmap -sT -p 1-1000 <target-ip>

# Service/version detection (higher signal — banner grabs are distinctive in packet captures)
nmap -sV -p 22,80,443,3389 <target-ip>
```
Run from an attacker VM against an isolated lab target — never against infrastructure you don't own or have written authorization to test.

### 2. Capture and inspect in Wireshark
Capture on the target (or a span/mirror port) during the scan. What a SYN scan looks like in Wireshark:
- A burst of `SYN` packets to sequential/many destination ports from one source, in a short window
- `RST, ACK` responses on closed ports, `SYN, ACK` on open ports, no `ACK` completing the handshake (that's the "half-open" signature)
- Useful filter: `tcp.flags.syn==1 and tcp.flags.ack==0`

### 3. Detect with Suricata
```
alert tcp any any -> $HOME_NET any (msg:"POSSIBLE NMAP SYN SCAN - Multiple ports single source"; \
  flags:S,12; flow:stateless; threshold:type both, track by_src, count 20, seconds 10; \
  classtype:attempted-recon; sid:9000001; rev:1;)

alert tcp any any -> $HOME_NET any (msg:"POSSIBLE NMAP SERVICE SCAN - Banner grab pattern"; \
  flow:to_server,established; threshold:type both, track by_src, count 5, seconds 30; \
  classtype:attempted-recon; sid:9000002; rev:1;)
```
`threshold` is doing the real work here — a single SYN to a single port is normal traffic; 20 SYNs to 20 different ports from the same source in 10 seconds is not. Tune `count`/`seconds` against your own network's baseline before trusting this in anything but a lab.

### 4. Correlate in Splunk
```spl
index=* sourcetype=suricata event_type=alert alert.signature="*NMAP*"
| stats count as alert_count, dc(dest_port) as distinct_ports, values(dest_port) as ports by src_ip, dest_ip
| where distinct_ports >= 10
| eval detection="nmap-recon-scan"
| eval severity=case(distinct_ports>=100, "high", distinct_ports>=30, "medium", true(), "low")
| table src_ip dest_ip alert_count distinct_ports severity ports detection
| sort - distinct_ports
```
This mirrors the correlation approach used in [`splunk-detections`](https://github.com/nicky-quist/splunk-detections) — threshold on a distinctive fan-out pattern (many ports/hosts from one source) rather than alerting on individual events.

## Investigation pivots
- **Source reputation** — is this IP internal (routine vuln-scan schedule?) or external?
- **Scope** — single host or multiple hosts touched from the same source in the same window?
- **Follow-through** — any successful connections (not just SYN/RST) to the ports that responded open? A scan followed by a real connection attempt is a different priority than a scan alone.
- **Timing** — business hours vs. off-hours; scheduled scanner windows vs. unexpected activity

## Known false positives
- Authorized vulnerability scanners (Nessus, Qualys, internal Nmap sweeps) — allowlist by source IP and validate against the scan schedule
- Network monitoring/asset-discovery tools that behave like scans structurally
- Misconfigured load balancers or health checks hitting many ports on one host

## Status
Detection logic (Suricata rule + Splunk correlation) is written and lab-testable end-to-end; not yet validated against a live capture in this repo. Next step: run the lab, capture the PCAP and Suricata `eve.log` output, and add them as evidence alongside a validation writeup (same format as [`splunk-detections`](https://github.com/nicky-quist/splunk-detections) evidence folders).

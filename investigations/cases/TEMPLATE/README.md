# Case: <name>

## Source
Where this capture came from (public training PCAP, lab exercise, platform name + link). Never include real production/customer traffic.

## Initial triage
What drew attention to this traffic — an alert, an anomaly noticed while scanning flows, or a manual hunt. What was the starting hypothesis?

## Protocol / flow analysis
Wireshark/tshark breakdown of the relevant conversations — protocols involved, notable filters used, key packets.

## Timeline
See [`timeline.md`](timeline.md) for the full sequence with timestamps.

## IOCs
See [`iocs.md`](iocs.md) for the full list.

## SIEM pivot
How this traffic would surface in Splunk/Suricata logs, and whether an existing detection (see [`splunk-detections`](https://github.com/nicky-quist/splunk-detections)) would catch it. If not, what detection logic would need to be written.

## Findings
Root cause, scope, and recommended response/containment steps.

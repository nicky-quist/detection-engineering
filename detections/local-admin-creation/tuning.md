## Known limitations
- **Severity decays with continued use.** `span_min` runs to the *last* 4624 in the search window, so every later logon by the account stretches the span and lowers the severity. The validation below had one logon, so it didn't exercise this.
- **Order is not enforced.** `values()` returns a sorted set, so the query confirms all three steps happened but not that they happened as create → elevate → log on.

Both are fixed in [`query_v2.spl`](query_v2.spl), **pending validation**; see [`validation/`](../../validation). Lab 05 includes a step that shows the decay directly.

## Validation notes
Tested against live Sysmon + Security event data (Splunk Free, manual
account creation -> elevation -> logon). Observed real span of 16 minutes
between account creation and first logon, correctly classified as
severity=medium under default thresholds (<=15min=high, <=30min=medium).

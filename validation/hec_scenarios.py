#!/usr/bin/env python3
"""Send the validation scenarios for the v1 -> v2 query fixes to Splunk HEC.

Each defect gets a scenario that should expose it, plus a positive control
that both query versions must catch. The control is what makes an empty
result meaningful: if the control fires and the defect scenario does not, v1
really missed it; if the control doesn't fire either, the events never
arrived and the test says nothing about the query.

    python hec_scenarios.py --self-check          # verify scenario shapes, no network
    python hec_scenarios.py --dry-run             # print the events, no network
    python hec_scenarios.py                       # send all scenarios
    python hec_scenarios.py --scenario spray-boundary

Configuration comes from the environment, never from arguments, so a token
can't end up in shell history or in a screenshot of the command:

    SPLUNK_HEC_URL       e.g. https://localhost:8088
    SPLUNK_HEC_TOKEN     the HEC token
    SPLUNK_HEC_INDEX     optional; a dedicated index keeps test data separate
    SPLUNK_HEC_INSECURE  set to 1 to accept the self-signed cert on a lab box

Standard library only.
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict

# A custom sourcetype still matches the detections' `*wineventlog*security*`
# clause, but has no Windows TA props attached. The JSON body is then
# extracted by Splunk's default AUTO_KV_JSON, the same way for every
# install, whereas the real WinEventLog:Security sourcetype's extraction
# depends on which add-ons are present.
SOURCETYPE = "hec:wineventlog:security"
SOURCE = "validation/hec_scenarios.py"
BLOCK = 600  # the 10-minute span used by v1's `bucket _time span=10m`
ADMINS_SID = "S-1-5-32-544"


# ── scenario construction ────────────────────────────────────────────────────

def anchor(now=None):
    """A 10-minute clock boundary two hours ago.

    v1's bucket edges fall on multiples of 600s since the epoch, so anchoring
    here puts the boundary scenario exactly across an edge. Two hours back
    keeps every event, including the admin-decay logon 90 minutes after its
    anchor, safely in the past and inside a "Last 4 hours" search.
    """
    now = time.time() if now is None else now
    return int(now // BLOCK) * BLOCK - 7200


def failed_logon(t, src, user, host):
    return {"time": t, "host": host, "event": {
        "EventCode": 4625, "IpAddress": src, "TargetUserName": user,
        "ComputerName": host, "LogonType": 3, "Status": "0xC000006D",
        "SubStatus": "0xC000006A"}}


def spray_control(b):
    """8 users, 2 failures each, well inside one 10-minute block. Both versions must fire."""
    src, users = "10.0.0.60", [f"ctrl.user{i}" for i in range(1, 9)]
    events, t = [], b + 60
    for user in users:
        for _ in range(2):
            events.append(failed_logon(t, src, user, "WIN10-LAB1"))
            t += 15
    return events


def spray_boundary(b):
    """10 users in about 5 minutes, split 5 and 5 across the block edge at `b`.

    Each block sees 10 failures but only 5 distinct users, one short of
    distinct_users >= 6, so v1 stays silent. A sliding 10-minute window sees
    all 10 users.
    """
    src = "10.0.0.61"
    before = [f"edge.user{i}" for i in range(1, 6)]
    after = [f"edge.user{i}" for i in range(6, 11)]
    events = []
    t = b - 150
    for user in before:
        for _ in range(2):
            events.append(failed_logon(t, src, user, "WIN10-LAB2"))
            t += 12
    t = b + 30
    for user in after:
        for _ in range(2):
            events.append(failed_logon(t, src, user, "WIN10-LAB2"))
            t += 12
    return events


def created(t, sid, name, host="WIN10-LAB3"):
    return {"time": t, "host": host, "event": {
        "EventCode": 4720, "TargetUserSid": sid, "TargetUserName": name,
        "SubjectUserName": "lab-admin", "ComputerName": host}}


def added_to_admins(t, sid, host="WIN10-LAB3"):
    return {"time": t, "host": host, "event": {
        "EventCode": 4732, "MemberSid": sid, "TargetSid": ADMINS_SID,
        "TargetUserName": "Administrators", "SubjectUserName": "lab-admin",
        "ComputerName": host}}


def logon(t, sid, name, host="WIN10-LAB3"):
    return {"time": t, "host": host, "event": {
        "EventCode": 4624, "TargetUserSid": sid, "TargetUserName": name,
        "LogonType": 2, "ComputerName": host}}


def admin_control(b):
    """Create, elevate, log on in 4 minutes. Both versions: high."""
    sid, name = "S-1-5-21-1000000000-1000000000-1000000000-1001", "lab-svc-1001"
    return [created(b, sid, name), added_to_admins(b + 120, sid), logon(b + 240, sid, name)]


def admin_decay(b):
    """The control chain, plus one more logon 90 minutes later.

    v1 measures to the last logon, so span_min = 90 and severity = low.
    v2 measures to the first logon after elevation: span_min = 4, high.
    """
    sid, name = "S-1-5-21-1000000000-1000000000-1000000000-1002", "lab-svc-1002"
    return [created(b, sid, name), added_to_admins(b + 120, sid),
            logon(b + 240, sid, name), logon(b + 5400, sid, name)]


def admin_order(b):
    """Create, log on, then elevate 50 minutes later, with no logon after.

    All three steps are present, so v1 fires (low). The chain the detection
    describes, create -> elevate -> log on as admin, never happened, and v2
    returns nothing.
    """
    sid, name = "S-1-5-21-1000000000-1000000000-1000000000-1003", "lab-svc-1003"
    return [created(b, sid, name), logon(b + 120, sid, name), added_to_admins(b + 3000, sid)]


SCENARIOS = {
    "spray-control": spray_control,
    "spray-boundary": spray_boundary,
    "admin-control": admin_control,
    "admin-decay": admin_decay,
    "admin-order": admin_order,
}

# What each query version should return when both are run in Splunk.
EXPECTED = {
    "spray-control":  {"detection": "password-spray-4625", "key": "10.0.0.60", "v1": "fires", "v2": "fires"},
    "spray-boundary": {"detection": "password-spray-4625", "key": "10.0.0.61", "v1": "no result", "v2": "fires"},
    "admin-control":  {"detection": "local-admin-creation", "key": "...-1001", "v1": "high", "v2": "high"},
    "admin-decay":    {"detection": "local-admin-creation", "key": "...-1002", "v1": "low", "v2": "high"},
    "admin-order":    {"detection": "local-admin-creation", "key": "...-1003", "v1": "low", "v2": "no result"},
}


# ── self-check ───────────────────────────────────────────────────────────────
# These are small restatements of what each query computes, in Python. They
# are NOT a substitute for running the SPL. Their only job is to prove the
# scenario data has the shape that exposes each defect, e.g. that the
# boundary events really do straddle a block edge, so that a surprising
# Splunk result points at the query rather than at badly built test data.

def severity(span_min):
    return "high" if span_min <= 15 else "medium" if span_min <= 30 else "low"


def spray_v1(events):
    blocks = defaultdict(lambda: {"n": 0, "users": set()})
    for e in events:
        k = (e["time"] // BLOCK * BLOCK, e["event"]["IpAddress"])
        blocks[k]["n"] += 1
        blocks[k]["users"].add(e["event"]["TargetUserName"])
    return any(v["n"] >= 8 and len(v["users"]) >= 6 for v in blocks.values())


def spray_v2(events):
    by_src = defaultdict(list)
    for e in events:
        by_src[e["event"]["IpAddress"]].append(e)
    for evs in by_src.values():
        evs.sort(key=lambda e: e["time"])
        for cur in evs:
            window = [e for e in evs if cur["time"] - BLOCK < e["time"] <= cur["time"]]
            if len(window) >= 8 and len({e["event"]["TargetUserName"] for e in window}) >= 6:
                return True
    return False


def steps(events):
    out = defaultdict(list)
    for e in events:
        ev = e["event"]
        kind = {4720: "created", 4624: "logon"}.get(ev["EventCode"])
        if ev["EventCode"] == 4732 and ev.get("TargetSid") == ADMINS_SID:
            kind = "admin"
        if kind:
            out[kind].append(e["time"])
    return out


def admin_v1(events):
    s = steps(events)
    if not (s["created"] and s["admin"] and s["logon"]):
        return "no result"
    times = s["created"] + s["admin"] + s["logon"]
    return severity(round((max(times) - min(times)) / 60, 1))


def admin_v2(events):
    s = steps(events)
    if not (s["created"] and s["admin"]):
        return "no result"
    c, a = min(s["created"]), min(s["admin"])
    after = [t for t in s["logon"] if t >= a]
    if a < c or not after:
        return "no result"
    return severity(round((min(after) - c) / 60, 1))


def self_check(b):
    failures = []
    for name, build in SCENARIOS.items():
        events, exp = build(b), EXPECTED[name]
        if name.startswith("spray"):
            got = {"v1": "fires" if spray_v1(events) else "no result",
                   "v2": "fires" if spray_v2(events) else "no result"}
        else:
            got = {"v1": admin_v1(events), "v2": admin_v2(events)}
        ok = got["v1"] == exp["v1"] and got["v2"] == exp["v2"]
        print(f"  {'ok  ' if ok else 'FAIL'} {name:15s} v1={got['v1']:10s} v2={got['v2']:10s}"
              f"(expected v1={exp['v1']}, v2={exp['v2']})")
        if not ok:
            failures.append(name)

    # The boundary scenario is only meaningful if it actually crosses an edge.
    edge = spray_boundary(b)
    blocks = {e["time"] // BLOCK for e in edge}
    span = max(e["time"] for e in edge) - min(e["time"] for e in edge)
    straddles = len(blocks) == 2 and span < BLOCK
    print(f"  {'ok  ' if straddles else 'FAIL'} spray-boundary crosses one block edge "
          f"({len(blocks)} blocks, {span}s span)")
    if not straddles:
        failures.append("spray-boundary-shape")

    in_past = all(e["time"] < time.time() for build in SCENARIOS.values() for e in build(b))
    print(f"  {'ok  ' if in_past else 'FAIL'} every event is in the past")
    if not in_past:
        failures.append("future-events")
    return failures


# ── sending ──────────────────────────────────────────────────────────────────

def to_hec(event, run_id, index):
    payload = {"time": event["time"], "host": event["host"], "source": SOURCE,
               "sourcetype": SOURCETYPE, "event": {**event["event"], "validation_run": run_id}}
    if index:
        payload["index"] = index
    return payload


def send(payloads, url, token, insecure):
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    channel = str(uuid.uuid4())
    headers = {"Authorization": f"Splunk {token}", "X-Splunk-Request-Channel": channel,
               "Content-Type": "application/json"}
    body = "\n".join(json.dumps(p) for p in payloads).encode()
    req = urllib.request.Request(url.rstrip("/") + "/services/collector/event",
                                 data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        reply = json.loads(resp.read() or b"{}")
    print(f"HEC accepted {len(payloads)} events: {reply}")

    ack_id = reply.get("ackId")
    if ack_id is None:
        print("No ackId returned (indexer acknowledgement is off); skipping index confirmation.")
        return
    # With acknowledgement on, "accepted" only means received. Poll until the
    # indexer confirms the batch is written, so a search run straight after
    # isn't racing the ingest.
    ack_req = urllib.request.Request(url.rstrip("/") + "/services/collector/ack",
                                     data=json.dumps({"acks": [ack_id]}).encode(),
                                     headers=headers, method="POST")
    for _ in range(30):
        with urllib.request.urlopen(ack_req, context=ctx, timeout=30) as resp:
            if json.loads(resp.read()).get("acks", {}).get(str(ack_id)):
                print(f"Indexer confirmed ack {ack_id}. Safe to search.")
                return
        time.sleep(2)
    print(f"Ack {ack_id} not confirmed after 60s. Events may still be indexing.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=["all", *SCENARIOS], default="all")
    ap.add_argument("--dry-run", action="store_true", help="print events instead of sending")
    ap.add_argument("--self-check", action="store_true", help="verify scenario shapes and exit")
    args = ap.parse_args()

    b = anchor()
    if args.self_check:
        print("Scenario self-check (models the query logic; does not replace running the SPL):")
        failed = self_check(b)
        print("PASS" if not failed else f"FAILED: {', '.join(failed)}")
        return 1 if failed else 0

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    run_id = time.strftime("%Y%m%dT%H%M%S")
    index = os.environ.get("SPLUNK_HEC_INDEX")
    payloads = [to_hec(e, run_id, index) for n in names for e in SCENARIOS[n](b)]

    if args.dry_run:
        for p in payloads:
            print(json.dumps(p))
    else:
        url, token = os.environ.get("SPLUNK_HEC_URL"), os.environ.get("SPLUNK_HEC_TOKEN")
        if not url or not token:
            sys.exit("Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN (or use --dry-run / --self-check).")
        insecure = os.environ.get("SPLUNK_HEC_INSECURE") == "1"
        if insecure:
            print("WARNING: TLS verification disabled (SPLUNK_HEC_INSECURE=1). Lab use only.")
        try:
            send(payloads, url, token, insecure)
        except urllib.error.HTTPError as e:
            sys.exit(f"HEC rejected the request: {e.code} {e.read().decode(errors='replace')}")

    first, last = min(p["time"] for p in payloads), max(p["time"] for p in payloads)
    print(f"\nvalidation_run={run_id}   events span "
          f"{time.strftime('%H:%M', time.localtime(first))}-{time.strftime('%H:%M', time.localtime(last))} local time")
    print("Search with a time range covering that span (Last 4 hours works). "
          "Run query.spl and query_v2.spl and compare against:\n")
    print(f"  {'scenario':15s} {'detection':22s} {'row key':11s} {'v1':10s} v2")
    for n in names:
        e = EXPECTED[n]
        print(f"  {n:15s} {e['detection']:22s} {e['key']:11s} {e['v1']:10s} {e['v2']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

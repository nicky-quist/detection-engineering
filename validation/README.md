# Validation: v1 → v2 query fixes

Two detections have a `query_v2.spl` that fixes a logic defect found by reviewing the SPL. **Both are pending validation.** Every detection in this repo is claimed to be validated against real or simulated event data, and neither fix has been run in Splunk yet. Until it has, `query.spl` stays the detection of record.

This folder holds the test that settles it.

## The defects

| Detection | Defect in `query.spl` | Consequence |
|---|---|---|
| [`password-spray-4625`](../detections/password-spray-4625) | `bucket _time span=10m` splits time into fixed clock blocks | A spray crossing a block edge is divided in two, so neither half reaches `distinct_users >= 6`. Pacing a spray at about 5 users per 10 minutes avoids the detection entirely |
| [`local-admin-creation`](../detections/local-admin-creation) | `span_min` is measured to the **last** logon in the search window | Severity drops the longer an attacker uses the account: a 4-minute chain is scored `low` once there's another logon 90 minutes later |
| [`local-admin-creation`](../detections/local-admin-creation) | Step order is never checked (`values()` is a sorted set) | The README promises create → elevate → log on *in order*, but the query only confirms all three happened |

Neither showed up in the original validation. The spray test sent all 20 events well inside one block, and the admin test had a single logon. Both tests were correct; they just didn't include the cases that expose these defects.

## Running it

[`hec_scenarios.py`](hec_scenarios.py) sends five scenarios over HEC, using the same ingest path as the original [password-spray validation](../detections/password-spray-4625/evidence/validation-notes.md). It uses only the standard library.

```bash
python validation/hec_scenarios.py --self-check   # no network: confirm the scenarios are shaped right
python validation/hec_scenarios.py --dry-run      # no network: print what would be sent
```

Then, against the lab Splunk:

```bash
export SPLUNK_HEC_URL=https://localhost:8088
export SPLUNK_HEC_TOKEN=...          # environment only, never a command-line argument
export SPLUNK_HEC_INDEX=validation   # optional, keeps test events out of real indexes
export SPLUNK_HEC_INSECURE=1         # only for the lab's self-signed certificate
python validation/hec_scenarios.py
```

The script waits for the indexer to acknowledge the batch before printing the expected results, so the search doesn't race the ingest. Then run **both** `query.spl` and `query_v2.spl` for each detection over "Last 4 hours".

## Expected results

| Scenario | What it sends | Row key | `query.spl` | `query_v2.spl` |
|---|---|---|---|---|
| `spray-control` | 8 users × 2 failures, inside one block | `10.0.0.60` | fires | fires |
| `spray-boundary` | 10 users in ~5 min, 5 before a block edge and 5 after | `10.0.0.61` | **no result** | fires |
| `admin-control` | create → admin +2m → logon +4m | SID `…-1001` | high | high |
| `admin-decay` | the same chain, plus a logon +90m | SID `…-1002` | **low** | high |
| `admin-order` | create → logon +2m → admin +50m, no later logon | SID `…-1003` | **low** | **no result** |

**Read the controls first.** If `spray-control` or `admin-control` is missing from *either* query's output, the events didn't arrive or weren't extracted. Stop and fix ingestion, because the other rows mean nothing yet. A missing `spray-boundary` row only proves the defect if the control row is there beside it.

## What counts as validated

A fix is validated when all five rows match the table. Record the result the same way as the existing [`validation-notes.md`](../detections/password-spray-4625/evidence/validation-notes.md): date, environment, scenario parameters, expected vs. observed, and screenshots of both queries' output. Then:

1. Replace `query.spl` with `query_v2.spl` and delete the v2 file
2. Remove the "pending validation" notes from the detection's README and playbook
3. Keep the evidence, since it now documents both the defect and the fix

If a row doesn't match, that is also a result worth writing up. It means either the SPL behaves differently from the reasoning in the v2 header, or the scenario doesn't do what the self-check says it does.

## What the self-check does and doesn't prove

`--self-check` restates each query's logic in a few lines of Python and confirms the scenarios produce the expected v1/v2 split. It also independently confirms that the boundary events really cross exactly one block edge. That rules out one failure mode: test data built wrong, so that a surprising Splunk result gets blamed on the query.

It does **not** show the SPL is correct. A Python restatement is only as right as its reading of Splunk's semantics (for example, how `streamstats time_window` treats the window edge). Only running the queries settles that.

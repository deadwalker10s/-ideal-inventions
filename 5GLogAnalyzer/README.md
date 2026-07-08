# AMF Log Analyzer

A Python pipeline that parses raw 5G AMF (Access and Mobility Management Function) logs, classifies events, runs a per-UE branched state machine, and produces a human-readable failure/completion report.

---

## Pipeline Overview

```
Raw AMF Log
    │
    ▼
┌─────────┐
│  Parser  │  Extracts: timestamp, level, source file, message, JSON context
└────┬─────┘
     │
     ▼
┌──────────────┐
│  Classifier  │  Maps message text → EVENT_CODE (e.g. REG_REQUEST, AUTH_START)
└────┬─────────┘
     │
     ▼
┌──────────────────┐
│  UE Correlation  │  Groups events per UE using amf_ue_ngap_id → ran_addr → fallback
└────┬─────────────┘
     │
     ▼
┌───────────────────────┐
│  Branched State       │  Per-UE FSM: tracks state, detects FAILED / STUCK / COMPLETED
│  Machine (per UE)     │
└────┬──────────────────┘
     │
     ▼
┌──────────────────┐
│  Report Generator│  Prints summary + per-UE status, reason, and failure timeline
└──────────────────┘
```

---

## Requirements

- Python **3.7+**
- No third-party libraries — uses only the standard library (`re`, `json`, `datetime`, `argparse`)

---

## How to Run

### Basic usage (prints report to terminal)

```bash
python3 amf_log_analyzer.py /path/to/your/amf.log
```

### With JSON output (full structured results saved to a file)

```bash
python3 amf_log_analyzer.py /path/to/your/amf.log --json results.json
```

### Examples

```bash
# Run on a log file in the same folder
python3 amf_log_analyzer.py 5G_log.log

# Run with JSON output saved alongside the script
python3 amf_log_analyzer.py 5G_log.log --json out.json

# Full path (Linux/macOS)
python3 amf_log_analyzer.py /var/log/5g/amf_full.log --json /var/log/5g/report.json

# Full path (Windows)
python amf_log_analyzer.py C:\logs\amf_full.log --json C:\logs\report.json
```

---

## Arguments

| Argument     | Required | Description                                              |
|--------------|----------|----------------------------------------------------------|
| `logfile`    | Yes      | Path to the raw AMF log file                             |
| `--json`     | No       | Path to save full structured results as a JSON file      |

---

## Output

### Terminal report example

```
======================================================================
AMF LOG ANALYSIS REPORT
======================================================================
Total UE sessions analyzed: 3
  COMPLETED          : 1
  FAILED             : 1
  STUCK              : 1

----------------------------------------------------------------------
UE: AMF_UE_NGAP_ID:1654759
  SUPI: SUPI:imsi-001010000000004
  SUCI: suci-0-001-01-0-0-0-0000000004
  RAN Address: 10.176.26.41:39748
  Status: COMPLETED
  Final State: RELEASED
  Reason: Full lifecycle observed: registered, session handled, deregistered cleanly.
  Last Event Time: 2026-06-25T12:05:01.538000+05:30
======================================================================
```

### UE status values

| Status             | Meaning                                                                 |
|--------------------|-------------------------------------------------------------------------|
| `COMPLETED`        | Full lifecycle observed — NG Setup → Registration → PDU Session → Deregistration → Release |
| `FAILED`           | A known failure transition was hit (auth failure, reg reject, PDU setup fail) |
| `STUCK`            | UE reached an intermediate state with no further events (timeout, missing response, log truncation) |
| `ACTIVE_AT_LOG_END`| UE reached REGISTERED or PDU_SESSION_ACTIVE and the log window simply ended — no failure detected |

---

## State Machine Flow

```
START
  └─► NG_SETUP_REQUESTED ──► NG_SETUP_DONE
                                    │
                                    ▼
                             REG_REQUESTED
                                    │
                          ┌─────────┴──────────┐
                          ▼                    ▼
                   AUTH_IN_PROGRESS      FAIL_REG_REJECTED
                          │
                ┌─────────┴──────────┐
                ▼                    ▼
             AUTH_OK            FAIL_AUTH
                │
                ▼
          REG_ACCEPTED ──► CTX_SETUP_DONE ──► REGISTERED
                                                    │
                                       ┌────────────┴────────────┐
                                       ▼                         ▼
                                 PDU_TRIGGERED             DEREG_REQUESTED
                                       │                         │
                                       ▼                         ▼
                              PDU_SETUP_REQUESTED          CTX_RELEASED
                                       │                         │
                            ┌──────────┴──────┐                  ▼
                            ▼                 ▼             UE_RELEASING
                   PDU_SESSION_ACTIVE   FAIL_PDU_SETUP            │
                            │                                     ▼
                            └──────────────────────────────►  RELEASED ✓
```

---

## Extending the Classifier

When you run this against a full AMF log, new message strings will appear that fall through to `UNKNOWN`. To handle them, add a new row to the `CLASSIFY_RULES` list in the script:

```python
CLASSIFY_RULES = [
    ...
    (r'your new message pattern',  "YOUR_EVENT_CODE",  "Human readable label"),
    ...
]
```

Then add the new event code to `TRANSITIONS` if it represents a valid state change.

---

## Extending the State Machine

To add a new state or branch (e.g. a Handover procedure), add entries to the `TRANSITIONS` dict:

```python
TRANSITIONS = {
    ...
    "PDU_SESSION_ACTIVE": {
        "HANDOVER_REQUIRED": "HANDOVER_IN_PROGRESS",
        "DEREG_REQUEST":     "DEREG_REQUESTED",
    },
    "HANDOVER_IN_PROGRESS": {
        "HANDOVER_SUCCESS": "PDU_SESSION_ACTIVE",
        "HANDOVER_FAILURE": "FAIL_HANDOVER",
    },
    ...
}
```

And add a reason string for the failure state:

```python
FAILURE_REASONS = {
    ...
    "FAIL_HANDOVER": "Handover procedure failed.",
}
```

---

## File Structure

```
.
├── amf_log_analyzer.py   # Main script (parser + classifier + FSM + report)
├── README.md             # This file
└── out.json              # Generated output (if --json flag is used)
```

---

## Known Limitations

1. **Multi-UE interleaving** — lines with no `amf_ue_ngap_id` or `ran_addr` in their context (e.g. N1N2 trigger lines) are attached to the most recently active UE. This works for low-traffic logs but can misattribute events in a heavily interleaved multi-UE log.

2. **New message patterns** — any message not in `CLASSIFY_RULES` is labelled `UNKNOWN` and does not advance the state machine. Check the JSON output's `event_code: "UNKNOWN"` entries after running on a new log and extend the rule table accordingly.

3. **No NGAP cause codes** — the script reads the AMF log only; it does not parse NGAP cause values from raw packets. Failure reasons are inferred from message text alone.

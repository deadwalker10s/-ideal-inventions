#!/usr/bin/env python3
"""
AMF Log Analyzer
=================
Pipeline: Parser -> Classifier -> Branched per-UE State Machine -> Report Generator

Usage:
    python3 amf_log_analyzer.py <logfile> [--json out.json] [--stuck-timeout 5]

Design notes
------------
- Parser extracts: timestamp, level, source(file:line), message, and the trailing
  JSON context dict, for every line -- independent of which UE it belongs to.
- Events are correlated to a UE using whichever identifier is available at that
  point in the procedure: amf_ue_ngap_id (preferred, once assigned) falling back
  to ran_addr (covers NG Setup / pre-registration events that have no UE id yet).
  Once an amf_ue_ngap_id appears for a ran_addr, all earlier ran_addr-only events
  for that connection are folded into the same UE timeline.
- Classifier maps message text -> a short EVENT_CODE using a pattern table, so new
  message strings encountered in the full log can be added without touching logic.
- State machine is per-UE and branched: each state declares a set of acceptable
  next events, not a single one. Anything else is either a known FAILURE
  transition (mapped explicitly) or an UNEXPECTED event (caught generically).
  A UE that stalls in a non-terminal state with no further events is reported
  as "stuck" with the last successful step and elapsed time.
"""

import re
import json
import sys
import argparse
import logging
from datetime import datetime
from collections import OrderedDict, defaultdict

# ---------------------------------------------------------------------------
# 1. PARSER
# ---------------------------------------------------------------------------

LINE_RE = re.compile(
    r'^(?P<ts>\S+)\s+'
    r'(?P<level>\w+)\s+'
    r'(?P<source>\S+)\s+'
    r'(?P<message>.*?)\s*'
    r'(?P<context>\{.*\})\s*$'
)

def parse_line(line):
    line = line.rstrip('\n')
    if not line.strip():
        return None
    logging.debug("Parsing line: %s", line)
    m = LINE_RE.match(line)
    if not m:
        return {"raw": line, "parse_error": True}
    ctx_raw = m.group("context")
    try:
        context = json.loads(ctx_raw)
    except json.JSONDecodeError:
        context = {}
    ts_raw = m.group("ts")
    # 2026-06-25T10:57:25.662+0530
    try:
        ts = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        ts = None
    return {
        "timestamp_raw": ts_raw,
        "timestamp": ts,
        "level": m.group("level"),
        "source": m.group("source"),
        "message": m.group("message").strip(),
        "context": context,
    }

def parse_log(path):
    events = []
    with open(path, "r", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            parsed = parse_line(line)
            if parsed is None:
                continue
            if parsed.get("parse_error"):
                logging.debug("Skipping parse error on line %d: %s", lineno, parsed.get("raw"))
                continue
            parsed["lineno"] = lineno
            logging.debug("Parsed line %d: %s", lineno, parsed)
            events.append(parsed)
    logging.debug("Finished parsing log %s: %d events", path, len(events))
    return events


# ---------------------------------------------------------------------------
# 2. CLASSIFIER
# ---------------------------------------------------------------------------
# (regex_on_message, EVENT_CODE, human_label)
# Order matters: more specific patterns should precede generic ones.
CLASSIFY_RULES = [
    (r'Create a new NG connection',                 "NG_CONN_NEW",        "New NG Connection"),
    (r'handle NG Setup request',                     "NG_SETUP_REQ",       "NG Setup Request"),
    (r'send NG-Setup response',                       "NG_SETUP_RESP",      "NG Setup Response"),
    (r'Handle Registration Request',                  "REG_REQUEST",        "Registration Request"),
    (r'Authentication procedure',                     "AUTH_START",         "Authentication Procedure Start"),
    (r'Authentication.*(fail|reject)',                "AUTH_FAILED",        "Authentication Failed"),
    (r'Handle InitialRegistration',                   "REG_INITIAL",        "Initial Registration Handling"),
    (r'send Registration Accept',                     "REG_ACCEPT",         "Registration Accept Sent"),
    (r'send Registration Reject',                     "REG_REJECT",         "Registration Reject Sent"),
    (r'handle Initial Context Setup Response',        "CTX_SETUP_RESP",     "Initial Context Setup Response"),
    (r'Handle Registration Complete',                 "REG_COMPLETE",       "Registration Complete"),
    (r'Handle N1N2 Message Transfer Request',         "N1N2_TRANSFER",      "N1N2 Message Transfer"),
    (r'send PDU Session Resource Setup Request',      "PDU_SETUP_REQ",      "PDU Session Setup Request"),
    (r'handle PDU Session Resource Setup Response',   "PDU_SETUP_RESP",     "PDU Session Setup Response"),
    (r'PDU Session.*(fail|reject)',                   "PDU_SETUP_FAILED",   "PDU Session Setup Failed"),
    (r'Handle Deregistration Request',                "DEREG_REQUEST",      "Deregistration Request"),
    (r'handle UE Context Release Complete',           "CTX_RELEASE_COMPLETE","UE Context Release Complete"),
    (r'Release UE.*Context',                          "UE_CONTEXT_RELEASED","UE Context Released"),
    (r'RanUe has been deleted',                       "RANUE_DELETED",      "RAN UE Deleted"),
    (r'(timeout|timed out)',                          "TIMEOUT",           "Timeout"),
    (r'(error|fail|reject)',                          "GENERIC_FAILURE",   "Generic Failure/Error"),
]
COMPILED_RULES = [(re.compile(p, re.I), code, label) for p, code, label in CLASSIFY_RULES]

CATEGORY_GROUP = {
    "NGAP": "NGAP",
    "GMM": "Registration/Authentication/Deregistration (GMM)",
    "Producer": "Session Management Trigger",
    "Context": "Context Management",
}

def classify(event):
    msg = event.get("message", "")
    logging.debug("Classifying message: %s", msg)
    for regex, code, label in COMPILED_RULES:
        if regex.search(msg):
            event["event_code"] = code
            event["event_label"] = label
            break
    else:
        event["event_code"] = "UNKNOWN"
        event["event_label"] = f"Unclassified: {msg[:60]}"
    cat = event.get("context", {}).get("category", "")
    event["group"] = CATEGORY_GROUP.get(cat, cat or "Unknown")
    logging.debug(
        "Classified event: line=%s code=%s label=%s group=%s",
        event.get("lineno", "?"),
        event["event_code"],
        event["event_label"],
        event["group"],
    )
    return event


# ---------------------------------------------------------------------------
# UE CORRELATION
# ---------------------------------------------------------------------------

def correlate_ue_timelines(events):
    """
    Group events into per-UE timelines.
    Key preference: amf_ue_ngap_id > ran_addr (pre-id events get folded in once
    an amf_ue_ngap_id shows up on the same ran_addr).
    """
    timelines = OrderedDict()       # ue_key -> list of events
    ran_addr_to_uekey = {}          # ran_addr -> ue_key (once known)
    last_active_uekey = None        # fallback for events with no identifiers at all
                                     # (e.g. N1N2 transfer, RanUe deleted lines that
                                     # carry no ran_addr/amf_ue_ngap_id in this log format)

    for ev in events:
        ctx = ev.get("context", {})
        amf_id = ctx.get("amf_ue_ngap_id")
        ran_addr = ctx.get("ran_addr")

        if amf_id:
            ue_key = amf_id
            if ran_addr:
                # fold prior ran_addr-only events into this UE's timeline
                prior_key = ran_addr_to_uekey.get(ran_addr)
                if prior_key and prior_key != ue_key and prior_key in timelines:
                    timelines.setdefault(ue_key, [])
                    timelines[ue_key] = timelines.pop(prior_key) + timelines.get(ue_key, [])
                ran_addr_to_uekey[ran_addr] = ue_key
        elif ran_addr:
            ue_key = ran_addr_to_uekey.get(ran_addr, f"ran:{ran_addr}")
            ran_addr_to_uekey.setdefault(ran_addr, ue_key)
        elif last_active_uekey:
            # No identifiers in this line's context at all. Attach it to whichever
            # UE timeline was most recently touched. Safe for single-UE-at-a-time
            # traffic; for heavily interleaved multi-UE logs this heuristic should
            # be tightened (e.g. using nearby NGAP/GMM lines within a small time
            # window to disambiguate) once we see that pattern in the full log.
            ue_key = last_active_uekey
        else:
            ue_key = "UNCORRELATED"

        logging.debug(
            "Correlating event line %d: amf_id=%s ran_addr=%s -> ue_key=%s",
            ev.get("lineno", "?"),
            amf_id,
            ran_addr,
            ue_key,
        )
        timelines.setdefault(ue_key, []).append(ev)
        if ue_key != "UNCORRELATED":
            last_active_uekey = ue_key

    # sort each timeline by timestamp/lineno
    for k in timelines:
        timelines[k].sort(key=lambda e: (e["timestamp"] or datetime.min.replace(tzinfo=None), e["lineno"]) if e["timestamp"] else (datetime.min, e["lineno"]))
    return timelines


# ---------------------------------------------------------------------------
# 3. BRANCHED STATE MACHINE
# ---------------------------------------------------------------------------
# Each state: { next_event_code: next_state }. Multiple keys = branching.
# "FAIL_*" target states are terminal failure states with a reason.

TRANSITIONS = {
    "START": {
        "NG_CONN_NEW": "NG_CONNECTED",
        "NG_SETUP_REQ": "NG_SETUP_REQUESTED",  # NG_CONN_NEW line often carries no
                                                # ran_addr, so it may not correlate
        "REG_REQUEST": "REG_REQUESTED",        # UE id already known mid-stream
    },
    "NG_CONNECTED": {
        "NG_SETUP_REQ": "NG_SETUP_REQUESTED",
        "REG_REQUEST": "REG_REQUESTED",
    },
    "NG_SETUP_REQUESTED": {
        "NG_SETUP_RESP": "NG_SETUP_DONE",
    },
    "NG_SETUP_DONE": {
        "REG_REQUEST": "REG_REQUESTED",
    },
    "REG_REQUESTED": {
        "AUTH_START": "AUTH_IN_PROGRESS",
        "REG_REJECT": "FAIL_REG_REJECTED",
    },
    "AUTH_IN_PROGRESS": {
        "REG_INITIAL": "AUTH_OK",
        "AUTH_FAILED": "FAIL_AUTH",
        "REG_REJECT": "FAIL_REG_REJECTED",
    },
    "AUTH_OK": {
        "REG_ACCEPT": "REG_ACCEPTED",
    },
    "REG_ACCEPTED": {
        "CTX_SETUP_RESP": "CTX_SETUP_DONE",
    },
    "CTX_SETUP_DONE": {
        "REG_COMPLETE": "REGISTERED",
    },
    "REGISTERED": {
        "N1N2_TRANSFER": "PDU_TRIGGERED",
        "PDU_SETUP_REQ": "PDU_SETUP_REQUESTED",  # defensive: skip trigger if N1N2 line didn't correlate
        "DEREG_REQUEST": "DEREG_REQUESTED",
    },
    "PDU_TRIGGERED": {
        "PDU_SETUP_REQ": "PDU_SETUP_REQUESTED",
    },
    "PDU_SETUP_REQUESTED": {
        "PDU_SETUP_RESP": "PDU_SESSION_ACTIVE",
        "PDU_SETUP_FAILED": "FAIL_PDU_SETUP",
    },
    "PDU_SESSION_ACTIVE": {
        "DEREG_REQUEST": "DEREG_REQUESTED",
        "N1N2_TRANSFER": "PDU_TRIGGERED",   # additional PDU sessions
    },
    "DEREG_REQUESTED": {
        "CTX_RELEASE_COMPLETE": "CTX_RELEASED",
    },
    "CTX_RELEASED": {
        "UE_CONTEXT_RELEASED": "UE_RELEASING",
    },
    "UE_RELEASING": {
        "RANUE_DELETED": "RELEASED",
    },
}

TERMINAL_SUCCESS_STATES = {"RELEASED"}
TERMINAL_FAILURE_PREFIX = "FAIL_"
NON_TERMINAL_OK_END_STATES = {  # ok to end here if log window just stops (UE still active)
    "REGISTERED", "PDU_SESSION_ACTIVE",
}

FAILURE_REASONS = {
    "FAIL_AUTH": "Authentication procedure failed (UE rejected or auth vectors exhausted).",
    "FAIL_REG_REJECTED": "AMF sent Registration Reject.",
    "FAIL_PDU_SETUP": "PDU Session Resource Setup failed/rejected by RAN or UE.",
}

def run_state_machine(ue_key, timeline, stuck_timeout_minutes=None):
    state = "START"
    history = []
    last_ts = None
    for ev in timeline:
        code = ev.get("event_code")
        ts = ev.get("timestamp")
        allowed = TRANSITIONS.get(state, {})
        if code in allowed:
            new_state = allowed[code]
        elif code in ("GENERIC_FAILURE", "TIMEOUT"):
            new_state = f"FAIL_UNSPECIFIED"
        elif code == "UNKNOWN":
            new_state = state  # ignore unclassified noise, don't break the FSM
        else:
            # event happened but isn't a valid transition from this state
            new_state = f"UNEXPECTED({code} while in {state})"
        history.append({
            "lineno": ev["lineno"],
            "timestamp": ev["timestamp_raw"],
            "event_code": code,
            "event_label": ev.get("event_label"),
            "from_state": state,
            "to_state": new_state,
        })
        logging.debug(
            "StateMachine %s line %s: %s -> %s",
            ue_key,
            ev.get("lineno", "?"),
            state,
            new_state,
        )
        if not new_state.startswith("UNEXPECTED"):
            state = new_state
        last_ts = ts

    outcome = {
        "ue_key": ue_key,
        "final_state": state,
        "history": history,
        "last_event_time": last_ts.isoformat() if last_ts else None,
    }

    if state in TERMINAL_SUCCESS_STATES:
        outcome["status"] = "COMPLETED"
        outcome["reason"] = "Full lifecycle observed: registered, session handled, deregistered cleanly."
    elif state.startswith(TERMINAL_FAILURE_PREFIX):
        outcome["status"] = "FAILED"
        outcome["reason"] = FAILURE_REASONS.get(state, f"Failed in state {state}.")
    elif state in NON_TERMINAL_OK_END_STATES:
        outcome["status"] = "ACTIVE_AT_LOG_END"
        outcome["reason"] = f"UE reached '{state}' and log window ended; no failure observed, but no deregistration seen either."
    else:
        outcome["status"] = "STUCK"
        outcome["reason"] = f"UE stalled in intermediate state '{state}' with no further events — likely missing a response (timeout) or log truncation."

    logging.debug("Outcome for %s: final_state=%s status=%s", ue_key, state, outcome["status"])
    return outcome


# ---------------------------------------------------------------------------
# 4. REPORT GENERATOR
# ---------------------------------------------------------------------------

def generate_report(outcomes, ue_meta):
    lines = []
    lines.append("=" * 70)
    lines.append("AMF LOG ANALYSIS REPORT")
    lines.append("=" * 70)

    counts = defaultdict(int)
    for o in outcomes:
        counts[o["status"]] += 1
    lines.append(f"Total UE sessions analyzed: {len(outcomes)}")
    for status in ("COMPLETED", "FAILED", "STUCK", "ACTIVE_AT_LOG_END"):
        if counts[status]:
            lines.append(f"  {status:<18}: {counts[status]}")
    lines.append("")

    for o in outcomes:
        meta = ue_meta.get(o["ue_key"], {})
        lines.append("-" * 70)
        lines.append(f"UE: {o['ue_key']}")
        if meta.get("supi"):
            lines.append(f"  SUPI: {meta['supi']}")
        if meta.get("suci"):
            lines.append(f"  SUCI: {meta['suci']}")
        if meta.get("ran_addr"):
            lines.append(f"  RAN Address: {meta['ran_addr']}")
        lines.append(f"  Status: {o['status']}")
        lines.append(f"  Final State: {o['final_state']}")
        lines.append(f"  Reason: {o['reason']}")
        lines.append(f"  Last Event Time: {o['last_event_time']}")
        if o["status"] in ("FAILED", "STUCK"):
            lines.append("  Timeline leading to issue:")
            for h in o["history"]:
                marker = " <-- ISSUE" if h["to_state"].startswith("FAIL") or h["to_state"].startswith("UNEXPECTED") else ""
                lines.append(f"    [{h['timestamp']}] line {h['lineno']:>4}  {h['event_code']:<22} "
                              f"({h['from_state']} -> {h['to_state']}){marker}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def extract_ue_meta(timelines):
    meta = {}
    for ue_key, evs in timelines.items():
        m = {}
        for ev in evs:
            ctx = ev.get("context", {})
            for f in ("supi", "suci", "ran_addr"):
                if ctx.get(f) and f not in m:
                    m[f] = ctx[f]
        meta[ue_key] = m
    return meta


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="AMF log parser/classifier/state-machine/report tool")
    ap.add_argument("logfile")
    ap.add_argument("--json", help="optional path to dump full structured results as JSON")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    logging.info("amf_log_analyzer.py: Parsing and analyzing log file: %s", args.logfile)
    
    events = parse_log(args.logfile)
    logging.info("Events parsed: %d", len(events))
    events = [classify(ev) for ev in events]
    timelines = correlate_ue_timelines(events)
    ue_meta = extract_ue_meta(timelines)

    outcomes = []
    for ue_key, evs in timelines.items():
        if ue_key == "UNCORRELATED":
            continue
        outcomes.append(run_state_machine(ue_key, evs))

    report = generate_report(outcomes, ue_meta)
    logging.info("Generated report")
    print(report)

    if args.json:
        def default(o):
            if isinstance(o, datetime):
                return o.isoformat()
            return str(o)
        with open(args.json, "w") as f:
            json.dump({
                "ue_count": len(outcomes),
                "outcomes": outcomes,
                "ue_meta": ue_meta,
            }, f, indent=2, default=default)
        print(f"\n[Full structured results written to {args.json}]")


if __name__ == "__main__":
    main()

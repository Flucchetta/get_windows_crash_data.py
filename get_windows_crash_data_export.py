import argparse
import csv
import datetime
import json
import os
import time

try:
    import win32evtlog
except ImportError:
    raise SystemExit(
        "This script requires Windows and the pywin32 package.\n"
        "Install it with: pip install pywin32"
    )

"""
Windows Crash Data Exporter - JSON/CSV Export Variant
======================================================
This version exports Windows crash and shutdown events to JSON or CSV format.
Use this when you need to log events to a file for analysis, archival, or integration.

Main version (console output): get_windows_crash_data.py
This version (file export): get_windows_crash_data_json.py or get_windows_crash_data_export.py
"""

CRASH_EVENT_IDS = {
    41,     # Kernel-Power: unexpected shutdown
    1001,   # Windows Error Reporting
    6008,   # Unexpected shutdown
    7034,   # Service crashed unexpectedly
    7036,   # Service state change
    1074,   # System shutdown or restart
    1076,   # System shutdown due to error
}

CRASH_SOURCES = {
    "kernel-power",
    "bugcheck",
    "application error",
    "windows error reporting",
    "eventlog",
    "service control manager",
    "wininit",
    "winlogon",
}


def get_event_time(event):
    try:
        if hasattr(event.TimeGenerated, "Format"):
            return event.TimeGenerated.Format()
        return str(event.TimeGenerated)
    except Exception:
        return str(datetime.datetime.now())


def get_event_message(event):
    inserts = getattr(event, "StringInserts", None)
    if inserts:
        try:
            return " ".join(str(x) for x in inserts)
        except Exception:
            return str(inserts)
    return "No description available"


def is_relevant_event(event):
    event_id = getattr(event, "EventID", 0) & 0xFFFF
    source = (getattr(event, "SourceName", "") or "").lower()

    if event_id in CRASH_EVENT_IDS:
        return True

    if any(s in source for s in CRASH_SOURCES):
        return True

    message = get_event_message(event).lower()
    if "crash" in message or "unexpected shutdown" in message or "bugcheck" in message:
        return True

    return False


def read_events(log_name, max_events=200):
    hand = None
    events = []

    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            batch = win32evtlog.ReadEventLog(hand, flags, 0)
            if not batch:
                break

            for event in batch:
                events.append(event)
                if len(events) >= max_events:
                    return events

    except Exception as exc:
        print(f"[{log_name}] Error reading event log: {exc}")
        return []
    finally:
        if hand:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass

    return events


def to_event_dict(log_name, event):
    return {
        "log": log_name,
        "time": get_event_time(event),
        "source": getattr(event, "SourceName", "Unknown"),
        "event_id": getattr(event, "EventID", 0) & 0xFFFF,
        "event_type": getattr(event, "EventType", "Unknown"),
        "message": get_event_message(event),
    }


def collect_relevant_events(log_names=("System", "Application"), max_events=200):
    collected = []
    for log_name in log_names:
        for event in read_events(log_name, max_events=max_events):
            if is_relevant_event(event):
                collected.append(to_event_dict(log_name, event))
    return collected


def save_json(data, output_path):
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"✓ Saved {len(data)} event(s) to {output_path}")


def save_csv(data, output_path):
    if not data:
        print(f"✓ No events to save to {output_path}")
        return

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["log", "time", "source", "event_id", "event_type", "message"])
        writer.writeheader()
        writer.writerows(data)
    print(f"✓ Saved {len(data)} event(s) to {output_path}")


def poll_and_export(output_path="windows_crash_events.json", format_type="json", interval_seconds=60, once=False):
    print("Starting Windows Crash Export Monitor (JSON/CSV variant)")
    print("=" * 60)
    print(f"Export format: {format_type.upper()}")
    print(f"Output file: {output_path}")
    print("=" * 60)

    while True:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Checking logs...")
        data = collect_relevant_events()

        if format_type.lower() == "csv":
            save_csv(data, output_path)
        else:
            save_json(data, output_path)

        if once:
            break

        print(f"Waiting {interval_seconds} seconds before next export...")
        time.sleep(interval_seconds)


def main():
    parser = argparse.ArgumentParser(
        description="Export Windows crash events to JSON or CSV.",
        epilog="Example: python get_windows_crash_data_export.py --format json --output crashes.json --once"
    )
    parser.add_argument("--output", default="windows_crash_events.json", help="Path to output file")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (json or csv)")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds")
    parser.add_argument("--once", action="store_true", help="Check once and exit")
    args = parser.parse_args()

    poll_and_export(output_path=args.output, format_type=args.format, interval_seconds=args.interval, once=args.once)


if __name__ == "__main__":
    main()

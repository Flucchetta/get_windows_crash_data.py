import argparse
import datetime
import time

try:
    import win32evtlog
except ImportError:
    raise SystemExit(
        "This script requires Windows and the pywin32 package.\n"
        "Install it with: pip install pywin32"
    )

# Focus on the most relevant crash/shutdown events
CRASH_EVENT_IDS = {
    41,     # Kernel-Power: unexpected shutdown
    1001,   # Windows Error Reporting
    6008,   # Unexpected shutdown
    7034,   # Service crashed unexpectedly
    7036,   # Service state change (may help with crash-related services)
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

    # Also catch common crash-style error messages from the log
    message = get_event_message(event).lower()
    if "crash" in message or "unexpected shutdown" in message or "bugcheck" in message:
        return True

    return False

def read_recent_events(log_name, max_events=100):
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

def dump_relevant_events(log_name, max_events=100):
    found = False

    for event in read_recent_events(log_name, max_events=max_events):
        if not is_relevant_event(event):
            continue

        found = True
        event_time = get_event_time(event)
        event_id = getattr(event, "EventID", 0) & 0xFFFF
        source = getattr(event, "SourceName", "Unknown")
        event_type = getattr(event, "EventType", "Unknown")
        message = get_event_message(event)

        print(f"Time: {event_time}")
        print(f"Log: {log_name}")
        print(f"Source: {source}")
        print(f"Event ID: {event_id}")
        print(f"Event Type: {event_type}")
        print(f"Message: {message}")
        print("-" * 60)

    if not found:
        print(f"[{log_name}] No relevant crash/shutdown events found in the recent log window.")

def poll_for_crashes(interval_seconds=60, once=False):
    print("Starting Windows crash/shutdown log monitor")
    print("=" * 60)

    while True:
        print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking logs...")
        dump_relevant_events("System", max_events=100)
        dump_relevant_events("Application", max_events=100)

        if once:
            break

        print(f"Waiting {interval_seconds} seconds before next check...")
        time.sleep(interval_seconds)

def main():
    parser = argparse.ArgumentParser(description="Monitor Windows crash and shutdown events.")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds")
    parser.add_argument("--once", action="store_true", help="Check once and exit")
    args = parser.parse_args()

    poll_for_crashes(interval_seconds=args.interval, once=args.once)

if __name__ == "__main__":
    main()

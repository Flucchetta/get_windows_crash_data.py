import argparse
import datetime
import time

try:
    import win32evtlog
    import win32evtlogutil
except ImportError:
    raise SystemExit(
        "This script requires Windows and the pywin32 package.\n"
        "Install it with: pip install pywin32"
    )

# Focus on the most relevant crash/shutdown events.
CRASH_EVENT_IDS = {
    41,     # Kernel-Power: unexpected shutdown
    1001,   # Windows Error Reporting
    6008,   # Unexpected shutdown
    7034,   # Service crashed unexpectedly
}

# Related shutdown/restart events are useful, but they are not crashes.
SHUTDOWN_EVENT_IDS = {
    1074,   # System shutdown or restart (normal user-driven shutdown)
    1076,   # System shutdown due to error
}

CRASH_SOURCES = {
    "bugcheck",
    "application error",
    "windows error reporting",
}

EVENT_TYPE_NAMES = {
    0: "Unknown",
    1: "Error",
    2: "Warning",
    3: "Information",
    4: "Audit Success",
    5: "Audit Failure",
}


def get_event_time(event):
    try:
        time_generated = getattr(event, "TimeGenerated", None)
        if time_generated is None:
            return "unknown"
        if hasattr(time_generated, "Format"):
            return time_generated.Format()
        if isinstance(time_generated, datetime.datetime):
            return time_generated.strftime("%Y-%m-%d %H:%M:%S")
        return str(time_generated)
    except Exception:
        return "unknown"


def get_event_type_name(event_type):
    try:
        return EVENT_TYPE_NAMES.get(int(event_type), f"Unknown ({event_type})")
    except (TypeError, ValueError):
        return "Unknown"


def get_event_message(event, log_name=None):
    try:
        if log_name:
            try:
                formatted = win32evtlogutil.SafeFormatMessage(event, log_name)
                if formatted and formatted.strip():
                    return formatted.strip()
            except Exception:
                pass
    except Exception:
        pass

    inserts = getattr(event, "StringInserts", None)
    if inserts:
        try:
            return " ".join(str(x) for x in inserts)
        except Exception:
            return str(inserts)
    return "No description available"


def is_relevant_event(event, log_name=None):
    event_id = getattr(event, "EventID", 0) & 0xFFFF
    source = (getattr(event, "SourceName", "") or "").lower()

    if event_id in CRASH_EVENT_IDS:
        return True

    if event_id in SHUTDOWN_EVENT_IDS:
        message = get_event_message(event, log_name).lower()
        if "shutdown" in message or "restart" in message or "power" in message:
            return True

    if any(s in source for s in CRASH_SOURCES):
        return True

    message = get_event_message(event, log_name).lower()
    if "crash" in message or "unexpected shutdown" in message or "bugcheck" in message:
        return True

    return False


def read_recent_events(log_name, max_events=500):
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


def dump_relevant_events(log_name, max_events=500, last_seen=None):
    if last_seen is None:
        last_seen = {}

    found = False
    newest_record = last_seen.get(log_name, 0)

    for event in read_recent_events(log_name, max_events=max_events):
        record_number = getattr(event, "RecordNumber", 0)
        if record_number and record_number <= newest_record:
            continue

        if not is_relevant_event(event, log_name):
            continue

        found = True
        newest_record = max(newest_record, record_number)

        event_time = get_event_time(event)
        event_id = getattr(event, "EventID", 0) & 0xFFFF
        source = getattr(event, "SourceName", "Unknown")
        event_type = get_event_type_name(getattr(event, "EventType", 0))
        message = get_event_message(event, log_name)

        print(f"Time: {event_time}")
        print(f"Log: {log_name}")
        print(f"Source: {source}")
        print(f"Event ID: {event_id}")
        print(f"Event Type: {event_type}")
        print(f"Message: {message}")
        print("-" * 60)

    last_seen[log_name] = newest_record
    return last_seen


def poll_for_crashes(interval_seconds=60, once=False):
    print("Starting Windows crash/shutdown log monitor")
    print("=" * 60)
    last_seen = {}

    while True:
        print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking logs...")
        dump_relevant_events("System", max_events=500, last_seen=last_seen)
        dump_relevant_events("Application", max_events=500, last_seen=last_seen)

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

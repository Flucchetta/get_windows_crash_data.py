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

# Crash-related sources only; removed broad filters like "eventlog", "winlogon", "service control manager"
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
    """Safely extract event timestamp. Returns 'unknown' if parsing fails."""
    try:
        time_generated = getattr(event, "TimeGenerated", None)
        if time_generated is None:
            return "unknown"
        
        # Try Format() method first (newer pywin32 versions)
        if hasattr(time_generated, "Format"):
            formatted = time_generated.Format()
            if formatted:
                return formatted
        
        # Try as datetime object
        if isinstance(time_generated, datetime.datetime):
            return time_generated.strftime("%Y-%m-%d %H:%M:%S")
        
        # Fallback to string representation
        time_str = str(time_generated).strip()
        if time_str:
            return time_str
        
        return "unknown"
    except Exception:
        return "unknown"


def get_event_type_name(event_type):
    """Convert numeric event type to readable name."""
    try:
        type_int = int(event_type)
        return EVENT_TYPE_NAMES.get(type_int, f"Unknown ({type_int})")
    except (TypeError, ValueError):
        return "Unknown"


def get_event_message(event, log_name=None):
    """
    Extract event message with proper formatting.
    Tries SafeFormatMessage first, falls back to StringInserts.
    """
    # Try SafeFormatMessage for properly formatted message (best option)
    if log_name:
        try:
            formatted = win32evtlogutil.SafeFormatMessage(event, log_name)
            if formatted and isinstance(formatted, str) and formatted.strip():
                return formatted.strip()
        except Exception:
            pass
    
    # Fall back to StringInserts (raw event parameters)
    inserts = getattr(event, "StringInserts", None)
    if inserts:
        try:
            message_parts = [str(x).strip() for x in inserts if x]
            if message_parts:
                return " ".join(message_parts)
        except Exception:
            pass
    
    return "No description available"


def is_relevant_event(event, log_name=None):
    """
    Determine if an event is crash/shutdown-related.
    Checks event ID, source, and message content.
    """
    event_id = getattr(event, "EventID", 0) & 0xFFFF
    source = (getattr(event, "SourceName", "") or "").lower()

    # Check crash event IDs first
    if event_id in CRASH_EVENT_IDS:
        return True

    # For shutdown events, verify the message contains shutdown/restart keywords
    if event_id in SHUTDOWN_EVENT_IDS:
        message = get_event_message(event, log_name).lower()
        if any(keyword in message for keyword in ["shutdown", "restart", "power", "error"]):
            return True
        return False

    # Check crash-specific sources
    if any(s in source for s in CRASH_SOURCES):
        return True

    # Check message content for crash indicators
    message = get_event_message(event, log_name).lower()
    crash_indicators = ["crash", "unexpected shutdown", "bugcheck", "application error"]
    if any(indicator in message for indicator in crash_indicators):
        return True

    return False


def read_recent_events(log_name, max_events=500):
    """Read recent events from Windows event log. Returns list of event objects."""
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
    """
    Read and print crash/shutdown events, skipping duplicates.
    Tracks the highest RecordNumber to avoid re-printing the same events.
    """
    if last_seen is None:
        last_seen = {}

    found = False
    newest_record = last_seen.get(log_name, 0)

    for event in read_recent_events(log_name, max_events=max_events):
        record_number = getattr(event, "RecordNumber", 0)
        
        # Skip events we've already seen
        if record_number and record_number <= newest_record:
            continue

        # Skip non-relevant events
        if not is_relevant_event(event, log_name):
            continue

        # Found a new relevant event
        found = True
        if record_number:
            newest_record = max(newest_record, record_number)

        # Extract event details
        event_time = get_event_time(event)
        event_id = getattr(event, "EventID", 0) & 0xFFFF
        source = getattr(event, "SourceName", "Unknown")
        event_type = get_event_type_name(getattr(event, "EventType", 0))
        message = get_event_message(event, log_name)

        # Print event details
        print(f"Time: {event_time}")
        print(f"Log: {log_name}")
        print(f"Source: {source}")
        print(f"Event ID: {event_id}")
        print(f"Event Type: {event_type}")
        print(f"Message: {message}")
        print("-" * 60)

    # Update the last seen record number for this log
    if newest_record:
        last_seen[log_name] = newest_record

    if not found:
        print(f"[{log_name}] No relevant crash/shutdown events found in the recent log window.")

    return last_seen


def poll_for_crashes(interval_seconds=60, once=False):
    """
    Poll Windows event logs for crash/shutdown events.
    Runs continuously (unless once=True) at specified interval.
    """
    print("Starting Windows crash/shutdown log monitor")
    print("=" * 60)
    last_seen = {}

    while True:
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n[{current_time}] Checking logs...")
        
        # Check System log for kernel-power, unexpected shutdowns, etc.
        last_seen = dump_relevant_events("System", max_events=500, last_seen=last_seen)
        
        # Check Application log for application crashes
        last_seen = dump_relevant_events("Application", max_events=500, last_seen=last_seen)

        if once:
            break

        print(f"Waiting {interval_seconds} seconds before next check...")
        time.sleep(interval_seconds)


def main():
    """Main entry point. Parse arguments and start monitoring."""
    parser = argparse.ArgumentParser(
        description="Monitor Windows crash and shutdown events in System and Application logs."
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Polling interval in seconds (default: 60)"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Check logs once and exit (default: continuous polling)"
    )
    
    args = parser.parse_args()

    try:
        poll_for_crashes(interval_seconds=args.interval, once=args.once)
    except KeyboardInterrupt:
        print("\n\nMonitor stopped by user.")
    except Exception as exc:
        print(f"Fatal error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

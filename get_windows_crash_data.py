import win32evtlog
import datetime
import time

def get_windows_crash_data():
    # Define the log type to query (System or Application logs for crashes/errors)
    log_type = "System"
    server = "localhost"  # Local machine

    # Open the event log
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        print(f"Error opening event log: {e}")
        return

    # Flags to read the most recent events first
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    # Read events from the log
    print(f"\nRetrieving crash data and error messages from {log_type} log...\n")
    try:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        while events:
            for event in events:
                # Filter for Error (EventType 1) and Critical (EventType 5) events
                if event.EventType in (win32evtlog.EVENTLOG_ERROR_TYPE, win32evtlog.EVENTLOG_CRITICAL_TYPE):
                    event_time = event.TimeGenerated.Format()  # Format timestamp
                    source = event.SourceName
                    event_id = event.EventID & 0xFFFF  # Get lower 16 bits of EventID
                    description = event.StringInserts if event.StringInserts else ["No description available"]

                    print(f"Time: {event_time}")
                    print(f"Source: {source}")
                    print(f"Event ID: {event_id}")
                    print(f"Description: {description}")
                    print("-" * 50)

            # Read next batch of events
            events = win32evtlog.ReadEventLog(hand, flags, 0)

    except Exception as e:
        print(f"Error reading event log: {e}")
    finally:
        win32evtlog.CloseEventLog(hand)

def main():
    print("Starting Windows Crash Data and Error Log Retrieval")
    print("=" * 50)
    
    # Continuously check for new crash/error data (every 60 seconds)
    while True:
        get_windows_crash_data()
        print("Waiting for new events... (checking every 60 seconds)")
        time.sleep(60)

if __name__ == "__main__":
    main()
# Windows Crash Data Monitor

## Overview

This repository contains two variants of the same Windows crash/event-log monitor:

- `get_windows_crash_data.py` — console-based monitor that prints recent crash/shutdown-related events in real time.
- `get_windows_crash_data_export.py` — export-oriented variant that saves relevant events to JSON or CSV for analysis, logging, or archiving.

## Which version should I use?

- Use `get_windows_crash_data.py` if you want a quick live console monitor.
- Use `get_windows_crash_data_export.py` if you want to export events to a file for later review or automation.

## Example usage

Console monitor:

```bash
python get_windows_crash_data.py --once
python get_windows_crash_data.py --interval 60
```

Export variant:

```bash
python get_windows_crash_data_export.py --format json --output crashes.json --once
python get_windows_crash_data_export.py --format csv --output crashes.csv --interval 60
```

## Notes

- This script is intended for Windows environments.
- It requires `pywin32` (`pip install pywin32`).
- Event logs may require appropriate permissions depending on the machine and log access level.

## License

This project is provided as-is for local Windows troubleshooting and event-log analysis.

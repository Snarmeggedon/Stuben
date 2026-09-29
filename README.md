# Stuben

Stuben is a local desktop tool for scanning source files and directories for suspicious code patterns. It includes a Tkinter dashboard, threat scoring and reporting, a small local threat-intelligence dataset, and action-history/analytics helpers.

## Requirements

- Python 3 with Tkinter support
- Dependencies listed in `requirements.txt`

On Windows, install dependencies and launch the desktop app from this directory:

```powershell
py -m pip install -r requirements.txt
py agent.py desktop
```

Run a directory scan from the command line:

```powershell
py agent.py scan "C:\path\to\scan"
```

Run the focused false-positive regression tests:

```powershell
py -m unittest test_false_positive_reduction.py
```

## Notes

- Detection is based on static patterns and heuristics; findings need human review and this is not a substitute for endpoint protection.
- Local action history, generated analytics, credentials, quarantine contents, and Python cache files are excluded from Git.
- Gmail integration is currently an offline-safe placeholder and does not retrieve messages.
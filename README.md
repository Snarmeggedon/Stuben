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
- Gmail integration is read-only (`gmail.readonly` scope only).

## Email companion

Stuben vets your inbox from metadata only (sender/domain spoofing, SPF/DKIM/DMARC, links, risky attachments, phishing phrases) before any body is read, classifies each message as safe / suspicious / junk, and writes a markdown digest of safe mail only (job updates, important, FYI) plus counts of filtered items. Bodies of suspicious/junk mail are never opened. Gmail's short preview snippet is used for classification. Attachment filenames/types are read from message structure without decoding any content.

Setup (one-time): place the Google OAuth Desktop client JSON at `gmail_credentials.json` (gitignored), install deps (`py -m pip install -r requirements.txt`), then run the browser consent:

```powershell
py agent.py gmail-auth
```

Generate the digest (non-interactive once `gmail_token.json` exists; suitable for an 8 AM scheduled task):

```powershell
py agent.py email-digest [--query "in:inbox newer_than:1d"] [--limit 100] [--output digest.md]
```

Output defaults to `digests\email_digest_YYYY-MM-DD.md`. Tests: `py -m unittest test_email_digest.py`.
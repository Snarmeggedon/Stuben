# Daily Patch 2026-10-06

- Hardened the false-positive filter in analyzer.py. Lines with strong indicators (-enc, IEX, DownloadString, raw-IP URLs, base64 decoding) are never suppressed.
- Plain URLs and the word 'test' no longer suppress every line they appear on.
- Added a regression test. Email was not sent because the Gmail integration is a placeholder.
- Next: apply the same hardening to threat_scorer.py and threat_analyst.py, then commit and push.

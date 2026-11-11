# Daily Patch 2026-10-07

- Hardened threat_scorer.py and threat_analyst.py contextual filters. Strong indicators are never zeroed, and tokens now match on word boundaries ("latest" no longer counts as "test").
- Added a regression test. 7 tests pass.
- Email was not sent because the Gmail integration is a placeholder.
- Next: commit and push the accumulated changes, then add a scan benchmark.

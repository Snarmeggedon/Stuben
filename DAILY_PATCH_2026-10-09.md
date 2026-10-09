# Daily Patch 2026-10-09

- Added word boundaries to the 'c2 communication' and 'windows credential extraction' patterns. 'c2' no longer matches hex colors and 'SAM' no longer matches 'sample'.
- Self-scan findings dropped from 417 to 345 (about 17%).
- Added a regression test. 8 tests pass.
- Email was not sent because the Gmail integration is a placeholder.
- Next: review the 'browser credential theft' and 'secrets access' patterns for noise.

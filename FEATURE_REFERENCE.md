# Stuben Command Reference - New Autonomous Features

## Interactive Features (Built-in to Desktop App)

### Threat Score Display
When you run any scan, the right panel automatically shows:
```
⛔ THREAT SCORE: 8.5/10 (HIGH)
Attack: Advanced Persistent Threat (APT)
```

The threat score considers:
- Base severity of detected patterns
- Exploitability of each attack vector
- Whether multiple threat categories are chained together

### Per-Threat Questions & Actions
For each threat detected, Stuben automatically asks you a question and provides action buttons:

```
🔍 POWERSHELL EXECUTION (critical)
Q: Is this a legitimate development script or part of your build process?

→ Quarantine file
→ Review execution logs  
→ Check scheduled tasks
```

Each action button is clickable and executes immediately.

## Python API - Using New Modules

### View Action History
```python
from action_history import ActionHistory

history = ActionHistory()
print(history.get_action_summary())
# Output:
# {
#   "total_actions": 47,
#   "scans_run": 5,
#   "threats_found": 23,
#   "actions_taken": 12,
#   "user_responses": 8
# }

# Get recent actions
recent = history.get_recent_actions(limit=10)
for action in recent:
    print(f"{action['timestamp']}: {action['type']} - {action['action']}")

# Export full history
history.export_report("my_audit_trail.json")
```

### Threat Scoring
```python
from threat_scorer import EnhancedThreatScorer

scorer = EnhancedThreatScorer()

# Score a set of findings
findings = [
    {"pattern_name": "powershell execution", "severity": "critical"},
    {"pattern_name": "registry persistence", "severity": "high"},
]

score = scorer.calculate_cvss_score(findings)
print(f"Threat Score: {score:.1f}/10")  # Output: 8.2/10

# Get attack profile
profile = scorer.get_attack_profile(findings)
print(f"Attack Profile: {profile}")  # Output: Evasive Malware

# Get human-readable explanation
explanation = scorer.generate_scoring_explanation(findings)
print(explanation)
```

### Security Analytics
```python
from analytics_dashboard import StubensAnalyticsDashboard

dashboard = StubensAnalyticsDashboard()

# Get scan statistics
stats = dashboard.get_scan_statistics()
print(f"Scans run: {stats['total_scans']}")
print(f"Total files: {stats['total_files']}")
print(f"Average findings per scan: {stats['avg_findings_per_scan']:.1f}")

# Get threat trends
trends = dashboard.get_threat_trends()
print("Top threats:")
for threat, count in trends["top_threats"][:5]:
    print(f"  - {threat}: {count} detections")

# Get action effectiveness
effectiveness = dashboard.get_action_effectiveness()
print(f"Action success rate: {effectiveness['success_rate']:.1f}%")

# Generate daily report
report = dashboard.generate_daily_report()
print(report)

# Display dashboard summary
print(dashboard.format_dashboard_summary())

# Export for later analysis
dashboard.export_analytics_report("security_report.json")
```

### Performance Profiling
```python
from performance_profiler import PerformanceProfiler

profiler = PerformanceProfiler()

# Profile a single file
result = profiler.profile_file_scan("suspicious_script.py")
print(f"File scan time: {result['time_ms']:.2f}ms")
print(f"Findings: {result['findings']}")

# Profile a directory
result = profiler.profile_directory_scan("/home/user/projects", recursive=True)
print(f"Directory: {result['directory']}")
print(f"Files scanned: {result['files_scanned']}")
print(f"Total time: {result['time_seconds']:.2f}s")
print(f"Avg per file: {result['avg_ms_per_file']:.2f}ms")

# Get optimization recommendations
recs = profiler.get_optimization_recommendations(result)
for rec in recs:
    print(rec)
```

### UI Theme & Accessibility
```python
from ui_enhancements import UIThemeManager, AccessibilityOptions

# Switch themes
UIThemeManager.switch_theme("dark")   # or "light"
color = UIThemeManager.get_color("accent_critical")
print(f"Critical color: {color}")  # #fbbf24 (dark theme)

# Adjust font sizes
AccessibilityOptions.set_font_size("large")
size = AccessibilityOptions.get_font_size()
print(f"Current font size: {size}pt")

# Adjust contrast for accessibility
high_contrast_color = AccessibilityOptions.adjust_color_contrast("#60a5fa", multiplier=1.5)
print(f"High contrast: {high_contrast_color}")
```

## Command Line Tools

### View Analytics Dashboard
```bash
cd C:\Users\anoth\Stuben
python analytics_dashboard.py
```
Output:
```
📊 STUBEN SECURITY DASHBOARD
============================================================

📈 SCAN STATISTICS
  Total Scans Run:        12
  Files Scanned:          342
  Threats Detected:       87
  Avg. Threats/Scan:      7.25
  Avg. Scan Time:         3.45s

🎯 TOP THREATS (Last 1000 events)
  • powershell execution:................... 23 detected
  • domain request:......................... 18 detected
  • base64 encoding:........................ 15 detected
  • registry persistence:.................. 12 detected
  • eval execution:......................... 10 detected

👤 USER ENGAGEMENT
  Questions Answered:     31
  Actions Executed:       18
  Engagement Score:       2.45
```

### Profile Scanning Performance
```bash
python performance_profiler.py C:\Users\anoth\Downloads
```
Output:
```
PERFORMANCE PROFILE
============================================================
directory:...................................... C:\Users\anoth\Downloads
time_seconds:.................................. 1.24
files_scanned:.................................. 8
findings:....................................... 3
avg_ms_per_file:............................... 155.0

RECOMMENDATIONS
============================================================
🟡 Moderate file scanning speed (50-100ms/file): Can be optimized by pattern caching.
```

## Workflow Examples

### Example 1: Complete Security Incident Response
```python
from desktop_app import SecurityDashboard
from action_history import ActionHistory

# 1. Run scan (automatic)
# Click "AI Threat Scan" button in UI

# 2. Check what happened
history = ActionHistory()
recent = history.get_recent_actions(5)

# 3. Review threats
# Read threat explanations in right panel
# Click action buttons to execute recommended actions

# 4. Track the incident
audit_trail = history.export_report("incident_2026_09_21.json")
print(f"Incident audit trail saved to: {audit_trail}")
```

### Example 2: Track Performance Improvements
```python
from performance_profiler import PerformanceProfiler
from analytics_dashboard import StubensAnalyticsDashboard
import json
from datetime import datetime

profiler = PerformanceProfiler()
dashboard = StubensAnalyticsDashboard()

# Baseline scan
baseline = profiler.profile_directory_scan("/target/dir", recursive=True)
baseline["timestamp"] = datetime.now().isoformat()

# After optimization...

# New scan
optimized = profiler.profile_directory_scan("/target/dir", recursive=True)
optimized["timestamp"] = datetime.now().isoformat()

# Compare
speedup = baseline["avg_ms_per_file"] / optimized["avg_ms_per_file"]
print(f"Speedup: {speedup:.1f}x faster")

# Log to history
dashboard.export_analytics_report("performance_comparison.json")
```

### Example 3: Daily Security Report Generation
```python
from analytics_dashboard import StubensAnalyticsDashboard
from datetime import datetime

dashboard = StubensAnalyticsDashboard()

# Generate report
report = dashboard.generate_daily_report()

# Add timestamp
report["generated_at"] = datetime.now().isoformat()

# Export
output_file = dashboard.export_analytics_report(f"daily_report_{datetime.now().strftime('%Y%m%d')}.json")
print(f"Report saved to: {output_file}")

# Display summary
print(dashboard.format_dashboard_summary())
```

## File Locations

All persistent data is stored in the Stuben directory:
- `action_history.json` - Complete action log
- `analytics_report.json` - Latest analytics
- `quarantine/` - Quarantined files
- `reports/` - Generated reports (HTML, JSON, TXT)

## Key Features Summary

| Feature | Location | How to Use |
|---------|----------|-----------|
| Action Tracking | `action_history.py` | Automatic logging + manual API |
| Threat Scoring | `threat_scorer.py` | Automatic in right panel + API |
| Analytics | `analytics_dashboard.py` | Dashboard summary or API |
| Performance | `performance_profiler.py` | Command line or Python API |
| UI Themes | `ui_enhancements.py` | Python API for future UI updates |

---

**Remember**: Most features work automatically in the desktop app. These APIs are for advanced use cases and integration with other tools.

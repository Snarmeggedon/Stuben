# Stuben: Advanced Malicious Code Detection System

## Overview
Stuben is an offline-first security analysis system that detects malicious code patterns, AI-focused threats, and suspicious behavior. The system provides real-time threat assessment, per-threat recommendations, persistent action history, and CVSS-like threat scoring.

## New Features (Autonomous Improvements)

### 1. **Persistent Action History** (`action_history.py`)
- Tracks all user actions, recommendations accepted, and security decisions
- Stores in `action_history.json` for historical analysis
- Enables tracking of what was done, when, and with what result
- Methods:
  - `log_action()` - Log security actions taken
  - `log_scan()` - Log scan executions with metrics
  - `log_user_response()` - Track user responses to Stuben's questions
  - `get_recent_actions()` - Retrieve recent action history
  - `export_report()` - Export full action history

### 2. **Enhanced Threat Scoring** (`threat_scorer.py`)
- CVSS-like threat scoring (0-10 scale) with:
  - **Base Scores** per threat category (execution: 9.0, credential: 8.5, etc.)
  - **Exploitability Factors** (1.0-1.4 multipliers based on attack difficulty)
  - **Attack Complexity Modifiers** (critical/high/medium/low)
  - **Chaining Bonus** (15% boost for coordinated multi-category attacks)
- Attack Profile Detection: Identifies attack chains like APT, credential harvesting, evasive malware
- Risk Level Classification: CRITICAL (9.0+), HIGH (7.0+), MEDIUM (4.0+), LOW (<4.0)
- Methods:
  - `calculate_cvss_score()` - Calculate threat score
  - `get_attack_profile()` - Identify attack type
  - `get_risk_level()` - Convert score to risk level
  - `generate_scoring_explanation()` - Human-readable threat explanation

### 3. **Analytics Dashboard** (`analytics_dashboard.py`)
- Real-time security operations analytics
- Metrics tracked:
  - **Scan Statistics**: Total scans, files scanned, findings detected, avg scan time
  - **Threat Trends**: Top threats detected, frequency analysis
  - **Action Effectiveness**: Success rate of recommended actions
  - **User Engagement**: Questions answered, actions executed
- Methods:
  - `get_scan_statistics()` - Scan performance metrics
  - `get_threat_trends()` - Threat frequency analysis
  - `get_action_effectiveness()` - Action success rates
  - `get_user_engagement()` - User interaction metrics
  - `format_dashboard_summary()` - Display-ready summary
  - `export_analytics_report()` - Export as JSON

### 4. **Performance Profiler** (`performance_profiler.py`)
- Profile scanning performance at file and directory levels
- Identify bottlenecks and optimization opportunities
- Provide optimization recommendations
- Methods:
  - `profile_file_scan()` - Single file performance
  - `profile_directory_scan()` - Directory performance
  - `get_optimization_recommendations()` - Actionable advice

### 5. **UI/UX Enhancements** (`ui_enhancements.py`)
- Theme management (Dark/Light themes)
- Reusable UI component builders
- Accessibility options (font sizing, contrast adjustment)
- Consistent styling across all components

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    desktop_app.py                            │
│            Main UI orchestrator & controller                │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Threat Scan  │  │ Recommended  │  │  Action History  │   │
│  │   Engine     │  │   Actions    │  │    Tracking      │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │                 │                    │              │
├─────────┼─────────────────┼────────────────────┼──────────────┤
│  analyzer.py       threat_analyst.py    action_history.py    │
│  (41 patterns)     (risk scoring)       (persistent log)      │
├─────────────────────────────────────────────────────────────┤
│  threat_scorer.py      analytics_dashboard.py                │
│  (CVSS scoring)        (metrics & analytics)                 │
├─────────────────────────────────────────────────────────────┤
│  sec_advisor.py        report_generator.py                   │
│  (per-threat actions)  (text/json/html reports)             │
├─────────────────────────────────────────────────────────────┤
│  performance_profiler.py    ui_enhancements.py               │
│  (speed metrics)            (themes, accessibility)          │
└─────────────────────────────────────────────────────────────┘
```

## Detection Capabilities

### 41 Malicious Patterns Across 8 Categories

**Execution (5):** PowerShell, cmd, wget/curl, process creation, shell invocation
**Encoding (5):** Base64, eval, pickle, obfuscation, deobfuscation
**Network (5):** IPv4 beacons, domain requests, sockets, DNS, C2 communication
**Credential (5):** Browser creds, secrets, keylogging, credential dumping, Windows extraction
**Persistence (5):** Registry, scheduled tasks, startup folders, hive modification, service installation
**Obfuscation (5):** Sleep delays, random delays, anti-analysis, code injection, reflective loading
**AI Threats (5):** Prompt injection, agent hijacking, secret exfiltration, RAG poisoning, plugin abuse
**File Operations (6):** Deletion, writing, path traversal, DLL loading, batch execution, download & execute

### AI-Focused Threat Detection
- **Prompt Injection**: Detects attempts to manipulate AI models
- **Agent Hijacking**: Identifies unauthorized AI tool calls
- **Secret Exfiltration**: Finds API key/credential exposure
- **RAG Poisoning**: Detects training data corruption
- **Plugin Abuse**: Identifies malicious extension usage
- **Environment Variable Exposure**: Finds secret exposure in env vars

## Key Metrics

| Metric | Value |
|--------|-------|
| Detection Patterns | 41+ |
| Threat Categories | 8 |
| Scan Speed | 30-50x faster (with parallelization) |
| Threat Scoring | CVSS-like (0-10) |
| File Scanning | Parallel (8 concurrent) |
| Directory Scanning | Parallel (4 concurrent) |
| False Positive Reduction | Context-aware scoring |
| API Dependencies | 0 (offline only) |

## Usage

### Launch Desktop App
```bash
python agent.py desktop
```

### Analyze Files
- **Quick Actions**: Review file, assess threat, scan directory, AI threat scan
- **Per-Threat Actions**: Click action buttons to execute remediation
- **View Reports**: Export to HTML, JSON, or TXT

### Access Analytics
```bash
python analytics_dashboard.py  # View dashboard summary
```

### Profile Performance
```bash
python performance_profiler.py /path/to/scan
```

## Action History & Tracking

Actions are automatically logged to `action_history.json`:

```json
{
  "timestamp": "2026-09-21T16:23:02",
  "type": "action_taken",
  "threat_pattern": "powershell execution",
  "action": "Quarantine file",
  "success": true
}
```

Export full history with analytics:
```python
from action_history import ActionHistory
history = ActionHistory()
history.export_report()
```

## Threat Scoring Example

When a scan finds multiple threats:
1. **Base Score** calculated from threat categories (execution = 9.0)
2. **Exploitability** multiplied (PowerShell = 1.3x)
3. **Complexity** adjusted (critical severity = 1.0x)
4. **Chaining Bonus** applied if multiple categories (15% boost)

Result: **Score 8.5/10 = HIGH Risk | Advanced Persistent Threat**

## Autonomous Features

✅ **Action History** - Automatically tracks all security decisions
✅ **CVSS Scoring** - Automatically calculates threat severity
✅ **Analytics Dashboard** - Automatically generates metrics
✅ **Performance Profiling** - Automatically identifies bottlenecks
✅ **UI Enhancements** - Automatically manages themes and accessibility

## Future Improvements

- [ ] Add system monitoring during scans (CPU/memory/network)
- [ ] Integrate basic threat intelligence (known malware sigs, C2 IPs)
- [ ] Add ML-based false positive reduction
- [ ] Implement scheduled scans and alerts
- [ ] Add multi-user collaboration features
- [ ] Create mobile companion app

## License

Proprietary - Stuben Security Analysis System

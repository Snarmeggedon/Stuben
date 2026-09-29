class ReportGenerator:
    SEVERITY_ORDER = ("critical", "high", "medium", "low", "error")
    
    # Detailed explanations for each threat pattern
    THREAT_EXPLANATIONS = {
        "powershell execution": "PowerShell is often exploited to execute malicious scripts or commands with system privileges.",
        "cmd execution": "Command prompt execution can be used to run dangerous system commands or scripts.",
        "wget curl download": "Downloads from the internet can fetch malware or malicious payloads.",
        "process creation": "Creating child processes can indicate malware spawning secondary payloads.",
        "shell invocation": "Shell invocation (shell=True) can execute arbitrary commands and bypass input validation.",
        
        "base64 encoding": "Base64 encoding is commonly used to obfuscate malicious code or payloads.",
        "eval execution": "eval() executes arbitrary code and is a major security risk.",
        "pickle serialization": "Pickle deserialization can execute arbitrary code embedded in serialized objects.",
        "obfuscation": "Obfuscated code hides malicious intent and makes analysis harder.",
        "code deobfuscation": "Code deobfuscation tools may be used to hide malware capabilities.",
        
        "network beacon ipv4": "IP-based beaconing indicates C2 (command and control) communication.",
        "domain request": "Network requests to external domains could indicate data exfiltration or C2.",
        "socket connection": "Raw socket connections can be used for covert communication.",
        "dns resolution": "DNS queries can signal C2 communication or malware callbacks.",
        "c2 communication": "Command and control communication enables remote malware control.",
        
        "browser credential theft": "Stealing browser credentials grants access to accounts and sensitive data.",
        "secrets access": "Accessing API keys and secrets can lead to account compromise.",
        "keylogging": "Keylogging captures everything the user types, including passwords.",
        "credential dumping tools": "These tools extract credentials from memory or system storage.",
        "windows credential extraction": "Targets Windows credential storage for bulk credential theft.",
        
        "registry persistence": "Registry modifications ensure malware survives system restarts.",
        "scheduled task": "Scheduled tasks can execute malware on a recurring basis.",
        "startup folder": "Startup folder files auto-execute when Windows boots.",
        "registry hive modification": "Direct registry changes can enable persistence and escalation.",
        "service installation": "Malicious services run with system privileges automatically.",
        
        "sleep delay": "Sleep calls can evade automated detection and appear dormant.",
        "random delay": "Random delays make behavioral detection and analysis more difficult.",
        "anti-analysis": "Anti-analysis checks detect debuggers and prevent malware inspection.",
        "code injection": "Code injection modifies running process memory to inject malicious code.",
        "reflective loading": "Reflective loading loads code directly into memory without disk artifacts.",
        
        "prompt injection": "Prompt injection manipulates AI models to ignore safety guidelines.",
        "agent hijacking": "Hijacking AI tool calls enables unauthorized actions and data access.",
        "secret exfiltration": "Exfiltrating API keys and secrets compromises AI system security.",
        "rag poisoning": "Poisoning RAG systems corrupts AI decision-making with malicious information.",
        "plugin abuse": "Plugin abuse leverages AI extensions for unauthorized actions.",
        
        "file deletion": "Deleting files covers tracks and destroys evidence.",
        "file writing": "Writing files can create backdoors or plant malicious payloads.",
        "path traversal": "Path traversal bypasses directory restrictions to access sensitive files.",
        "dll loading": "Loading DLLs can inject malicious code into processes.",
        "batch script execution": "Batch scripts can execute arbitrary commands with elevated privileges.",
        "script download and execute": "Downloading and executing scripts enables remote code execution.",
    }

    @staticmethod
    def get_threat_explanation(pattern_name):
        """Get the explanation for a threat pattern."""
        return ReportGenerator.THREAT_EXPLANATIONS.get(
            pattern_name, 
            "Unknown threat pattern. Review the matched content carefully."
        )

    @staticmethod
    def _count_severities(findings):
        counts = {level: 0 for level in ReportGenerator.SEVERITY_ORDER}
        for item in findings:
            severity = item.get("severity", "low")
            if severity in counts:
                counts[severity] += 1
        return counts

    def generate(self, findings, output='text'):
        if output == 'json':
            return {"findings": findings}

        if output == 'html':
            return self._generate_html(findings)

        return self._generate_text(findings)

    def _generate_text(self, findings):
        if not findings:
            return "SCAN\n[OK] No suspicious indicators found."

        lines = ["SCAN", f"Findings: {len(findings)}"]
        severity_counts = self._count_severities(findings)
        summary = ", ".join(
            f"{level}={count}"
            for level, count in severity_counts.items()
            if count
        )
        lines.append(f"Severity: {summary}")
        lines.append("")

        for idx, item in enumerate(findings[:10], start=1):
            file_name = item.get("file", "unknown")
            line_num = item.get("line", "?")
            pattern = item.get("pattern_name", "suspicious")
            match = item.get("malicious_line", "")
            severity = item.get("severity", "low").upper()
            
            lines.append(f"\n[{idx}] {pattern.upper()}")
            lines.append(f"    Severity: {severity}")
            lines.append(f"    Location: {file_name}:{line_num}")
            lines.append(f"    Match: {match[:120]}")
            
            explanation = self.THREAT_EXPLANATIONS.get(pattern, "Unknown threat pattern.")
            lines.append(f"    Why it matters: {explanation}")

        if len(findings) > 10:
            lines.append(f"\n... and {len(findings) - 10} more findings (see HTML report for details)")

        return "\n".join(lines)

    def _generate_html(self, findings):
        if not findings:
            return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Stuben Security Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1220; color: #e5e7eb; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #93c5fd; border-bottom: 2px solid #1e3a8a; padding-bottom: 10px; }
        .summary { background: #111827; padding: 15px; border-radius: 6px; margin: 20px 0; }
        .ok { color: #4ade80; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Stuben Security Scan Report</h1>
        <div class="summary">
            <p class="ok">✓ No suspicious indicators found.</p>
        </div>
    </div>
</body>
</html>"""

        severity_counts = self._count_severities(findings)
        severity_colors = {
            "critical": "#f87171",
            "high": "#fb923c",
            "medium": "#fbbf24",
            "low": "#60a5fa",
            "error": "#6b7280"
        }

        rows = ""
        for item in findings:
            severity = item.get("severity", "low")
            color = severity_colors.get(severity, "#60a5fa")
            pattern = item.get("pattern_name", "suspicious")
            explanation = self.THREAT_EXPLANATIONS.get(pattern, "Unknown threat pattern.")
            rows += f"""
        <tr style="border-bottom: 1px solid #1f2937;">
            <td style="padding: 12px; color: #cbd5e1;">{item.get('file', 'unknown')}</td>
            <td style="padding: 12px; text-align: center; color: #cbd5e1;">{item.get('line', '?')}</td>
            <td style="padding: 12px;"><span style="background: {color}; color: #000; padding: 4px 8px; border-radius: 4px; font-weight: bold;">{severity.upper()}</span></td>
            <td style="padding: 12px; color: #cbd5e1;">{pattern}</td>
            <td style="padding: 12px; color: #9ca3af; font-family: monospace; font-size: 12px;">{item.get('malicious_line', '')[:120]}</td>
            <td style="padding: 12px; color: #cbd5e1; font-size: 13px;">{explanation}</td>
        </tr>"""

        severity_summary = "".join(
            f"<li><strong>{level.upper()}:</strong> {count}</li>"
            for level, count in severity_counts.items()
            if count
        )

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Stuben Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1220; color: #e5e7eb; margin: 0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #93c5fd; border-bottom: 2px solid #1e3a8a; padding-bottom: 10px; }}
        .summary {{ background: #111827; padding: 20px; border-radius: 6px; margin: 20px 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #1f2937; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-label {{ color: #9ca3af; font-size: 12px; margin-bottom: 5px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; }}
        .critical-color {{ color: #f87171; }}
        .high-color {{ color: #fb923c; }}
        .medium-color {{ color: #fbbf24; }}
        .low-color {{ color: #60a5fa; }}
        table {{ width: 100%; border-collapse: collapse; background: #111827; border-radius: 6px; overflow: hidden; margin-top: 20px; }}
        th {{ background: #1f2937; color: #cbd5e1; padding: 12px; text-align: left; font-weight: 600; }}
        tr:hover {{ background: #1f2937; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Stuben Security Scan Report</h1>
        <div class="summary">
            <p>Scan completed with <strong>{len(findings)}</strong> finding(s) detected.</p>
        </div>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{len(findings)}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Critical</div>
                <div class="stat-value critical-color">{severity_counts.get('critical', 0)}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">High</div>
                <div class="stat-value high-color">{severity_counts.get('high', 0)}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Medium</div>
                <div class="stat-value medium-color">{severity_counts.get('medium', 0)}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Low</div>
                <div class="stat-value low-color">{severity_counts.get('low', 0)}</div>
            </div>
        </div>
        <table>
            <thead>
                <tr style="background: #1f2937;">
                    <th>File</th>
                    <th style="width: 60px; text-align: center;">Line</th>
                    <th style="width: 100px;">Severity</th>
                    <th>Pattern</th>
                    <th style="width: 25%;">Match</th>
                    <th style="width: 35%;">Why It Matters</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return html

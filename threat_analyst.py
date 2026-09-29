import re


class ThreatAnalyst:
    SEVERITY_WEIGHTS = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    
    # Reference threat explanations
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

    def assess_threat(self, findings, file_path):
        if not findings:
            return {
                "threat_level": "safe",
                "risk_score": 0,
                "malware_type": "none",
                "attack_vectors": [],
                "reasons": ["No suspicious code detected."],
            }

        categories = {finding.get("category", "misc") for finding in findings}
        severities = {finding.get("severity", "info") for finding in findings}

        score = sum(
            self.SEVERITY_WEIGHTS.get(finding.get("severity", "low"), 1)
            for finding in findings
        )
        if findings and all(self._is_likely_contextual_false_positive(f) for f in findings):
            score = 0
        score = min(score, 10)

        if "critical" in severities:
            level = "critical"
        elif "high" in severities:
            level = "high"
        elif "medium" in severities:
            level = "medium"
        else:
            level = "low"

        attack_vectors = sorted(categories)
        malware = (
            "trojan-like payload"
            if "execution" in categories or "network" in categories
            else "suspicious script"
        )
        
        # Build detailed reasons including threat explanations
        reasons = [f"Detected {len(findings)} suspicious indicators in {file_path}."]
        unique_patterns = set()
        for finding in findings:
            pattern = finding.get("pattern_name", "")
            if pattern and pattern not in unique_patterns:
                explanation = self.THREAT_EXPLANATIONS.get(pattern, "Suspicious code pattern detected.")
                reasons.append(f"• {pattern}: {explanation}")
                unique_patterns.add(pattern)

        return {
            "threat_level": level,
            "risk_score": score,
            "malware_type": malware,
            "attack_vectors": attack_vectors,
            "reasons": reasons[:8],  # Limit to top 8 reasons
        }

    @staticmethod
    def _is_likely_contextual_false_positive(finding):
        text = " ".join(
            str(finding.get(key, "")).lower()
            for key in ("pattern_name", "malicious_line", "match", "file")
        )
        return any(token in text for token in ("example", "sample", "documentation", "readme", "tutorial", "test", "benign", "safe"))

    def extract_ips(self, findings):
        text = "\n".join(
            str(item.get("malicious_line", ""))
            for item in findings
            if item.get("malicious_line")
        )
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        result = {}
        for ip in sorted(set(ips)):
            result[ip] = {"ip": ip, "type": "candidate"}
        return result

    def extract_iocs(self, content):
        if not isinstance(content, str):
            content = str(content)

        domains = sorted(set(re.findall(r"https?://([A-Za-z0-9.-]+)", content)))
        ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))
        return {"domains": domains[:10], "ips": ips[:10]}

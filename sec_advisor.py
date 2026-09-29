class SecurityAdvisor:
    # Reference threat explanations from ReportGenerator
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
    
    # Per-threat recommendations and questions
    THREAT_ACTIONS = {
        "powershell execution": {
            "actions": ["Quarantine file", "Review execution logs", "Check scheduled tasks", "Disable PowerShell"],
            "question": "Is this a legitimate development script or part of your build process?",
        },
        "cmd execution": {
            "actions": ["Quarantine file", "Check process history", "Review command logs", "Block execution"],
            "question": "Did you intentionally create this file or install an application that uses cmd.exe?",
        },
        "wget curl download": {
            "actions": ["Block URL", "Inspect network logs", "Check firewall rules", "Analyze destination"],
            "question": "Do you recognize the download source? Is this a legitimate dependency?",
        },
        "process creation": {
            "actions": ["Terminate process", "Review child processes", "Check parent process", "Monitor execution"],
            "question": "Are you expecting this application to spawn child processes?",
        },
        "shell invocation": {
            "actions": ["Refactor code", "Use safe alternatives", "Remove shell=True", "Code review needed"],
            "question": "Can this be refactored to avoid shell invocation?",
        },
        
        "base64 encoding": {
            "actions": ["Decode and inspect", "Review purpose", "Check for obfuscation", "Get source review"],
            "question": "Why is base64 encoding needed here? Is this legitimate serialization?",
        },
        "eval execution": {
            "actions": ["Replace with safe alternative", "Remove eval()", "Code refactor required", "Security review"],
            "question": "Can this functionality be achieved without using eval()?",
        },
        "pickle serialization": {
            "actions": ["Use json instead", "Validate sources", "Sandboxing recommended", "Code review"],
            "question": "Do you control the source of pickled data? Consider using JSON instead.",
        },
        "obfuscation": {
            "actions": ["Deobfuscate code", "Analyze intent", "Security review needed", "Check dependencies"],
            "question": "Why is this code obfuscated? Is this from a trusted vendor?",
        },
        "code deobfuscation": {
            "actions": ["Check for malware", "Analyze deobfuscated code", "Review dependencies", "Source review"],
            "question": "Are you intentionally deobfuscating code? What is the legitimate purpose?",
        },
        
        "network beacon ipv4": {
            "actions": ["Block IP", "Quarantine file", "Check firewall logs", "Network isolation"],
            "question": "Is this connection to a known C2 server? Should this IP be blocked?",
        },
        "domain request": {
            "actions": ["Block domain", "Inspect traffic", "Check DNS logs", "Firewall rule"],
            "question": "Is this domain request legitimate? Do you recognize the destination?",
        },
        "socket connection": {
            "actions": ["Block socket", "Monitor connection", "Firewall rule", "Network inspection"],
            "question": "Is this socket communication expected? What data is being transmitted?",
        },
        "dns resolution": {
            "actions": ["Check DNS logs", "Block domain", "Monitor queries", "Firewall block"],
            "question": "Are these DNS queries legitimate? Do you recognize the domains?",
        },
        "c2 communication": {
            "actions": ["Isolate system", "Block all traffic", "Deep inspection needed", "Incident response"],
            "question": "This indicates command & control. Should you isolate this system?",
        },
        
        "browser credential theft": {
            "actions": ["Change passwords", "Reset browser", "Monitor accounts", "MFA enable"],
            "question": "Should you change passwords for compromised browser accounts?",
        },
        "secrets access": {
            "actions": ["Revoke API keys", "Rotate secrets", "Check audit logs", "Update credentials"],
            "question": "Have any of your API keys or secrets been exposed? Time to rotate them.",
        },
        "keylogging": {
            "actions": ["Quarantine", "Change passwords", "Monitor system", "Remove malware"],
            "question": "This captures keystrokes. Should you reset all passwords immediately?",
        },
        "credential dumping tools": {
            "actions": ["Isolate system", "Password reset", "Credential rotation", "MFA enable"],
            "question": "Are credential extraction tools present? Consider isolating the system.",
        },
        "windows credential extraction": {
            "actions": ["Reset credentials", "Audit access", "Check SAM", "System isolation"],
            "question": "Windows credentials may be compromised. Should you rotate all passwords?",
        },
        
        "registry persistence": {
            "actions": ["Clean registry", "Remove startup", "Monitor auto-start", "System cleanup"],
            "question": "This tries to persist on restart. Should you remove the registry entry?",
        },
        "scheduled task": {
            "actions": ["Delete task", "Check taskschd.msc", "Review history", "Monitor scheduler"],
            "question": "Is this scheduled task legitimate? Should you delete it?",
        },
        "startup folder": {
            "actions": ["Remove file", "Check startup folder", "Verify legitimacy", "Monitor auto-start"],
            "question": "Do you recognize this startup file? Is it supposed to auto-run?",
        },
        "registry hive modification": {
            "actions": ["Restore registry", "Check backups", "Monitor changes", "System scan"],
            "question": "Registry hives are modified. Should you restore from a backup?",
        },
        "service installation": {
            "actions": ["Remove service", "Check services.msc", "Audit start type", "System cleanup"],
            "question": "Is this system service legitimate? Should it be uninstalled?",
        },
        
        "sleep delay": {
            "actions": ["Analyze code", "Understand purpose", "Code review", "Check for malware"],
            "question": "Why does this code sleep? Is it trying to evade detection?",
        },
        "random delay": {
            "actions": ["Analyze timing", "Understand purpose", "Code inspection", "Behavioral analysis"],
            "question": "Random delays can hide malicious behavior. Review the code logic.",
        },
        "anti-analysis": {
            "actions": ["Advanced analysis needed", "Sandbox execution", "Check for VM detection", "Decompile code"],
            "question": "This code detects debugging. Is this intentional obfuscation?",
        },
        "code injection": {
            "actions": ["Quarantine", "Memory inspection", "Process analysis", "Malware removal"],
            "question": "Code injection detected. Is memory of running processes affected?",
        },
        "reflective loading": {
            "actions": ["Memory forensics", "Process dump", "Behavioral monitor", "Incident response"],
            "question": "Reflective loading bypasses disk artifacts. Deep inspection needed.",
        },
        
        "prompt injection": {
            "actions": ["Input validation", "Prompt filtering", "Sandbox AI", "Code review"],
            "question": "Is user input being passed to AI without proper validation?",
        },
        "agent hijacking": {
            "actions": ["Verify tool calls", "Access control", "Audit logs", "API restrictions"],
            "question": "Are AI tool calls properly authenticated and authorized?",
        },
        "secret exfiltration": {
            "actions": ["Rotate secrets", "Audit access", "Add logging", "Monitor API"],
            "question": "Are API keys/secrets being exposed to AI or external services?",
        },
        "rag poisoning": {
            "actions": ["Validate training data", "Data integrity checks", "Audit sources", "Update models"],
            "question": "Is RAG training data from trusted sources? Check integrity.",
        },
        "plugin abuse": {
            "actions": ["Verify plugins", "Code review", "Sandbox execution", "Update policies"],
            "question": "Are plugins from trusted sources? Do they need additional permissions?",
        },
        
        "file deletion": {
            "actions": ["Check recycle bin", "File recovery", "Audit logs", "Forensics"],
            "question": "Are important files being deleted? Enable file versioning.",
        },
        "file writing": {
            "actions": ["Monitor file access", "Verify legitimacy", "Backup check", "Integrity check"],
            "question": "Are unexpected files being written? Check if they're malicious.",
        },
        "path traversal": {
            "actions": ["Input validation", "Path sanitization", "Code review", "Security fix"],
            "question": "Can this code access files outside intended directory?",
        },
        "dll loading": {
            "actions": ["Verify DLL source", "Code signing check", "Reputation scan", "Sandboxing"],
            "question": "Is the DLL from a trusted source? Check signature and reputation.",
        },
        "batch script execution": {
            "actions": ["Review script", "Remove batch file", "Code analysis", "Execution policy"],
            "question": "What does this batch script do? Is it supposed to run?",
        },
        "script download and execute": {
            "actions": ["Quarantine", "Block URL", "Network isolation", "Malware removal"],
            "question": "This downloads and runs remote code. Should you isolate this system?",
        },
    }
    
    @staticmethod
    def _matches_any(text, keywords):
        return any(keyword in text for keyword in keywords)
    
    def get_threat_explanation(self, pattern_name):
        """Get explanation for a threat pattern."""
        return self.THREAT_EXPLANATIONS.get(
            pattern_name,
            "Unknown threat pattern. Review the matched content carefully."
        )
    
    def get_threat_actions(self, pattern_name):
        """Get recommended actions for a specific threat pattern."""
        return self.THREAT_ACTIONS.get(
            pattern_name.lower(),
            {
                "actions": ["Review findings", "Manual investigation needed", "Consult security team"],
                "question": "What is the legitimate purpose of this code?",
            }
        )
    
    def get_threat_question(self, pattern_name):
        """Get question to ask user about a specific threat."""
        actions = self.get_threat_actions(pattern_name)
        return actions.get("question", "Is this code behavior expected?")
    
    def format_threat_with_actions(self, finding):
        """Format a finding with its threat explanation and recommended actions."""
        pattern = finding.get("pattern_name", "unknown")
        match_text = finding.get("malicious_line", "")
        location = finding.get("location", "")
        severity = finding.get("severity", "medium")
        
        explanation = self.get_threat_explanation(pattern)
        threat_info = self.get_threat_actions(pattern)
        
        return {
            "pattern": pattern,
            "severity": severity,
            "location": location,
            "match": match_text[:100] + ("..." if len(match_text) > 100 else ""),
            "explanation": explanation,
            "actions": threat_info.get("actions", []),
            "question": threat_info.get("question", "Is this expected?"),
        }

    def get_remediation_advice(self, finding):
        lower = (finding or '').lower()
        advice = {"immediate": [], "short_term": [], "long_term": []}

        if self._matches_any(lower, ('powershell', 'cmd', 'start-process', 'wmic', 'rundll32')):
            advice["immediate"] = ["Disable the script and isolate the host from the network."]
            advice["short_term"] = ["Review recent execution logs and scheduled tasks."]
            advice["long_term"] = ["Apply PowerShell execution policies and EDR monitoring."]
        elif self._matches_any(lower, ('http', 'socket', 'curl', 'wget', 'invoke-webrequest', 'requests')):
            advice["immediate"] = ["Block outbound connections to the associated external host."]
            advice["short_term"] = ["Inspect firewall and DNS logs for beaconing."]
            advice["long_term"] = ["Require signed scripts and monitor network egress."]
        else:
            advice["immediate"] = ["Quarantine the file and review the source context."]
            advice["short_term"] = ["Compare with known-good baselines and remove malicious artifacts."]
            advice["long_term"] = ["Add static checks to CI and maintain safe execution policies."]

        return advice

    def get_recommendation_list(self, finding):
        advice = self.get_remediation_advice(finding)
        recommendations = []
        for priority in ("immediate", "short_term", "long_term"):
            for item in advice.get(priority, []):
                if item not in recommendations:
                    recommendations.append(item)
        return recommendations

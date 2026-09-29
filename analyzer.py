import re
from pathlib import Path
from threat_intelligence import ThreatIntelligenceDB


class CodeAnalyzer:
    PATTERNS = [
        # Execution (execution)
        ("powershell execution", "execution", "critical", r"powershell\s*\.exe|PowerShell|Invoke-Expression|IEX\s*\(|Start-Process|cmd\.exe\s*/c"),
        ("cmd execution", "execution", "critical", r"cmd\.exe|cmd\s+/c|cmd\s+/k"),
        ("wget curl download", "execution", "high", r"wget\s+http|curl\s+http|wget\(|curl\("),
        ("process creation", "execution", "critical", r"CreateProcess|CreateProcessA|CreateProcessW|WinExec"),
        ("shell invocation", "execution", "high", r"shell\s*=\s*True|shell=True|shell=\"True\"|subprocess\.call|subprocess\.run|os\.system"),

        # Encoding (encoding)
        ("base64 encoding", "encoding", "high", r"base64|FromBase64String|b64decode|btoa|atob"),
        ("eval execution", "encoding", "critical", r"\beval\s*\(|\bexec\s*\(|compile\s*\("),
        ("pickle serialization", "encoding", "high", r"pickle\.loads|pickle\.load|marshal\.loads|pickle\.dumps"),
        ("obfuscation", "encoding", "medium", r"obfusc|obfus|hidden|dropper|gcod|xor|rot13"),
        ("code deobfuscation", "encoding", "medium", r"deobfus|deflate|gunzip|decompress|unescape"),

        # Network (network)
        ("network beacon ipv4", "network", "high", r"http[s]?://\d+\.\d+\.\d+\.\d+|https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        ("domain request", "network", "high", r"https?://[A-Za-z0-9][A-Za-z0-9.-]*\.[a-z]{2,}"),
        ("socket connection", "network", "high", r"socket\.|requests\.|urllib\.|Invoke-WebRequest"),
        ("dns resolution", "network", "medium", r"gethostbyname|getaddrinfo|nslookup|Resolve-DnsName"),
        ("c2 communication", "network", "critical", r"beacon|c2|command.?and.?control|remote.?access"),

        # Credential Theft (credential)
        ("browser credential theft", "credential", "critical", r"browser\.|credential|password|passwd"),
        ("secrets access", "credential", "critical", r"secrets|token|api.?key|apikey|secret.?key"),
        ("keylogging", "credential", "critical", r"keylogger|key.?log|GetAsyncKeyState|SetWindowsHookEx"),
        ("credential dumping tools", "credential", "critical", r"Get-Credential|Mimikatz|rundll32|regsvr32"),
        ("windows credential extraction", "credential", "critical", r"SAM|HKLM\\Security|credential manager|LSA"),

        # Persistence (persistence)
        ("registry persistence", "persistence", "high", r"RunOnce|HKCU.*Run|HKLM.*Run|CurrentVersion.*Run"),
        ("scheduled task", "persistence", "high", r"schtasks|TaskScheduler|New-ScheduledTask|at\s+\*"),
        ("startup folder", "persistence", "high", r"startup|autorun|startup folder|All Users.*Startup"),
        ("registry hive modification", "persistence", "high", r"reg add|reg.exe|RegOpenKeyEx|RegSetValueEx"),
        ("service installation", "persistence", "high", r"CreateService|InstallService|New-Service|sc create"),

        # Obfuscation/Evasion (obfuscation)
        ("sleep delay", "obfuscation", "medium", r"sleep\(|time\.sleep|Start-Sleep|[Ss]tart-[Ss]leep"),
        ("random delay", "obfuscation", "medium", r"random\.randint|Random\(|RandomDelay|jitter"),
        ("anti-analysis", "obfuscation", "medium", r"isDebuggerPresent|IsProcessorFeaturePresent|get_magic_name"),
        ("code injection", "obfuscation", "critical", r"WriteProcessMemory|CreateRemoteThread|VirtualAllocEx|SetWindowLong"),
        ("reflective loading", "obfuscation", "high", r"reflection|Reflection|LoadModule|Reflection\.Assembly"),

        # AI/LLM Threats (ai_threat)
        ("prompt injection", "ai_threat", "critical", r"ignore (all|previous) instructions|system prompt|developer message|jailbreak|override policy|do anything now|prompt injection|roleplay as|you are now|bypass safeguards"),
        ("agent hijacking", "ai_threat", "critical", r"tool call|function call|agent loop|execute this command|run the next tool|use your tools to|hidden instruction|autonomous agent|workflow hijack"),
        ("secret exfiltration", "ai_threat", "critical", r"api key|secret key|openai api|anthropic api|gemini api|token leak|exfiltrate|send secrets|dump credentials|read env|environment variables"),
        ("rag poisoning", "ai_threat", "high", r"poisoned document|malicious corpus|retrieval augmented|RAG|embedding poisoning|knowledge base injection|vector store|malicious context"),
        ("plugin abuse", "ai_threat", "high", r"browser agent|plugin|extension|MCP|tool misuse|connector abuse|prompt to the plugin|download and run|open this link|upload your data"),

        # File/System Operations (file_ops)
        ("file deletion", "file_ops", "high", r"unlink|remove\(|os\.remove|File\.Delete|DeleteFile"),
        ("file writing", "file_ops", "high", r"write_bytes|write_text|\.write\(|fopen.*w|FileWriter"),
        ("path traversal", "file_ops", "high", r"\.\./|\.\.\x5c|path.?traversal|directory.?traversal"),
        ("dll loading", "file_ops", "high", r"LoadLibrary|load_dll|import_dll|ctypes\.CDLL|windll\."),
        ("batch script execution", "file_ops", "high", r"\.bat|\.cmd|batch file|@echo off"),
        ("script download and execute", "file_ops", "critical", r"download.*execute|fetch.*run|pull.*code"),
    ]

    SCANNABLE_SUFFIXES = {'.py', '.ps1', '.bat', '.cmd', '.js', '.vbs', '.txt', '.sh', '.yaml', '.yml', '.json', '.html', '.hta', '.exe'}
    LEGITIMATE_CONTEXT_PATTERNS = (
        re.compile(r'^(?:#|//|/\*|\*|<!--)', re.I),
        re.compile(r'\b(?:example|sample|demo|documentation|docs?|readme|tutorial|test|tests?)\b', re.I),
        re.compile(r'\b(?:safe|benign|legitimate|trusted|approved|allowlist|whitelist)\b', re.I),
    )
    
    def __init__(self):
        # Pre-compile all regex patterns at startup for maximum speed
        self._compiled_patterns = []
        for pattern_name, category, severity, regex in self.PATTERNS:
            try:
                compiled = re.compile(regex, re.I | re.M)
                self._compiled_patterns.append((pattern_name, category, severity, compiled))
            except Exception:
                pass  # Skip invalid patterns
        
        # Initialize threat intelligence database
        try:
            self.threat_intel = ThreatIntelligenceDB()
        except Exception:
            self.threat_intel = None  # Graceful fallback

    @staticmethod
    def _build_missing_result(path, kind):
        return [{
            "file": str(path),
            "severity": "error",
            "pattern_name": f"missing {kind}",
            "category": "filesystem",
            "malicious_line": f"{kind.capitalize()} not found: {path}",
            "line": 0,
        }]

    @staticmethod
    def _build_read_error(path):
        return [{
            "file": str(path),
            "severity": "error",
            "pattern_name": "read error",
            "category": "filesystem",
            "malicious_line": f"Could not read: {path}",
            "line": 0,
        }]

    def analyze_file(self, file_path):
        path = Path(file_path)
        if not path.exists():
            return self._build_missing_result(path, 'file')
        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return self._build_read_error(path)
        return self.analyze_content(content, str(path))

    def analyze_directory(self, directory, recursive=True):
        path = Path(directory)
        if not path.exists():
            return self._build_missing_result(path, 'directory')

        findings = []
        try:
            items = sorted(path.iterdir())
        except PermissionError:
            # Can't access this directory (common in system folders like $RECYCLE.BIN)
            return findings
        except Exception:
            # Other errors (e.g., symlink loops)
            return findings
        
        for item in items:
            try:
                if item.is_dir() and recursive:
                    findings.extend(self.analyze_directory(item, recursive=True))
                elif item.is_file() and item.suffix.lower() in self.SCANNABLE_SUFFIXES:
                    findings.extend(self.analyze_file(str(item)))
            except PermissionError:
                # Skip files/dirs we can't access
                continue
            except Exception:
                # Skip other errors
                continue
        return findings

    def analyze_content(self, content, source_name):
        findings = []
        lines = content.splitlines()

        # Use pre-compiled patterns for speed
        for pattern_name, category, severity, compiled in self._compiled_patterns:
            for index, line in enumerate(lines, start=1):
                if compiled.search(line):
                    if self._is_likely_contextual_false_positive(line):
                        continue
                    findings.append({
                        "file": source_name,
                        "line": index,
                        "pattern_name": pattern_name,
                        "category": category,
                        "severity": severity,
                        "malicious_line": line.strip(),
                        "match": line.strip(),
                    })
        return findings

    def _is_likely_contextual_false_positive(self, line):
        stripped = line.strip()
        if not stripped:
            return True

        lower = stripped.lower()
        if any(pattern.search(stripped) for pattern in self.LEGITIMATE_CONTEXT_PATTERNS):
            return True

        if stripped.startswith(("http://", "https://")):
            return True

        if any(token in lower for token in ("https://", "http://", "www.")) and "download and execute" not in lower:
            return True

        return False

"""
Enhanced threat scoring with CVSS-like methodology.
Considers impact, exploitability, and attack complexity.
"""


class EnhancedThreatScorer:
    """Score threats with CVSS-like methodology."""
    
    # Base scores for threat categories (impact)
    CATEGORY_BASE_SCORES = {
        "execution": 9.0,         # Highest impact - immediate code execution
        "credential": 8.5,        # High impact - full account compromise
        "persistence": 8.0,       # High impact - maintains access
        "network": 7.5,           # High impact - remote communication
        "ai_threat": 7.5,         # High impact - AI system compromise
        "obfuscation": 6.0,       # Medium impact - hides intent
        "file_ops": 5.5,          # Medium impact - file manipulation
        "encoding": 5.0,          # Lower impact - mainly obfuscation
    }
    
    # Exploitability modifiers
    EXPLOITABILITY_FACTORS = {
        "powershell execution": 1.3,          # Easily exploitable
        "cmd execution": 1.3,                 # Easily exploitable
        "c2 communication": 1.4,              # Highly exploitable for attacks
        "script download and execute": 1.4,  # Remote code execution
        "shell invocation": 1.3,              # Easily exploitable
        "eval execution": 1.3,                # Easily exploitable
        "code injection": 1.35,               # Complex but effective
        "dll loading": 1.3,                   # Common attack vector
        "agent hijacking": 1.25,              # Requires context
        "prompt injection": 1.2,              # Requires crafted input
        "plugin abuse": 1.15,                 # Requires extension
    }
    
    # Attack complexity modifiers (lower = more complex)
    ATTACK_COMPLEXITY = {
        "critical": 1.0,  # No complexity - instant impact
        "high": 0.95,     # Low complexity
        "medium": 0.85,   # Medium complexity
        "low": 0.7,       # High complexity
    }
    
    # Context factors (increases score if multiple patterns from same category)
    CHAINING_BONUS = 1.15  # 15% bonus if multiple threats indicate coordinated attack
    
    def calculate_cvss_score(self, findings):
        """
        Calculate a CVSS-like score (0-10) for a set of findings.
        
        Args:
            findings: List of finding dictionaries with pattern_name and severity
            
        Returns:
            Float score 0-10
        """
        if not findings:
            return 0.0
        
        # Get base score from most severe category
        max_base_score = 0.0
        categories_found = set()
        
        for finding in findings:
            category = finding.get("category", "misc")
            categories_found.add(category)
            
            base_score = self.CATEGORY_BASE_SCORES.get(category, 5.0)
            pattern = finding.get("pattern_name", "").lower()
            severity = finding.get("severity", "low")
            
            # Apply exploitability multiplier
            exploit_mult = self.EXPLOITABILITY_FACTORS.get(pattern, 1.0)
            
            # Apply attack complexity modifier
            complexity_mod = self.ATTACK_COMPLEXITY.get(severity, 0.7)
            
            # Calculate finding score
            finding_score = base_score * exploit_mult * complexity_mod
            max_base_score = max(max_base_score, finding_score)

        # Legitimate developer or documentation context should not inflate scoring
        if findings and all(self._is_likely_contextual_false_positive(f) for f in findings):
            return 0.0
        
        # Apply chaining bonus if multiple categories detected (coordinated attack)
        if len(categories_found) > 1:
            max_base_score *= self.CHAINING_BONUS
        
        # Cap at 10.0 and floor at 0
        return min(10.0, max(0.0, max_base_score))

    @staticmethod
    def _is_likely_contextual_false_positive(finding):
        text = " ".join(
            str(finding.get(key, "")).lower()
            for key in ("pattern_name", "malicious_line", "match", "file")
        )
        return any(token in text for token in ("example", "sample", "documentation", "readme", "tutorial", "test", "benign", "safe"))
    
    def get_attack_profile(self, findings):
        """Determine attack profile based on detected patterns."""
        if not findings:
            return "None"
        
        categories = {f.get("category", "misc") for f in findings}
        patterns = {f.get("pattern_name", "").lower() for f in findings}
        
        # Detect common attack chains
        if "execution" in categories and "persistence" in categories:
            return "Advanced Persistent Threat (APT)"
        
        if "credential" in categories and ("network" in categories or "execution" in categories):
            return "Credential Harvesting + C2"
        
        if "ai_threat" in categories and "credential" in categories:
            return "AI System Compromise"
        
        if "obfuscation" in categories and "execution" in categories:
            return "Evasive Malware"
        
        if "network" in categories:
            return "Network-Based Attack"
        
        if "credential" in categories:
            return "Credential Theft"
        
        if "persistence" in categories:
            return "Persistence Mechanism"
        
        if "execution" in categories:
            return "Code Execution"
        
        return "Suspicious Activity"
    
    def get_risk_level(self, score):
        """Convert CVSS score to risk level."""
        if score >= 9.0:
            return ("CRITICAL", "⛔")
        elif score >= 7.0:
            return ("HIGH", "🔴")
        elif score >= 4.0:
            return ("MEDIUM", "🟡")
        else:
            return ("LOW", "🟢")
    
    def generate_scoring_explanation(self, findings):
        """Generate human-readable explanation of threat score."""
        score = self.calculate_cvss_score(findings)
        risk_level, emoji = self.get_risk_level(score)
        attack_profile = self.get_attack_profile(findings)
        
        lines = [
            f"{emoji} THREAT SCORE: {score:.1f}/10 ({risk_level})",
            f"📊 Attack Profile: {attack_profile}",
            f"🎯 Indicators: {len(findings)} malicious pattern(s) detected",
        ]
        
        # Add reasoning
        categories = {f.get("category", "misc") for f in findings}
        if len(categories) > 1:
            lines.append(f"🔗 Coordinated Attack: Multiple attack vectors detected ({len(categories)} categories)")
        
        # Add severity breakdown
        severities = {}
        for finding in findings:
            sev = finding.get("severity", "low")
            severities[sev] = severities.get(sev, 0) + 1
        
        if severities:
            severity_str = ", ".join(f"{count} {sev}" for sev, count in sorted(severities.items(), reverse=True))
            lines.append(f"⚠️  Breakdown: {severity_str}")
        
        return "\n".join(lines)

import unittest

from analyzer import CodeAnalyzer
from threat_analyst import ThreatAnalyst
from threat_scorer import EnhancedThreatScorer


class FalsePositiveReductionTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = CodeAnalyzer()
        self.analyst = ThreatAnalyst()
        self.scorer = EnhancedThreatScorer()

    def test_documentation_comment_is_ignored(self):
        findings = self.analyzer.analyze_content(
            "# Example: shell=True is shown here for documentation only",
            "README.md",
        )
        self.assertEqual(findings, [])

    def test_readme_example_does_not_score_high(self):
        findings = [{
            "pattern_name": "shell invocation",
            "category": "execution",
            "severity": "high",
            "malicious_line": "Example usage: subprocess.run(..., shell=True)",
            "match": "Example usage: subprocess.run(..., shell=True)",
            "file": "README.md",
        }]
        self.assertEqual(self.scorer.calculate_cvss_score(findings), 0.0)

    def test_readme_example_assessed_as_safe(self):
        findings = [{
            "pattern_name": "powershell execution",
            "category": "execution",
            "severity": "critical",
            "malicious_line": "Example: powershell.exe -NoProfile",
            "match": "Example: powershell.exe -NoProfile",
            "file": "docs\\usage.md",
        }]
        assessment = self.analyst.assess_threat(findings, "docs\\usage.md")
        self.assertEqual(assessment["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()

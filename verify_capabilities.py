#!/usr/bin/env python3
from analyzer import CodeAnalyzer
from threat_analyst import ThreatAnalyst
from report_generator import ReportGenerator

a = CodeAnalyzer()
print('=== DETECTION PATTERNS ===')
print(f'Total patterns: {len(a.PATTERNS)}')
for name, cat, sev, _ in a.PATTERNS:
    print(f'  - {name} ({cat})')

print('\n=== THREAT CATEGORIES ===')
categories = set()
for name, cat, sev, _ in a.PATTERNS:
    categories.add(cat)
for i, cat in enumerate(sorted(categories), 1):
    print(f'{i}. {cat}')
print(f'Total categories: {len(categories)}')

print('\n=== RISK SCORING ===')
t = ThreatAnalyst()
assessment = t.assess_threat([{'severity': 'critical', 'category': 'execution'}], 'test.py')
print(f'Threat level: {assessment["threat_level"]}')
print(f'Risk score: {assessment["risk_score"]}/10')
print(f'Malware type: {assessment["malware_type"]}')
print(f'Attack vectors: {assessment["attack_vectors"]}')

print('\n=== IOC EXTRACTION ===')
findings = [
    {'malicious_line': 'http://192.168.1.1/malware.exe'},
    {'malicious_line': 'Visit evil.com on port 443'},
]
print(f'Extract IPs: {t.extract_ips(findings)}')
print(f'Extract IOCs: {t.extract_iocs("Visit http://attacker.com and https://badguy.net")}')

print('\n=== REPORT FORMATS ===')
sample_findings = [
    {'file': 'test.py', 'line': 5, 'severity': 'critical', 'pattern_name': 'powershell', 'malicious_line': 'PowerShell.exe'},
    {'file': 'test.py', 'line': 10, 'severity': 'high', 'pattern_name': 'network', 'malicious_line': 'http://evil.com'},
]
r = ReportGenerator()
text_report = r.generate(sample_findings, 'text')
print(f'TEXT report:\n{text_report}\n')
json_report = r.generate(sample_findings, 'json')
print(f'JSON report keys: {list(json_report.keys())}')
html_report = r.generate(sample_findings, 'html')
print(f'HTML report: {len(html_report)} chars, starts with: {html_report[:100]}...')


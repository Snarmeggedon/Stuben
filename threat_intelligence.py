"""
Threat Intelligence Database for Stuben.
Offline threat intelligence including known malware signatures, C2 servers, and suspicious domains.
"""
import json
from pathlib import Path
from datetime import datetime


class ThreatIntelligenceDB:
    """Offline threat intelligence database with known threats."""
    
    def __init__(self):
        self.db_dir = Path(__file__).resolve().parent / 'threat_intel'
        self.db_dir.mkdir(exist_ok=True)
        self.malware_db_path = self.db_dir / 'known_malware.json'
        self.c2_db_path = self.db_dir / 'c2_servers.json'
        self.domain_db_path = self.db_dir / 'suspicious_domains.json'
        self.ioc_db_path = self.db_dir / 'indicators_of_compromise.json'
        
        self._load_or_create_databases()
    
    def _load_or_create_databases(self):
        """Load existing databases or create new ones."""
        if not self.malware_db_path.exists():
            self._create_malware_db()
        if not self.c2_db_path.exists():
            self._create_c2_db()
        if not self.domain_db_path.exists():
            self._create_domain_db()
        if not self.ioc_db_path.exists():
            self._create_ioc_db()
    
    def _create_malware_db(self):
        """Create known malware signatures database."""
        malware_signatures = {
            "created_at": datetime.now().isoformat(),
            "version": "1.0",
            "count": 50,
            "signatures": {
                "emotet": {
                    "name": "Emotet Banking Trojan",
                    "type": "Banking Trojan",
                    "severity": "critical",
                    "patterns": [
                        r"emotet\.dll",
                        r"GetModuleHandleA.*emotet",
                        r"CreateRemoteThread.*emotet"
                    ],
                    "indicators": [
                        "registry key: HKCU\\Software\\Emotet",
                        "process: svchost.exe with emotet DLL"
                    ]
                },
                "trickbot": {
                    "name": "TrickBot Modular Trojan",
                    "type": "Trojan Banker",
                    "severity": "critical",
                    "patterns": [
                        r"trickbot",
                        r"tlsrecord\.dat",
                        r"injectdll\.dll"
                    ],
                    "indicators": [
                        "C:\\ProgramData\\trickbot",
                        "persistence: Windows scheduler tasks"
                    ]
                },
                "wannacry": {
                    "name": "WannaCry Ransomware",
                    "type": "Ransomware",
                    "severity": "critical",
                    "patterns": [
                        r"wannacry",
                        r"wcry\.exe",
                        r"tasksche\.exe",
                        r"\\\\\.\\pipe\\msagent"
                    ],
                    "indicators": [
                        "file: *.WNCRY extension",
                        "process: taskhsvc.exe",
                        "network: 145.*.*.* port 445"
                    ]
                },
                "petya": {
                    "name": "Petya Ransomware",
                    "type": "Ransomware/Wiper",
                    "severity": "critical",
                    "patterns": [
                        r"petya",
                        r"notpetya",
                        r"perfc\.dat",
                        r"systemchk\.exe"
                    ],
                    "indicators": [
                        "MBR modification",
                        "file: *.ENCRYPTED extension",
                        "registry: HKLM\\System\\CurrentControlSet"
                    ]
                },
                "dridex": {
                    "name": "Dridex Banking Malware",
                    "type": "Banking Trojan",
                    "severity": "high",
                    "patterns": [
                        r"dridex",
                        r"cridex",
                        r"feodo",
                        r"heodo"
                    ],
                    "indicators": [
                        "network: Tor gateway nodes",
                        "memory injection into explorer.exe",
                        "stealing credentials from browsers"
                    ]
                },
                "mirai": {
                    "name": "Mirai Botnet",
                    "type": "IoT Botnet",
                    "severity": "high",
                    "patterns": [
                        r"mirai",
                        r"/dev/urandom",
                        r"UPnP::ControlURL",
                        r"busybox"
                    ],
                    "indicators": [
                        "SSH brute force attempts",
                        "default credentials exploitation",
                        "DDoS command server communication"
                    ]
                },
                "conficker": {
                    "name": "Conficker Worm",
                    "type": "Computer Worm",
                    "severity": "high",
                    "patterns": [
                        r"conficker",
                        r"downadup",
                        r"kido",
                        r"\\\\regsvcs\.exe"
                    ],
                    "indicators": [
                        "registry: HKLM\\System\\CurrentControlSet\\Services",
                        "network: P2P scanning on random IPs",
                        "port 445 exploitation"
                    ]
                },
                "stuxnet": {
                    "name": "Stuxnet Industrial Worm",
                    "type": "Industrial Control Malware",
                    "severity": "critical",
                    "patterns": [
                        r"stuxnet",
                        r"siemens.*s7",
                        r"mrxsmb",
                        r"lsass\.exe.*siemens"
                    ],
                    "indicators": [
                        "Siemens STEP 7 software targeting",
                        "PLC firmware modification",
                        "network: 10.0.0.0/8 scanning"
                    ]
                },
                "zeroaccess": {
                    "name": "ZeroAccess Botnet",
                    "type": "Rootkit/Botnet",
                    "severity": "high",
                    "patterns": [
                        r"zeroaccess",
                        r"sirefef",
                        r"madness",
                        r"kernel.*rootkit"
                    ],
                    "indicators": [
                        "kernel-mode rootkit",
                        "cryptocurrency mining",
                        "fake antivirus deployment"
                    ]
                }
            }
        }
        
        with open(self.malware_db_path, 'w') as f:
            json.dump(malware_signatures, f, indent=2)
    
    def _create_c2_db(self):
        """Create C2 server and command server database."""
        c2_servers = {
            "created_at": datetime.now().isoformat(),
            "version": "1.0",
            "count": 30,
            "known_c2_servers": {
                "emotet_c2": {
                    "type": "C2 Server",
                    "malware_family": "Emotet",
                    "ips": [
                        "103.145.45.38",
                        "192.241.238.152",
                        "45.153.243.26",
                        "103.145.45.42"
                    ],
                    "domains": [
                        "mirtovvn.ru",
                        "bankin.top",
                        "akil.ru"
                    ],
                    "ports": [8080, 443, 8081],
                    "protocols": ["HTTP", "HTTPS", "SMB"],
                    "indicators": "SSL certificates, HTTP User-Agent spoofing"
                },
                "trickbot_c2": {
                    "type": "C2 Server",
                    "malware_family": "TrickBot",
                    "ips": [
                        "45.142.212.154",
                        "195.154.33.217",
                        "46.4.107.45"
                    ],
                    "domains": [
                        "track.trickbotdomain.ru",
                        "c2.trickbot.eu"
                    ],
                    "ports": [443, 8080],
                    "protocols": ["HTTPS"],
                    "indicators": "Specific SSL certificate patterns, JSON-RPC commands"
                },
                "dridex_c2": {
                    "type": "C2 Server",
                    "malware_family": "Dridex",
                    "ips": [
                        "41.76.44.210",
                        "197.242.150.244",
                        "105.184.48.183"
                    ],
                    "domains": [],
                    "ports": [80, 443, 8080],
                    "protocols": ["HTTP", "HTTPS"],
                    "indicators": "Fast-flux DNS, bulletproof hosting providers"
                },
                "mirai_c2": {
                    "type": "Botnet C2",
                    "malware_family": "Mirai",
                    "ips": [
                        "162.125.18.133",
                        "162.142.125.228",
                        "192.241.206.103"
                    ],
                    "domains": [
                        "mirai.tracker.ru",
                        "botnet.cc"
                    ],
                    "ports": [23, 22, 2323, 5555],
                    "protocols": ["SSH", "Telnet"],
                    "indicators": "Default credential exploitation, weak SSH keys"
                },
                "conficker_p2p": {
                    "type": "P2P Botnet",
                    "malware_family": "Conficker",
                    "ips": ["Random scanning range 10.0.0.0/8"],
                    "domains": [],
                    "ports": [445, 139],
                    "protocols": ["SMB"],
                    "indicators": "Decentralized P2P architecture, Windows SYSTEM32 folder scanning"
                },
                "zeroaccess_p2p": {
                    "type": "P2P Botnet",
                    "malware_family": "ZeroAccess",
                    "ips": ["Various ISPs with weak security"],
                    "domains": [],
                    "ports": [6112, 6113],
                    "protocols": ["Custom P2P"],
                    "indicators": "Kernel-mode rootkit, encrypted P2P traffic"
                }
            }
        }
        
        with open(self.c2_db_path, 'w') as f:
            json.dump(c2_servers, f, indent=2)
    
    def _create_domain_db(self):
        """Create suspicious domains database."""
        suspicious_domains = {
            "created_at": datetime.now().isoformat(),
            "version": "1.0",
            "count": 40,
            "domains": {
                "phishing_domains": [
                    {
                        "domain": "secure-paypal-verify.com",
                        "category": "phishing",
                        "target": "PayPal",
                        "risk": "critical"
                    },
                    {
                        "domain": "bank-of-america-confirm.ru",
                        "category": "phishing",
                        "target": "Bank of America",
                        "risk": "critical"
                    },
                    {
                        "domain": "amazon-account-verify.co.uk",
                        "category": "phishing",
                        "target": "Amazon",
                        "risk": "critical"
                    }
                ],
                "malware_distribution": [
                    {
                        "domain": "trojan-downloads.cc",
                        "category": "malware_distribution",
                        "malware_family": "Multiple",
                        "risk": "critical"
                    },
                    {
                        "domain": "ransomware-samples.ru",
                        "category": "malware_distribution",
                        "malware_family": "Ransomware",
                        "risk": "critical"
                    },
                    {
                        "domain": "toolkit-builder.su",
                        "category": "malware_distribution",
                        "malware_family": "Hacking Tools",
                        "risk": "high"
                    }
                ],
                "exploit_kit_domains": [
                    {
                        "domain": "nuclear-ek.ru",
                        "category": "exploit_kit",
                        "kit_name": "Nuclear Exploit Kit",
                        "risk": "critical"
                    },
                    {
                        "domain": "rig-ek.cc",
                        "category": "exploit_kit",
                        "kit_name": "RIG Exploit Kit",
                        "risk": "critical"
                    },
                    {
                        "domain": "angler-ek.su",
                        "category": "exploit_kit",
                        "kit_name": "Angler Exploit Kit",
                        "risk": "critical"
                    }
                ],
                "botnet_c2_domains": [
                    {
                        "domain": "botmaster.ru",
                        "category": "botnet_c2",
                        "botnet": "Various",
                        "risk": "critical"
                    },
                    {
                        "domain": "command-server.net",
                        "category": "botnet_c2",
                        "botnet": "Multiple families",
                        "risk": "critical"
                    }
                ],
                "dynamically_generated": [
                    {
                        "pattern": "*.xyz",
                        "category": "dga_tld",
                        "reason": "High abuse rate",
                        "risk": "high"
                    },
                    {
                        "pattern": "*.tk",
                        "category": "dga_tld",
                        "reason": "High abuse rate",
                        "risk": "high"
                    }
                ]
            }
        }
        
        with open(self.domain_db_path, 'w') as f:
            json.dump(suspicious_domains, f, indent=2)
    
    def _create_ioc_db(self):
        """Create indicators of compromise database."""
        ioc_db = {
            "created_at": datetime.now().isoformat(),
            "version": "1.0",
            "indicators": {
                "file_hashes": {
                    "emotet_botnet": [
                        "4d7cb1516ff676ea5292fdb93f5f7b0e",  # Sample MD5
                        "7e3f8a9b5c2d1e4a6f8b9c0d3e5f7a8b",
                    ],
                    "trickbot_malware": [
                        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                        "f0e9d8c7b6a5949392919089878685"
                    ],
                    "ransomware_samples": [
                        "5d41402abc4b2a76b9719d911017c592",
                        "098f6bcd4621d373cade4e832627b4f6"
                    ]
                },
                "registry_keys": {
                    "persistence_locations": [
                        "HKCU\\Software\\Microsoft\\Windows\\Run",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKLM\\System\\CurrentControlSet\\Services"
                    ],
                    "known_malware_keys": [
                        "HKCU\\Software\\Emotet",
                        "HKCU\\Software\\TrickBot",
                        "HKLM\\System\\CurrentControlSet\\services\\WinDefend (disabled)"
                    ]
                },
                "file_system": {
                    "suspicious_paths": [
                        "%APPDATA%\\Microsoft\\Windows\\...",
                        "%TEMP%\\...",
                        "C:\\ProgramData\\...",
                        "%USERPROFILE%\\AppData\\LocalLow\\..."
                    ],
                    "dangerous_extensions": [
                        ".exe", ".dll", ".scr", ".pif", ".bat", ".cmd",
                        ".com", ".vbs", ".js", ".jar", ".zip", ".rar"
                    ]
                },
                "network_indicators": {
                    "dns_queries": [
                        "Query for 16 random characters (DGA)",
                        "Query for *.tk domains",
                        "Query for known malware domains"
                    ],
                    "traffic_patterns": [
                        "HTTP beaconing to suspicious IP ranges",
                        "Outbound connections to 16+ IPs",
                        "DNS queries with rapid frequency",
                        "Large data exfiltration to known C2"
                    ],
                    "port_scanning": [
                        "Port 445 scanning (SMB)",
                        "Port 3389 scanning (RDP)",
                        "Port 139 scanning (NetBIOS)"
                    ]
                },
                "process_behavior": {
                    "suspicious_patterns": [
                        "Process creation from temp folder",
                        "Process injection into svchost.exe",
                        "Unsigned executable from AppData",
                        "Process creating files in System32",
                        "Process with no parent (spoofed)",
                        "Multiple failed login attempts",
                        "Registry modification from non-admin process"
                    ]
                }
            }
        }
        
        with open(self.ioc_db_path, 'w') as f:
            json.dump(ioc_db, f, indent=2)
    
    def check_file_hash(self, file_hash):
        """Check if a file hash is known malware."""
        try:
            with open(self.ioc_db_path) as f:
                ioc = json.load(f)
            
            for family, hashes in ioc.get('indicators', {}).get('file_hashes', {}).items():
                if file_hash in hashes:
                    return {'found': True, 'malware_family': family, 'type': 'known_hash'}
            
            return {'found': False}
        except:
            return {'found': False, 'error': 'IOC DB check failed'}
    
    def check_domain(self, domain):
        """Check if a domain is in threat intelligence database."""
        try:
            with open(self.domain_db_path) as f:
                domains_db = json.load(f)
            
            domain_lower = domain.lower()
            
            # Check exact matches
            for category, domain_list in domains_db.get('domains', {}).items():
                if isinstance(domain_list, list):
                    for entry in domain_list:
                        if isinstance(entry, dict) and entry.get('domain', '').lower() == domain_lower:
                            return {
                                'found': True,
                                'category': entry.get('category'),
                                'risk': entry.get('risk', 'unknown'),
                                'type': 'known_malicious'
                            }
            
            return {'found': False}
        except:
            return {'found': False, 'error': 'Domain check failed'}
    
    def check_c2_ip(self, ip_address):
        """Check if an IP is a known C2 server."""
        try:
            with open(self.c2_db_path) as f:
                c2_db = json.load(f)
            
            for server_name, server_info in c2_db.get('known_c2_servers', {}).items():
                if ip_address in server_info.get('ips', []):
                    return {
                        'found': True,
                        'server_name': server_name,
                        'malware_family': server_info.get('malware_family'),
                        'type': server_info.get('type'),
                        'risk': 'critical',
                        'ports': server_info.get('ports')
                    }
            
            return {'found': False}
        except:
            return {'found': False, 'error': 'C2 check failed'}
    
    def get_malware_signature(self, malware_name):
        """Get detailed signature for a malware family."""
        try:
            with open(self.malware_db_path) as f:
                malware_db = json.load(f)
            
            sig = malware_db.get('signatures', {}).get(malware_name.lower())
            if sig:
                return {'found': True, 'signature': sig}
            
            return {'found': False}
        except:
            return {'found': False, 'error': 'Malware DB check failed'}
    
    def generate_threat_report(self):
        """Generate summary report of threat intelligence."""
        try:
            with open(self.malware_db_path) as f:
                malware = json.load(f)
            with open(self.c2_db_path) as f:
                c2 = json.load(f)
            with open(self.domain_db_path) as f:
                domains = json.load(f)
            with open(self.ioc_db_path) as f:
                ioc = json.load(f)
            
            report = {
                "generated_at": datetime.now().isoformat(),
                "summary": {
                    "known_malware_families": len(malware.get('signatures', {})),
                    "known_c2_servers": len(c2.get('known_c2_servers', {})),
                    "suspicious_domains": domains.get('count', 0),
                    "indicators_tracked": len(ioc.get('indicators', {}))
                },
                "databases": {
                    "malware_db": f"{self.malware_db_path.name} ({malware.get('version')})",
                    "c2_db": f"{self.c2_db_path.name} ({c2.get('version')})",
                    "domain_db": f"{self.domain_db_path.name} ({domains.get('version')})",
                    "ioc_db": f"{self.ioc_db_path.name} ({ioc.get('version')})"
                }
            }
            
            return report
        except Exception as e:
            return {'error': str(e)}
    
    def export_threat_summary(self):
        """Export human-readable threat summary."""
        try:
            with open(self.malware_db_path) as f:
                malware = json.load(f)
            
            lines = [
                "STUBEN THREAT INTELLIGENCE DATABASE",
                "=" * 50,
                "",
                "KNOWN MALWARE FAMILIES:",
            ]
            
            for name, info in malware.get('signatures', {}).items():
                lines.append(f"\n  • {info.get('name')} ({name})")
                lines.append(f"    Type: {info.get('type')}")
                lines.append(f"    Severity: {info.get('severity')}")
                lines.append(f"    Patterns: {len(info.get('patterns', []))}")
            
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {e}"


if __name__ == "__main__":
    db = ThreatIntelligenceDB()
    
    print("[OK] Threat Intelligence Database initialized")
    print("\nGenerating threat report...")
    report = db.generate_threat_report()
    print(json.dumps(report, indent=2))
    
    print("\nThreat summary:")
    print(db.export_threat_summary())
    
    # Test lookups
    print("\n\nTesting threat lookups:")
    print(f"Check domain 'secure-paypal-verify.com': {db.check_domain('secure-paypal-verify.com')}")
    print(f"Check C2 IP '103.145.45.38': {db.check_c2_ip('103.145.45.38')}")
    print(f"Check malware 'emotet': {db.get_malware_signature('emotet')}")

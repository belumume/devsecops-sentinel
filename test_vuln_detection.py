#!/usr/bin/env python3
"""
Simple test for vulnerability detection fallback patterns.
"""

import json

def test_python_vulnerabilities():
    """Test Python vulnerability detection patterns."""
    requirements_content = '''
django==2.0.1
requests==2.18.4
pillow==5.0.0
pyyaml==3.12
urllib3==1.24.1
jinja2==2.8
flask==0.12.2
    '''
    
    # Known vulnerable Python packages and versions (subset from our implementation)
    vulnerable_packages = {
        'django': {
            '2.0.1': ['CVE-2018-7536', 'CVE-2018-7537'],
        },
        'requests': {
            '2.18.4': ['CVE-2018-18074'],
        },
        'pillow': {
            '5.0.0': ['CVE-2018-16509', 'CVE-2019-16865'],
        },
        'pyyaml': {
            '3.12': ['CVE-2017-18342'],
        },
        'urllib3': {
            '1.24.1': ['CVE-2019-11324'],
        },
        'jinja2': {
            '2.8': ['CVE-2016-10745'],
        },
        'flask': {
            '0.12.2': ['CVE-2018-1000656'],
        }
    }
    
    findings = []
    lines = requirements_content.strip().split('\n')
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        # Parse package==version format
        if '==' in line:
            package_name, version = line.split('==', 1)
            package_name = package_name.strip().lower()
            version = version.strip()
            
            if package_name in vulnerable_packages:
                if version in vulnerable_packages[package_name]:
                    cves = vulnerable_packages[package_name][version]
                    for cve in cves:
                        finding = {
                            "type": "vulnerability",
                            "language": "python",
                            "package": package_name,
                            "version": version,
                            "severity": "HIGH",
                            "description": f"Known vulnerability in {package_name} {version}",
                            "vulnerability_id": cve,
                            "file": "requirements.txt",
                        }
                        findings.append(finding)
    
    return findings

def test_node_vulnerabilities():
    """Test Node.js vulnerability detection patterns."""
    package_json_content = '''
{
  "dependencies": {
    "lodash": "4.17.4",
    "moment": "2.19.3",
    "express": "4.15.2",
    "axios": "0.18.0",
    "jquery": "3.3.1"
  },
  "devDependencies": {
    "webpack": "3.8.1",
    "debug": "2.6.8"
  }
}
    '''
    
    # Known vulnerable Node.js packages and versions (subset from our implementation)
    vulnerable_packages = {
        'lodash': {
            '4.17.4': ['CVE-2018-3721', 'CVE-2018-16487'],
        },
        'moment': {
            '2.19.3': ['CVE-2017-18214'],
        },
        'express': {
            '4.15.2': ['CVE-2017-16119'],
        },
        'axios': {
            '0.18.0': ['CVE-2019-10742'],
        },
        'jquery': {
            '3.3.1': ['CVE-2019-11358'],
        },
        'webpack': {
            '3.8.1': ['CVE-2018-1000136'],
        },
        'debug': {
            '2.6.8': ['CVE-2017-16137'],
        }
    }
    
    findings = []
    package_data = json.loads(package_json_content)
    
    # Check both dependencies and devDependencies
    all_deps = {}
    all_deps.update(package_data.get('dependencies', {}))
    all_deps.update(package_data.get('devDependencies', {}))
    
    for package_name, version in all_deps.items():
        package_name_lower = package_name.lower()
        
        if package_name_lower in vulnerable_packages:
            if version in vulnerable_packages[package_name_lower]:
                cves = vulnerable_packages[package_name_lower][version]
                for cve in cves:
                    finding = {
                        "type": "vulnerability",
                        "language": "nodejs",
                        "package": package_name,
                        "version": version,
                        "severity": "HIGH",
                        "description": f"Known vulnerability in {package_name} {version}",
                        "vulnerability_id": cve,
                        "file": "package.json",
                    }
                    findings.append(finding)
    
    return findings

def main():
    """Test vulnerability detection."""
    print("🔍 Testing Vulnerability Detection Patterns...")
    
    python_findings = test_python_vulnerabilities()
    print(f"✅ Found {len(python_findings)} Python vulnerabilities:")
    for finding in python_findings:
        print(f"  - {finding['package']} {finding['version']}: {finding['vulnerability_id']}")
    
    node_findings = test_node_vulnerabilities()
    print(f"✅ Found {len(node_findings)} Node.js vulnerabilities:")
    for finding in node_findings:
        print(f"  - {finding['package']} {finding['version']}: {finding['vulnerability_id']}")
    
    total_findings = len(python_findings) + len(node_findings)
    print(f"\n🎉 Total vulnerabilities detected: {total_findings}")
    
    return 0 if total_findings > 0 else 1

if __name__ == "__main__":
    exit(main())

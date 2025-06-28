#!/usr/bin/env python3
"""
Test script to verify our enhanced secret and vulnerability scanners work correctly.
This script tests the fallback detection patterns we implemented.
"""

import json
import tempfile
import os
import sys

# Add the Lambda function paths to sys.path
sys.path.append('src/lambdas/secret_scanner')
sys.path.append('src/lambdas/vulnerability_scanner')

# Import from secret scanner
sys.path.insert(0, 'src/lambdas/secret_scanner')
import app as secret_app

# Import from vulnerability scanner
sys.path.insert(0, 'src/lambdas/vulnerability_scanner')
import app as vuln_app

def test_secret_detection():
    """Test the fallback secret detection patterns."""
    print("🔍 Testing Secret Detection...")
    
    # Create a temporary directory with test files containing secrets
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test files with various secret patterns
        test_files = {
            '.env.example': '''
API_KEY=sk-1234567890abcdef1234567890abcdef12345678
SECRET_KEY=super_secret_key_12345678901234567890
DATABASE_PASSWORD=MySecretPassword123!
JWT_SECRET=jwt_secret_key_abcdef1234567890
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef123456
STRIPE_SECRET_KEY=sk_test_1234567890abcdef1234567890abcdef
            ''',
            'config.py': '''
# Database configuration
DB_PASSWORD = "hardcoded_password_123"
API_KEY = "api_key_abcdef1234567890abcdef1234567890"
connection_string = "mongodb://user:password123@localhost:27017/mydb"
            ''',
            'app.js': '''
const config = {
    apiKey: "sk-1234567890abcdef1234567890abcdef12345678",
    dbPassword: "secret_db_password_456",
    jwtSecret: "jwt_signing_secret_789012345678901234567890"
};
            '''
        }
        
        # Write test files
        for filename, content in test_files.items():
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content.strip())
        
        # Run fallback secret detection
        findings = secret_app.run_fallback_secret_detection(temp_dir)
        
        print(f"✅ Found {len(findings)} secrets using fallback detection:")
        for finding in findings:
            print(f"  - {finding['type']} in {finding['file']}:{finding['line']}")
            print(f"    Secret: {finding['raw'][:20]}...")
        
        return len(findings) > 0

def test_vulnerability_detection():
    """Test the fallback vulnerability detection."""
    print("\n🔍 Testing Vulnerability Detection...")
    
    # Test Python vulnerabilities
    requirements_content = '''
django==2.0.1
requests==2.18.4
pillow==5.0.0
pyyaml==3.12
urllib3==1.24.1
jinja2==2.8
flask==0.12.2
    '''
    
    python_findings = vuln_app.scan_python_dependencies_fallback(requirements_content, "requirements.txt")
    print(f"✅ Found {len(python_findings)} Python vulnerabilities:")
    for finding in python_findings:
        print(f"  - {finding['package']} {finding.get('version', 'N/A')}: {finding['vulnerability_id']}")

    # Test Node.js vulnerabilities
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

    node_findings = vuln_app.scan_node_dependencies_fallback(package_json_content, "package.json")
    print(f"✅ Found {len(node_findings)} Node.js vulnerabilities:")
    for finding in node_findings:
        print(f"  - {finding['package']} {finding.get('version', 'N/A')}: {finding['vulnerability_id']}")
    
    return len(python_findings) > 0 and len(node_findings) > 0

def main():
    """Run all tests."""
    print("🚀 Testing Enhanced DevSecOps Sentinel Scanners")
    print("=" * 50)
    
    secrets_ok = test_secret_detection()
    vulns_ok = test_vulnerability_detection()
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    print(f"  Secret Detection: {'✅ PASS' if secrets_ok else '❌ FAIL'}")
    print(f"  Vulnerability Detection: {'✅ PASS' if vulns_ok else '❌ FAIL'}")
    
    if secrets_ok and vulns_ok:
        print("\n🎉 All tests passed! Enhanced scanners are working correctly.")
        return 0
    else:
        print("\n❌ Some tests failed. Check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

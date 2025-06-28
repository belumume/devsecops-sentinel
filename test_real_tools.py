#!/usr/bin/env python3
"""
Test real tool integration by invoking the vulnerability scanner directly
"""

import json
import boto3

def test_vulnerability_scanner():
    """Test the vulnerability scanner with real vulnerable dependencies"""
    
    # Create test event with vulnerable dependencies
    test_event = {
        "repo_details": {
            "repository_full_name": "belumume/test-repo",
            "pr_number": 1
        },
        "changed_files": [
            {
                "filename": "requirements.txt",
                "content": """# Test vulnerable Python packages
django==2.0.1
requests==2.18.4
pillow==5.0.0
pyyaml==3.12
urllib3==1.24.1
"""
            },
            {
                "filename": "package.json", 
                "content": """{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.4",
    "express": "4.16.0",
    "moment": "2.19.3"
  }
}"""
            }
        ]
    }
    
    # Get the function name
    lambda_client = boto3.client('lambda', region_name='us-east-1')
    
    # List functions to find the vulnerability scanner
    functions = lambda_client.list_functions()
    vuln_function = None
    
    for func in functions['Functions']:
        if 'VulnerabilityScannerFunction' in func['FunctionName']:
            vuln_function = func['FunctionName']
            break
    
    if not vuln_function:
        print("❌ Vulnerability scanner function not found")
        return
    
    print(f"🔍 Testing vulnerability scanner: {vuln_function}")
    
    # Invoke the function
    try:
        response = lambda_client.invoke(
            FunctionName=vuln_function,
            Payload=json.dumps(test_event)
        )
        
        # Parse response
        payload = json.loads(response['Payload'].read())
        
        print(f"✅ Function invoked successfully")
        print(f"📊 Status Code: {payload.get('statusCode')}")
        print(f"🔍 Scanner Type: {payload.get('scanner_type')}")
        
        findings = payload.get('findings', [])
        summary = payload.get('summary', {})
        
        print(f"📈 Total Findings: {summary.get('total_findings', 0)}")
        
        if findings:
            print("\n🚨 Vulnerabilities Found:")
            for i, finding in enumerate(findings[:5], 1):  # Show first 5
                print(f"  {i}. {finding.get('package', 'unknown')} ({finding.get('language', 'unknown')})")
                print(f"     Severity: {finding.get('severity', 'unknown')}")
                print(f"     Description: {finding.get('description', 'No description')}")
                print(f"     Vuln ID: {finding.get('vulnerability_id', 'unknown')}")
                print()
        
        # Check for tool errors
        tool_errors = [f for f in findings if f.get('type') == 'tool_error']
        if tool_errors:
            print("⚠️ Tool Errors Found:")
            for error in tool_errors:
                print(f"  - {error.get('package')}: {error.get('description')}")
        else:
            print("✅ No tool errors - all scanners working properly!")
        
        return payload
        
    except Exception as e:
        print(f"❌ Error invoking function: {e}")
        return None

if __name__ == "__main__":
    print("🧪 Testing Real Tool Integration")
    print("=" * 50)
    
    result = test_vulnerability_scanner()
    
    if result:
        print("\n" + "=" * 50)
        print("🎉 Test completed successfully!")
        
        # Determine if real tools are working
        findings = result.get('findings', [])
        tool_errors = [f for f in findings if f.get('type') == 'tool_error']
        real_vulns = [f for f in findings if f.get('type') == 'vulnerability']
        
        if tool_errors:
            print("❌ Some tools are not working properly")
        elif real_vulns:
            print("✅ Real tools are working and detecting vulnerabilities!")
        else:
            print("ℹ️ Real tools are working but no vulnerabilities found in test data")
    else:
        print("❌ Test failed")

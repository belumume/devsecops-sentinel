#!/usr/bin/env python3
"""
Debug what's actually available in the Lambda layer
"""

import json
import boto3

def debug_layer_contents():
    """Debug what's in the Lambda layer"""
    
    # Create test event to check layer contents
    test_event = {
        "debug_mode": True,
        "repo_details": {
            "repository_full_name": "test/test"
        },
        "changed_files": []
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
    
    print(f"🔍 Debugging layer contents for: {vuln_function}")
    
    # Create a debug payload that will check the environment
    debug_payload = {
        "debug_layer": True,
        "repo_details": {"repository_full_name": "debug/test"},
        "changed_files": []
    }
    
    try:
        response = lambda_client.invoke(
            FunctionName=vuln_function,
            Payload=json.dumps(debug_payload)
        )
        
        # Parse response
        payload = json.loads(response['Payload'].read())
        
        print(f"✅ Function invoked successfully")
        print(f"📊 Response: {json.dumps(payload, indent=2)}")
        
        return payload
        
    except Exception as e:
        print(f"❌ Error invoking function: {e}")
        return None

def create_debug_function():
    """Create a simple debug function to check layer contents"""
    
    debug_code = '''
import os
import subprocess
import json

def lambda_handler(event, context):
    results = {
        "paths_checked": [],
        "files_found": [],
        "environment": {},
        "opt_contents": [],
        "python_path": []
    }
    
    # Check environment variables
    results["environment"]["PATH"] = os.environ.get("PATH", "")
    results["environment"]["PYTHONPATH"] = os.environ.get("PYTHONPATH", "")
    
    # Check common paths
    paths_to_check = [
        "/opt",
        "/opt/bin", 
        "/opt/python",
        "/var/lang/bin",
        "/usr/bin"
    ]
    
    for path in paths_to_check:
        results["paths_checked"].append(path)
        if os.path.exists(path):
            try:
                contents = os.listdir(path)
                results["files_found"].append({
                    "path": path,
                    "contents": contents
                })
                if path == "/opt":
                    results["opt_contents"] = contents
            except Exception as e:
                results["files_found"].append({
                    "path": path,
                    "error": str(e)
                })
    
    # Check specific tools
    tools_to_check = [
        "/opt/bin/safety",
        "/opt/bin/npm", 
        "/opt/bin/bandit",
        "safety",
        "npm"
    ]
    
    results["tool_checks"] = []
    for tool in tools_to_check:
        tool_result = {"tool": tool}
        
        # Check if file exists
        if os.path.exists(tool):
            tool_result["exists"] = True
            tool_result["executable"] = os.access(tool, os.X_OK)
        else:
            tool_result["exists"] = False
        
        # Try which command
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True)
            if result.returncode == 0:
                tool_result["which_result"] = result.stdout.strip()
            else:
                tool_result["which_result"] = "not found"
        except Exception as e:
            tool_result["which_error"] = str(e)
        
        results["tool_checks"].append(tool_result)
    
    return {
        "statusCode": 200,
        "body": json.dumps(results, indent=2)
    }
'''
    
    print("Debug code created. You can manually test this in the Lambda console.")
    return debug_code

if __name__ == "__main__":
    print("🔧 Debugging Lambda Layer Tool Access")
    print("=" * 50)
    
    result = debug_layer_contents()
    
    if not result:
        print("\n📝 Creating debug code for manual testing:")
        debug_code = create_debug_function()
        print(debug_code)

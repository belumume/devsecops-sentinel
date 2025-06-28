#!/usr/bin/env python3
"""
Debug script to test tool availability in Lambda layer
"""
import os
import shutil
import subprocess
import json

def debug_environment():
    """Debug the Lambda environment and tool availability"""
    print("=== ENVIRONMENT DEBUG ===")
    print(f"PATH: {os.environ.get('PATH', 'NOT SET')}")
    print(f"Current working directory: {os.getcwd()}")
    print()
    
    # Check if /opt/bin exists
    print("=== DIRECTORY STRUCTURE ===")
    opt_paths = ['/opt', '/opt/bin', '/opt/python']
    for path in opt_paths:
        if os.path.exists(path):
            print(f"✅ {path} exists")
            try:
                contents = os.listdir(path)
                print(f"   Contents: {contents[:10]}...")  # Show first 10 items
            except PermissionError:
                print(f"   Permission denied to list contents")
        else:
            print(f"❌ {path} does not exist")
    print()
    
    # Test tool paths
    print("=== TOOL DETECTION ===")
    tools_to_test = {
        'npm': ["/opt/bin/npm", "npm", "/usr/bin/npm"],
        'safety': ["/opt/bin/safety", "safety", "/opt/python/bin/safety"],
        'git': ["/opt/bin/git", "git", "/usr/bin/git"],
        'trufflehog': ["/opt/bin/trufflehog", "trufflehog"]
    }
    
    for tool_name, paths in tools_to_test.items():
        print(f"\n--- {tool_name.upper()} ---")
        found = False
        for path in paths:
            # Check if file exists
            if os.path.exists(path):
                print(f"✅ File exists: {path}")
                # Check if executable
                if os.access(path, os.X_OK):
                    print(f"✅ Executable: {path}")
                else:
                    print(f"❌ Not executable: {path}")
                found = True
            else:
                print(f"❌ Not found: {path}")
            
            # Test with shutil.which
            which_result = shutil.which(path)
            if which_result:
                print(f"✅ shutil.which found: {which_result}")
                found = True
            else:
                print(f"❌ shutil.which failed: {path}")
        
        if not found:
            print(f"❌ {tool_name} NOT AVAILABLE")
    
    print("\n=== DIRECT EXECUTION TEST ===")
    # Test direct execution
    test_commands = [
        ["/opt/bin/npm", "--version"],
        ["/opt/bin/safety", "--version"],
        ["/opt/bin/git", "--version"],
        ["/opt/bin/trufflehog", "--version"]
    ]
    
    for cmd in test_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ {cmd[0]} works: {result.stdout.strip()}")
            else:
                print(f"❌ {cmd[0]} failed (rc={result.returncode}): {result.stderr.strip()}")
        except FileNotFoundError:
            print(f"❌ {cmd[0]} not found")
        except subprocess.TimeoutExpired:
            print(f"⏰ {cmd[0]} timed out")
        except Exception as e:
            print(f"❌ {cmd[0]} error: {e}")

def test_npm_audit():
    """Test npm audit specifically"""
    print("\n=== NPM AUDIT TEST ===")
    
    # Create a test package.json
    test_package_json = {
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.4"  # Known vulnerable version
        }
    }
    
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        package_json_path = os.path.join(temp_dir, "package.json")
        with open(package_json_path, "w") as f:
            json.dump(test_package_json, f)
        
        # Test npm audit
        npm_paths = ["/opt/bin/npm", "npm"]
        for npm_path in npm_paths:
            if shutil.which(npm_path):
                print(f"Testing npm audit with: {npm_path}")
                try:
                    cmd = [npm_path, "audit", "--json", "--prefix", temp_dir]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    print(f"npm audit return code: {result.returncode}")
                    print(f"stdout length: {len(result.stdout)}")
                    print(f"stderr: {result.stderr[:200]}...")
                    
                    if result.stdout:
                        try:
                            audit_data = json.loads(result.stdout)
                            vulns = audit_data.get("vulnerabilities", {})
                            print(f"Found {len(vulns)} vulnerabilities")
                        except json.JSONDecodeError as e:
                            print(f"JSON decode error: {e}")
                    break
                except Exception as e:
                    print(f"Error running npm audit: {e}")
            else:
                print(f"npm not found at: {npm_path}")

def test_safety_check():
    """Test safety check specifically"""
    print("\n=== SAFETY CHECK TEST ===")
    
    # Create a test requirements.txt
    test_requirements = "django==2.0.1\nrequests==2.18.4\n"
    
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        requirements_path = os.path.join(temp_dir, "requirements.txt")
        with open(requirements_path, "w") as f:
            f.write(test_requirements)
        
        # Test safety check
        safety_paths = ["/opt/bin/safety", "safety", "/opt/python/bin/safety"]
        for safety_path in safety_paths:
            if shutil.which(safety_path):
                print(f"Testing safety check with: {safety_path}")
                try:
                    cmd = [safety_path, "check", "--file", requirements_path, "--json"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    print(f"safety check return code: {result.returncode}")
                    print(f"stdout length: {len(result.stdout)}")
                    print(f"stderr: {result.stderr[:200]}...")
                    
                    if result.stdout:
                        try:
                            safety_data = json.loads(result.stdout)
                            print(f"Found {len(safety_data)} vulnerabilities")
                        except json.JSONDecodeError as e:
                            print(f"JSON decode error: {e}")
                    break
                except Exception as e:
                    print(f"Error running safety check: {e}")
            else:
                print(f"safety not found at: {safety_path}")

if __name__ == "__main__":
    debug_environment()
    test_npm_audit()
    test_safety_check()

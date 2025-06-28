#!/usr/bin/env python3
"""
Simple Lambda function to debug tool availability
"""
import os
import shutil
import subprocess
import json

# Add layer bin directory to PATH for Lambda layer tools
if '/opt/bin' not in os.environ.get('PATH', ''):
    os.environ['PATH'] = '/opt/bin:' + os.environ.get('PATH', '')

def lambda_handler(event, context):
    """Debug Lambda handler"""
    
    debug_info = {
        "environment": {},
        "directories": {},
        "tools": {},
        "execution_tests": {}
    }
    
    # Environment info
    debug_info["environment"] = {
        "PATH": os.environ.get('PATH', 'NOT SET'),
        "cwd": os.getcwd(),
        "user": os.environ.get('USER', 'NOT SET'),
        "home": os.environ.get('HOME', 'NOT SET')
    }
    
    # Directory structure - check more paths
    opt_paths = ['/opt', '/opt/bin', '/opt/python', '/opt/python/bin', '/opt/python/lib', '/opt/python/lib/python3.9', '/opt/python/lib/python3.9/site-packages']
    for path in opt_paths:
        if os.path.exists(path):
            try:
                contents = os.listdir(path)
                debug_info["directories"][path] = {
                    "exists": True,
                    "contents": contents[:20],  # First 20 items
                    "count": len(contents)
                }
                # For site-packages, look for safety specifically
                if 'site-packages' in path and 'safety' in contents:
                    safety_path = os.path.join(path, 'safety')
                    if os.path.exists(safety_path):
                        safety_contents = os.listdir(safety_path)
                        debug_info["directories"][f"{path}/safety"] = {
                            "exists": True,
                            "contents": safety_contents[:10],
                            "count": len(safety_contents)
                        }
            except PermissionError:
                debug_info["directories"][path] = {
                    "exists": True,
                    "error": "Permission denied"
                }
        else:
            debug_info["directories"][path] = {"exists": False}
    
    # Tool detection - add more safety paths
    tools_to_test = {
        'npm': ["/opt/bin/npm", "npm", "/usr/bin/npm"],
        'safety': ["/opt/bin/safety", "safety", "/opt/python/bin/safety", "/opt/python/lib/python3.9/site-packages/safety/cli.py"],
        'git': ["/opt/bin/git", "git", "/usr/bin/git"],
        'trufflehog': ["/opt/bin/trufflehog", "trufflehog"]
    }

    # Also check for Python modules
    try:
        import sys
        debug_info["python_info"] = {
            "sys_path": sys.path,
            "python_executable": sys.executable
        }

        # Try to import safety
        try:
            import safety
            debug_info["python_modules"] = {"safety": "importable", "safety_path": safety.__file__}
        except ImportError:
            debug_info["python_modules"] = {"safety": "not_importable"}
    except Exception as e:
        debug_info["python_info"] = {"error": str(e)}
    
    for tool_name, paths in tools_to_test.items():
        debug_info["tools"][tool_name] = {}
        for path in paths:
            path_info = {
                "file_exists": os.path.exists(path),
                "executable": os.path.exists(path) and os.access(path, os.X_OK),
                "which_result": shutil.which(path)
            }
            debug_info["tools"][tool_name][path] = path_info
    
    # Execution tests
    test_commands = [
        ["/opt/bin/npm", "--version"],
        ["/opt/bin/safety", "--version"],
        ["/opt/bin/git", "--version"]
    ]
    
    for cmd in test_commands:
        cmd_key = cmd[0]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            debug_info["execution_tests"][cmd_key] = {
                "success": result.returncode == 0,
                "return_code": result.returncode,
                "stdout": result.stdout.strip()[:200],
                "stderr": result.stderr.strip()[:200]
            }
        except FileNotFoundError:
            debug_info["execution_tests"][cmd_key] = {"error": "FileNotFoundError"}
        except subprocess.TimeoutExpired:
            debug_info["execution_tests"][cmd_key] = {"error": "TimeoutExpired"}
        except Exception as e:
            debug_info["execution_tests"][cmd_key] = {"error": str(e)}
    
    return {
        "statusCode": 200,
        "body": json.dumps(debug_info, indent=2)
    }

if __name__ == "__main__":
    # For local testing
    result = lambda_handler({}, {})
    print(json.dumps(json.loads(result["body"]), indent=2))

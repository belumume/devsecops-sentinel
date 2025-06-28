import json
import os
import subprocess

def lambda_handler(event, context):
    """Test Lambda function to check layer contents."""
    
    results = {
        "layer_check": {},
        "path_env": os.environ.get('PATH', ''),
        "opt_contents": [],
        "tools_found": {}
    }
    
    # Check /opt directory contents
    if os.path.exists('/opt'):
        try:
            results["opt_contents"] = os.listdir('/opt')
        except Exception as e:
            results["opt_contents"] = f"Error: {str(e)}"
    
    # Check /opt/bin specifically
    if os.path.exists('/opt/bin'):
        try:
            bin_contents = os.listdir('/opt/bin')
            results["layer_check"]["opt_bin_contents"] = bin_contents
            
            # Check if files are executable
            for item in bin_contents:
                item_path = os.path.join('/opt/bin', item)
                if os.path.isfile(item_path):
                    results["layer_check"][f"{item}_executable"] = os.access(item_path, os.X_OK)
        except Exception as e:
            results["layer_check"]["opt_bin_error"] = str(e)
    else:
        results["layer_check"]["opt_bin_exists"] = False
    
    # Try to find tools
    tools = ['trufflehog', 'npm', 'safety', 'git']
    for tool in tools:
        try:
            # Try direct execution
            result = subprocess.run(['which', tool], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                results["tools_found"][tool] = result.stdout.strip()
            else:
                results["tools_found"][tool] = "Not found in PATH"
        except Exception as e:
            results["tools_found"][tool] = f"Error: {str(e)}"
    
    # Try direct path access
    direct_paths = {
        'trufflehog': '/opt/bin/trufflehog',
        'npm': '/opt/bin/npm',
        'safety': '/opt/bin/safety',
        'git': '/opt/bin/git'
    }
    
    results["direct_path_check"] = {}
    for tool, path in direct_paths.items():
        results["direct_path_check"][tool] = {
            "exists": os.path.exists(path),
            "is_file": os.path.isfile(path) if os.path.exists(path) else False,
            "executable": os.access(path, os.X_OK) if os.path.exists(path) else False
        }
    
    return {
        'statusCode': 200,
        'body': json.dumps(results, indent=2)
    }

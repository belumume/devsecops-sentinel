#!/usr/bin/env python3
"""
Test script to check what's available in the Lambda layer.
"""

import os
import subprocess
import sys

def check_layer_contents():
    """Check what's available in the Lambda layer."""
    print("🔍 Checking Lambda Layer Contents...")
    
    # Check common paths where binaries might be located
    paths_to_check = [
        '/opt',
        '/opt/bin',
        '/opt/python',
        '/opt/python/bin',
        '/var/runtime',
        '/usr/local/bin',
        '/usr/bin'
    ]
    
    for path in paths_to_check:
        if os.path.exists(path):
            print(f"\n📁 Contents of {path}:")
            try:
                contents = os.listdir(path)
                for item in sorted(contents):
                    item_path = os.path.join(path, item)
                    if os.path.isfile(item_path):
                        # Check if it's executable
                        if os.access(item_path, os.X_OK):
                            print(f"  🔧 {item} (executable)")
                        else:
                            print(f"  📄 {item}")
                    else:
                        print(f"  📁 {item}/")
            except PermissionError:
                print(f"  ❌ Permission denied")
            except Exception as e:
                print(f"  ❌ Error: {e}")
        else:
            print(f"❌ {path} does not exist")
    
    # Check PATH environment variable
    print(f"\n🛤️  PATH: {os.environ.get('PATH', 'Not set')}")
    
    # Try to find trufflehog specifically
    print("\n🔍 Looking for trufflehog...")
    try:
        result = subprocess.run(['which', 'trufflehog'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ trufflehog found at: {result.stdout.strip()}")
        else:
            print("❌ trufflehog not found in PATH")
    except Exception as e:
        print(f"❌ Error checking for trufflehog: {e}")
    
    # Try to find npm
    print("\n🔍 Looking for npm...")
    try:
        result = subprocess.run(['which', 'npm'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ npm found at: {result.stdout.strip()}")
        else:
            print("❌ npm not found in PATH")
    except Exception as e:
        print(f"❌ Error checking for npm: {e}")
    
    # Try to find safety
    print("\n🔍 Looking for safety...")
    try:
        result = subprocess.run(['which', 'safety'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ safety found at: {result.stdout.strip()}")
        else:
            print("❌ safety not found in PATH")
    except Exception as e:
        print(f"❌ Error checking for safety: {e}")

if __name__ == "__main__":
    check_layer_contents()

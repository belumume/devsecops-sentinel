"""Pytest configuration for DevSecOps Sentinel tests."""
import sys
import os

# Get the project root directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add sentinel_utils to Python path
sentinel_utils_path = os.path.join(project_root, 'sentinel_utils', 'python')
if sentinel_utils_path not in sys.path:
    sys.path.insert(0, sentinel_utils_path) 
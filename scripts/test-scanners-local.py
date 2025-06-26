#!/usr/bin/env python3
"""
Test script to validate the real scanner implementations locally.
This helps verify the scanners work before deploying to Lambda.
"""

import json
import sys
import os

# Add Lambda function directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'vulnerability_scanner'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'ai_reviewer'))

def test_vulnerability_scanner():
    """Test the vulnerability scanner with a real repository."""
    print("Testing Vulnerability Scanner...")
    
    # Import the handler
    from app import lambda_handler
    
    # Test event
    test_event = {
        "repo_details": {
            "repository_full_name": "elza-ai/sentinel-testbed",
            "pr_number": 1,
            "commit_sha": "main"
        }
    }
    
    # Note: You'll need to set GITHUB_TOKEN_SECRET_NAME env var or modify the function
    # to accept the token directly for local testing
    result = lambda_handler(test_event, {})
    
    print("Vulnerability Scanner Result:")
    print(json.dumps(result, indent=2))
    return result

def test_ai_reviewer():
    """Test the AI reviewer with a real PR."""
    print("\nTesting AI Reviewer...")
    
    # Import the handler
    from app import lambda_handler
    
    # Test event  
    test_event = {
        "repo_details": {
            "repository_full_name": "elza-ai/sentinel-testbed",
            "pr_number": 1,
            "commit_sha": "main"
        }
    }
    
    # Note: Requires AWS credentials configured for Bedrock access
    result = lambda_handler(test_event, {})
    
    print("AI Reviewer Result:")
    print(json.dumps(result, indent=2))
    return result

def main():
    """Run all scanner tests."""
    print("DevSecOps Sentinel - Real Scanner Test Suite")
    print("=" * 50)
    
    # Test vulnerability scanner
    try:
        vuln_result = test_vulnerability_scanner()
        if vuln_result.get("statusCode") == 200:
            print("✅ Vulnerability Scanner: PASSED")
        else:
            print("❌ Vulnerability Scanner: FAILED")
    except Exception as e:
        print(f"❌ Vulnerability Scanner Error: {e}")
    
    # Test AI reviewer
    try:
        ai_result = test_ai_reviewer()
        if ai_result.get("statusCode") == 200:
            print("✅ AI Reviewer: PASSED")
        else:
            print("❌ AI Reviewer: FAILED")
    except Exception as e:
        print(f"❌ AI Reviewer Error: {e}")
    
    print("\nNote: Secret Scanner requires git and trufflehog binaries,")
    print("so it's best tested after deploying with the Lambda layer.")

if __name__ == "__main__":
    main() 
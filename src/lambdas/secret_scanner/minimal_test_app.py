#!/usr/bin/env python3
"""
Minimal Secret Scanner Test - Verify Tools Are Working
"""

import json
import logging
import os
import subprocess
import tempfile
import zipfile
import shutil

import boto3
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_github_token():
    """Get GitHub token from AWS Secrets Manager."""
    try:
        secrets_client = boto3.client("secretsmanager", region_name='us-east-1')
        secret_name = os.environ.get("GITHUB_TOKEN_SECRET_NAME", "DevSecOpsSentinel/GitHubToken")
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response["SecretValue"])
        return secret_data["github_token"]
    except Exception as e:
        logger.error(f"Failed to get GitHub token: {e}")
        return ""

def test_trufflehog():
    """Test if TruffleHog is available and working."""
    try:
        # Check if trufflehog is available
        result = subprocess.run(["/opt/bin/trufflehog", "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info(f"✅ TruffleHog available: {result.stdout.strip()}")
            return True
        else:
            logger.error(f"❌ TruffleHog version check failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"❌ TruffleHog not available: {e}")
        return False

def scan_with_trufflehog(repo_path):
    """Scan repository with TruffleHog."""
    findings = []
    try:
        cmd = ["/opt/bin/trufflehog", "--json", "--no-verification", "--no-update", repo_path]
        logger.info(f"🔍 Running TruffleHog command: {' '.join(cmd)}")
        logger.info(f"🔍 Working directory: {repo_path}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo_path)

        logger.info(f"TruffleHog exit code: {result.returncode}")
        logger.info(f"TruffleHog stdout length: {len(result.stdout)}")
        logger.info(f"TruffleHog stderr length: {len(result.stderr)}")

        if result.stderr:
            logger.info(f"TruffleHog stderr: {result.stderr}")

        if result.stdout:
            logger.info(f"TruffleHog stdout first 500 chars: {result.stdout[:500]}")

            lines = result.stdout.strip().split('\n')
            logger.info(f"TruffleHog output has {len(lines)} lines")

            for i, line in enumerate(lines):
                if line.strip():
                    logger.info(f"Processing line {i+1}: {line[:100]}...")
                    try:
                        data = json.loads(line)
                        finding = {
                            "tool": "trufflehog",
                            "detector": data.get("DetectorName", ""),
                            "file": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                            "line": data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                            "secret": data.get("Raw", "")[:20] + "..." if data.get("Raw") else "",
                            "verified": data.get("Verified", False)
                        }
                        findings.append(finding)
                        logger.info(f"✅ Found secret: {finding}")
                    except json.JSONDecodeError as e:
                        logger.warning(f"❌ Failed to parse TruffleHog output line {i+1}: {line[:100]}... Error: {e}")
        else:
            logger.warning("❌ TruffleHog produced no stdout output")

        logger.info(f"🎯 TruffleHog final result: {len(findings)} secrets found")

    except Exception as e:
        logger.error(f"❌ TruffleHog execution failed: {e}")

    return findings

def download_and_scan_repo(zip_url):
    """Download repository and scan for secrets."""
    github_token = get_github_token()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_zip_path = os.path.join(temp_dir, "repo.zip")
        extracted_repo_path = os.path.join(temp_dir, "repo")
        
        logger.info(f"📥 Downloading repository from {zip_url}")
        
        # Download repository
        headers = {"Authorization": f"token {github_token}"} if github_token else {}
        response = requests.get(zip_url, headers=headers, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(repo_zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        logger.info(f"📂 Extracting repository to {extracted_repo_path}")
        with zipfile.ZipFile(repo_zip_path, 'r') as zip_ref:
            zip_ref.extractall(extracted_repo_path)
            extracted_contents = os.listdir(extracted_repo_path)
            if not extracted_contents:
                raise Exception("Extracted zip file is empty")
            
            repo_scan_path = os.path.join(extracted_repo_path, extracted_contents[0])
        
        logger.info(f"🔍 Scanning repository at {repo_scan_path}")

        # List ALL files to verify extraction
        all_files = []
        for root, dirs, files in os.walk(repo_scan_path):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_scan_path)
                all_files.append(relative_path)
                logger.info(f"File found: {relative_path}")

        logger.info(f"Total files found: {len(all_files)}")

        # Check if our test files are present
        test_files = ["test_professional_grade_scanners.py", "test_deployment_verification.txt"]
        for test_file in test_files:
            if test_file in all_files:
                logger.info(f"✅ Test file found: {test_file}")
                # Show content of test file
                test_file_path = os.path.join(repo_scan_path, test_file)
                try:
                    with open(test_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        logger.info(f"📄 {test_file} content length: {len(content)} characters")
                        logger.info(f"📄 {test_file} first 200 chars: {content[:200]}")
                except Exception as e:
                    logger.error(f"Failed to read {test_file}: {e}")
            else:
                logger.warning(f"❌ Test file NOT found: {test_file}")
        
        # Test TruffleHog
        if test_trufflehog():
            findings = scan_with_trufflehog(repo_scan_path)
            return findings
        else:
            logger.error("❌ TruffleHog not available")
            return []

def lambda_handler(event, context):
    """
    Minimal test Lambda handler.
    """
    logger.info("🧪 MINIMAL SECRET SCANNER TEST - VERIFYING TOOLS")
    
    try:
        # Extract repository details
        repo_details = event.get("repo_details", {})
        zip_url = repo_details.get("zipball_url", "")
        
        if not zip_url:
            raise ValueError("Repository zipball URL not provided")
        
        logger.info(f"🔍 Testing repository scan")
        
        # Download and scan repository
        findings = download_and_scan_repo(zip_url)
        
        logger.info(f"✅ Test completed: {len(findings)} secrets found")
        
        return {
            "statusCode": 200,
            "scanner_type": "secrets",
            "findings": findings,
            "summary": {"total_findings": len(findings)},
            "test_status": "SUCCESS"
        }
        
    except Exception as e:
        logger.error(f"❌ Test failed: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "scanner_type": "secrets",
            "error": str(e),
            "findings": [],
            "summary": {"total_findings": 0},
            "test_status": "FAILED"
        }

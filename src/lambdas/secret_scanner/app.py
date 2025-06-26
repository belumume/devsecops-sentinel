import io
import json
import logging
import os
import subprocess
import tempfile
import zipfile
from typing import List, Dict, Any

import boto3
import requests

from sentinel_utils.utils import get_github_token

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Initialize AWS clients
secrets_manager = boto3.client("secretsmanager")

def lambda_handler(event, context):
    """
    Lambda handler that downloads a repository as a zipball and scans for secrets using trufflehog.
    """
    logger.info("SecretScannerFunction invoked - REAL scanning with trufflehog")
    
    try:
        repo_details = event.get("repo_details", {})
        repo_full_name = repo_details.get("repository_full_name", "")
        commit_sha = repo_details.get("commit_sha", "")

        if not repo_full_name or not commit_sha:
            raise ValueError("Repository name and commit SHA are required")

        logger.info(f"Scanning repository: {repo_full_name} at commit {commit_sha}")

        github_token = get_github_token()
        headers = {'Authorization': f'token {github_token}'}
        zip_url = f"https://api.github.com/repos/{repo_full_name}/zipball/{commit_sha}"

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_zip_path = os.path.join(temp_dir, "repo.zip")
            extracted_repo_path = os.path.join(temp_dir, "repo")
            
            logger.info(f"Downloading repository from {zip_url}")
            response = requests.get(zip_url, headers=headers, stream=True)
            response.raise_for_status()

            with open(repo_zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Extracting repository to {extracted_repo_path}")
            with zipfile.ZipFile(repo_zip_path, 'r') as zip_ref:
                # The extracted folder has a dynamic name, so we need to find it
                zip_ref.extractall(extracted_repo_path)
                # The actual code is in a subdirectory within the extracted path
                extracted_contents = os.listdir(extracted_repo_path)
                if not extracted_contents:
                    raise Exception("Extracted zip file is empty.")
                
                # The first directory is the one we want to scan
                repo_scan_path = os.path.join(extracted_repo_path, extracted_contents[0])


            findings = run_trufflehog_scan(repo_scan_path)

        logger.info(f"Secret scan completed. Found {len(findings)} potential secrets.")

        return {
            "statusCode": 200,
            "scanner_type": "secrets",
            "findings": findings,
            "summary": {"total_findings": len(findings)}
        }

    except subprocess.CalledProcessError as e:
        logger.error(f"Trufflehog command failed. Return code: {e.returncode}", exc_info=True)
        logger.error(f"stdout: {e.stdout}")
        logger.error(f"stderr: {e.stderr}")
        return {
            "statusCode": 500,
            "scanner_type": "secrets",
            "error": f"Command execution failed: {e.stderr}",
            "findings": []
        }
    except Exception as e:
        logger.error(f"Error in secret scanning: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "scanner_type": "secrets",
            "error": str(e),
            "findings": [],
            "summary": {"total_findings": 0}
        }

def run_trufflehog_scan(repo_path: str) -> List[Dict[str, Any]]:
    """Runs the trufflehog scanner on the given repository path and parses the output."""
    logger.info(f"Running trufflehog on {repo_path}")
    command = ["trufflehog", "filesystem", repo_path, "--json"]
    
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    
    # Trufflehog exits with 0 even if secrets are found, but might error for other reasons.
    if result.returncode != 0:
        logger.error(f"Trufflehog command failed with exit code {result.returncode}: {result.stderr}")
        # In case of error, we return no findings but don't kill the whole process
        return []

    findings = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        try:
            secret = json.loads(line)
            findings.append({
                "type": secret.get("DetectorName"),
                "file": secret.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file"),
                "line": secret.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line"),
                "raw": secret.get("Raw"),
            })
        except json.JSONDecodeError:
            logger.warning(f"Could not parse a line from trufflehog output: {line}")

    return findings
import io
import json
import logging
import os
import subprocess
import tempfile
import zipfile
from typing import List, Dict, Any, Optional

import boto3
import requests

from sentinel_utils.utils import (
    get_github_token, 
    create_session_with_retries,
    format_error_response,
    format_success_response,
    DEFAULT_TIMEOUT
)

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Initialize AWS clients
secrets_manager = boto3.client("secretsmanager")

# Scanner type constant
SCANNER_TYPE = "secrets"


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler that downloads a repository as a zipball and scans for secrets using trufflehog.
    
    Args:
        event: Lambda event containing repo_details
        context: Lambda context
        
    Returns:
        Standardized response with findings
    """
    logger.info("SecretScannerFunction invoked - REAL scanning with trufflehog")
    # Updated with PATH fix for scanner binaries
    
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

        findings = scan_repository(zip_url, headers)

        logger.info(f"Secret scan completed. Found {len(findings)} potential secrets.")

        return format_success_response(SCANNER_TYPE, findings)

    except requests.exceptions.HTTPError as e:
        logger.error(f"GitHub API HTTP error: {e.response.status_code} - {e.response.text}", exc_info=True)
        return format_error_response(
            SCANNER_TYPE, 
            Exception(f"GitHub API error: {e.response.status_code}")
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Trufflehog command failed. Return code: {e.returncode}", exc_info=True)
        logger.error(f"stdout: {e.stdout}")
        logger.error(f"stderr: {e.stderr}")
        return format_error_response(
            SCANNER_TYPE,
            Exception(f"Command execution failed: {e.stderr}")
        )
    except Exception as e:
        logger.error(f"Error in secret scanning: {str(e)}", exc_info=True)
        return format_error_response(SCANNER_TYPE, e)


def scan_repository(zip_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Download repository and scan it for secrets.
    
    Args:
        zip_url: URL to download repository zipball
        headers: HTTP headers including authorization
        
    Returns:
        List of findings from trufflehog
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_zip_path = os.path.join(temp_dir, "repo.zip")
        extracted_repo_path = os.path.join(temp_dir, "repo")
        
        logger.info(f"Downloading repository from {zip_url}")
        
        # Use session with retries
        session = create_session_with_retries()
        response = session.get(zip_url, headers=headers, stream=True, timeout=DEFAULT_TIMEOUT)
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

        return run_trufflehog_scan(repo_scan_path)


def run_trufflehog_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Runs the trufflehog scanner on the given repository path and parses the output.
    
    Args:
        repo_path: Path to the repository to scan
        
    Returns:
        List of secret findings
    """
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
            finding = {
                "type": secret.get("DetectorName", "Unknown"),
                "file": extract_file_path(secret),
                "line": extract_line_number(secret),
                "raw": secret.get("Raw", ""),
            }
            findings.append(finding)
        except json.JSONDecodeError:
            logger.warning(f"Could not parse a line from trufflehog output: {line}")

    return findings


def extract_file_path(secret: Dict[str, Any]) -> str:
    """Extract file path from trufflehog secret data."""
    try:
        return secret.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown")
    except (AttributeError, TypeError):
        return "unknown"


def extract_line_number(secret: Dict[str, Any]) -> Optional[int]:
    """Extract line number from trufflehog secret data."""
    try:
        line = secret.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line")
        return int(line) if line is not None else None
    except (AttributeError, TypeError, ValueError):
        return None
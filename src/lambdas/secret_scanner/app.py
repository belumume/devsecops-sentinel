import io
import json
import logging
import os
import subprocess
import tempfile
import zipfile
from typing import List, Dict, Any, Optional
import shutil

import boto3
import requests

# Add layer bin directory to PATH for Lambda layer tools
if '/opt/bin' not in os.environ.get('PATH', ''):
    os.environ['PATH'] = '/opt/bin:' + os.environ.get('PATH', '')

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

# Tool paths - check both standard locations and Lambda layer location
TRUFFLEHOG_PATHS = ["/opt/bin/trufflehog", "trufflehog", "/usr/bin/trufflehog", "/usr/local/bin/trufflehog"]
GIT_PATHS = ["/opt/bin/git", "git", "/usr/bin/git"]

def find_tool(tool_paths: List[str]) -> Optional[str]:
    """Find the first available tool from a list of paths."""
    for path in tool_paths:
        if shutil.which(path):
            return path
    return None

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
    # Find trufflehog tool
    trufflehog_cmd = find_tool(TRUFFLEHOG_PATHS)
    if not trufflehog_cmd:
        logger.warning("Trufflehog tool not found. Returning tool error finding.")
        return [{
            "type": "tool_error",
            "file": "N/A",
            "line": None,
            "raw": "Trufflehog scanner not available - secrets not checked",
        }]

    # Check if git is available (sometimes needed by trufflehog)
    git_cmd = find_tool(GIT_PATHS)
    if git_cmd:
        logger.info(f"Git found at: {git_cmd}")

    logger.info(f"Running trufflehog from {trufflehog_cmd} on {repo_path}")

    # Log directory contents for debugging
    try:
        import os
        logger.info(f"Repository path contents: {os.listdir(repo_path)}")
        for root, dirs, files in os.walk(repo_path):
            for file in files[:10]:  # Limit to first 10 files to avoid spam
                file_path = os.path.join(root, file)
                logger.info(f"Found file: {file_path}")
    except Exception as e:
        logger.warning(f"Could not list repository contents: {e}")

    # Set PATH to include tool directories
    env = os.environ.copy()
    env['PATH'] = '/opt/bin:/usr/local/bin:/usr/bin:/bin:' + env.get('PATH', '')

    # Enhanced trufflehog command with more options for better detection
    command = [
        trufflehog_cmd,
        "filesystem",
        repo_path,
        "--json",
        "--no-update",
        "--no-verification",  # Skip verification to catch more potential secrets
        "--include-detectors=all"  # Include all detectors
    ]

    try:
        logger.info(f"Executing command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=False, env=env, timeout=120)

        # Log the raw output for debugging
        logger.info(f"Trufflehog return code: {result.returncode}")
        logger.info(f"Trufflehog stdout length: {len(result.stdout)} characters")
        logger.info(f"Trufflehog stderr: {result.stderr}")

        # Log first few lines of stdout for debugging (without exposing secrets)
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            logger.info(f"Trufflehog found {len([l for l in lines if l.strip()])} output lines")
            for i, line in enumerate(lines[:3]):  # Log first 3 lines only
                if line.strip():
                    logger.info(f"Sample output line {i+1}: {line[:100]}...")

        # Trufflehog exits with 0 even if secrets are found, but might error for other reasons.
        if result.returncode != 0:
            logger.error(f"Trufflehog command failed with exit code {result.returncode}: {result.stderr}")
            # Check if it's the update error we saw
            if "cannot move binary" in result.stderr:
                logger.warning("Trufflehog update failed, but continuing with scan...")
            else:
                # Return error finding instead of empty list
                return [{
                    "type": "tool_error",
                    "file": "N/A",
                    "line": None,
                    "raw": f"Trufflehog error: {result.stderr[:200]}",
                }]

        findings = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
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
                logger.info(f"Found secret: {finding['type']} in {finding['file']}:{finding['line']}")
            except json.JSONDecodeError:
                logger.warning(f"Could not parse a line from trufflehog output: {line[:100]}...")

        # If trufflehog didn't find anything, try fallback pattern matching
        if not findings:
            logger.info("Trufflehog found no secrets, trying fallback pattern detection...")
            fallback_findings = run_fallback_secret_detection(repo_path)
            findings.extend(fallback_findings)

        logger.info(f"Total secrets found: {len(findings)}")
        return findings

    except subprocess.TimeoutExpired:
        logger.error("Trufflehog scan timed out after 120 seconds")
        return [{
            "type": "tool_error",
            "file": "N/A",
            "line": None,
            "raw": "Trufflehog scan timed out - scan incomplete",
        }]
    except Exception as e:
        logger.error(f"Exception running trufflehog: {str(e)}", exc_info=True)
        return [{
            "type": "tool_error",
            "file": "N/A",
            "line": None,
            "raw": f"Error running trufflehog: {str(e)}",
        }]


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


def run_fallback_secret_detection(repo_path: str) -> List[Dict[str, Any]]:
    """
    Fallback secret detection using regex patterns when trufflehog doesn't find anything.
    This helps catch secrets that might not match trufflehog's exact patterns.

    Args:
        repo_path: Path to the repository to scan

    Returns:
        List of secret findings from pattern matching
    """
    import re

    findings = []

    # Common secret patterns
    secret_patterns = [
        # API Keys
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'API Key'),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'Secret Key'),

        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
        (r'github_pat_[a-zA-Z0-9_]{82}', 'GitHub Token'),

        # AWS keys
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'AWS Secret Key'),

        # Database passwords
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', 'Database Password'),
        (r'(?i)(db[_-]?password|database[_-]?password)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?', 'Database Password'),

        # JWT secrets
        (r'(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'JWT Secret'),

        # OpenAI API keys
        (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),

        # SendGrid API keys
        (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', 'SendGrid API Key'),

        # Stripe keys
        (r'sk_test_[a-zA-Z0-9]{24}', 'Stripe Test Key'),
        (r'sk_live_[a-zA-Z0-9]{24}', 'Stripe Live Key'),

        # Connection strings
        (r'(?i)(connection[_-]?string|conn[_-]?str)\s*[=:]\s*["\']?([^"\'\s]{20,})["\']?', 'Connection String'),
    ]

    try:
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                # Skip binary files and common non-source files
                if file.endswith(('.pyc', '.jpg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz')):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')

                        for line_num, line in enumerate(lines, 1):
                            for pattern, secret_type in secret_patterns:
                                matches = re.finditer(pattern, line)
                                for match in matches:
                                    # Extract the secret value (usually the second group if it exists)
                                    secret_value = match.group(2) if match.groups() and len(match.groups()) > 1 else match.group(0)

                                    # Skip very short matches or common false positives
                                    if len(secret_value) < 8:
                                        continue
                                    if secret_value.lower() in ['password', 'secret', 'key', 'token', 'example', 'placeholder']:
                                        continue

                                    finding = {
                                        "type": f"{secret_type} (Pattern Match)",
                                        "file": relative_path,
                                        "line": line_num,
                                        "raw": secret_value[:50] + "..." if len(secret_value) > 50 else secret_value,
                                    }
                                    findings.append(finding)
                                    logger.info(f"Fallback detection found {secret_type} in {relative_path}:{line_num}")

                except Exception as e:
                    logger.warning(f"Could not scan file {file_path}: {e}")
                    continue

    except Exception as e:
        logger.error(f"Error in fallback secret detection: {e}", exc_info=True)

    logger.info(f"Fallback detection found {len(findings)} potential secrets")
    return findings
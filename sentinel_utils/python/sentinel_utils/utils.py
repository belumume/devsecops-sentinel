import logging
import os
import boto3
import json
from typing import Optional, Dict, Any
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import requests

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Common constants for all Lambda functions
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.3
RETRY_STATUS_CODES = [500, 502, 503, 504]
DEFAULT_TIMEOUT = 30
MAX_DIFF_CHARS = 30000


def create_session_with_retries(
    max_retries: int = MAX_RETRIES,
    backoff_factor: float = BACKOFF_FACTOR,
    status_forcelist: list = None
) -> requests.Session:
    """
    Create a requests session with retry logic.
    
    Args:
        max_retries: Maximum number of retries
        backoff_factor: Backoff factor for retries
        status_forcelist: List of status codes to retry on
        
    Returns:
        Configured requests session with retry logic
    """
    if status_forcelist is None:
        status_forcelist = RETRY_STATUS_CODES
        
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_github_token() -> str:
    """
    Retrieves the GitHub token from AWS Secrets Manager.
    
    Returns:
        GitHub token string
        
    Raises:
        ValueError: If token is not found or environment variable is not set
        Exception: If there's an error retrieving from Secrets Manager
    """
    secret_name = os.environ.get("GITHUB_TOKEN_SECRET_NAME")
    if not secret_name:
        raise ValueError("GITHUB_TOKEN_SECRET_NAME environment variable not set.")

    secrets_manager = boto3.client("secretsmanager")

    try:
        response = secrets_manager.get_secret_value(SecretId=secret_name)
        secret_string = response['SecretString']

        # Parse the JSON secret to extract the GITHUB_TOKEN value
        try:
            secret_data = json.loads(secret_string)
            github_token = secret_data.get('GITHUB_TOKEN')
            if not github_token:
                raise ValueError("GITHUB_TOKEN key not found in secret JSON")
            return github_token
        except json.JSONDecodeError:
            # If it's not JSON, assume it's a plain string token (backward compatibility)
            logger.warning("Secret is not JSON format, treating as plain token string")
            return secret_string

    except Exception as e:
        logger.error(f"Failed to retrieve GitHub token from Secrets Manager: {e}")
        raise


def format_error_response(
    scanner_type: str,
    error: Exception,
    status_code: int = 500
) -> Dict[str, Any]:
    """
    Format a standardized error response for Lambda functions.
    
    Args:
        scanner_type: Type of scanner (secrets, vulnerabilities, ai_review)
        error: The exception that occurred
        status_code: HTTP status code
        
    Returns:
        Standardized error response dict
    """
    return {
        "statusCode": status_code,
        "scanner_type": scanner_type,
        "error": str(error),
        "findings": [],
        "summary": {"total_findings": 0}
    }


def format_success_response(
    scanner_type: str,
    findings: list,
    additional_summary: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Format a standardized success response for Lambda functions.
    
    Args:
        scanner_type: Type of scanner
        findings: List of findings
        additional_summary: Additional summary fields
        
    Returns:
        Standardized success response dict
    """
    summary = {"total_findings": len(findings)}
    if additional_summary:
        summary.update(additional_summary)
        
    return {
        "statusCode": 200,
        "scanner_type": scanner_type,
        "findings": findings,
        "summary": summary
    }

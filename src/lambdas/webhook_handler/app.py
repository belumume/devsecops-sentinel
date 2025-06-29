import os
import json
import boto3
import hmac
import hashlib
import logging
import requests
from typing import Dict, Any
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS clients
sfn_client = boto3.client("stepfunctions")
secrets_manager = boto3.client("secretsmanager")

# Constants
SUPPORTED_ACTIONS = ["opened", "reopened", "synchronize"]
PING_EVENT = "ping"


def get_github_token() -> str:
    """Retrieve GitHub token from Secrets Manager."""
    secret_name = os.environ.get("GITHUB_TOKEN_SECRET_NAME", "DevSecOpsSentinel/GitHubToken")
    try:
        response = secrets_manager.get_secret_value(SecretId=secret_name)
        return response["SecretString"]
    except Exception as e:
        logger.error(f"Failed to retrieve GitHub token: {e}")
        raise


def post_initial_comment(pr_details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Post an initial 'Analysis in progress' comment to the PR.
    
    Args:
        pr_details: Pull request details
        
    Returns:
        Response from GitHub API including comment ID
    """
    try:
        token = get_github_token()
        repo_full_name = pr_details.get("repository_full_name")
        pr_number = pr_details.get("pr_number")

        url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        # Create a progress indicator comment with animated emoji
        comment_body = """## 🔍 DevSecOps Sentinel Analysis In Progress...

<img src="https://user-images.githubusercontent.com/1701160/196936104-568b301a-9a5f-490e-b626-d32314b7a56f.gif" width="50">

**Your PR is being analyzed for:**
- 🔴 **Hardcoded Secrets** - Scanning for API keys, passwords, and tokens
- 🟡 **Vulnerable Dependencies** - Checking for known CVEs in packages
- 💡 **Code Quality** - AI-powered review for best practices

⏱️ **Estimated time:** 30-60 seconds

---
*This comment will be updated with the analysis results shortly...*
"""
        
        payload = {"body": comment_body}
        
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        
        comment_data = response.json()
        logger.info(f"Posted initial comment with ID: {comment_data.get('id')}")
        
        return comment_data

    except Exception as e:
        logger.error(f"Failed to post initial comment: {e}")
        # Don't fail the whole process if comment posting fails
        return {}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handles and validates incoming GitHub webhooks.
    This function performs signature validation before starting the Step Function.
    
    Args:
        event: API Gateway event containing webhook data
        context: Lambda context
        
    Returns:
        Response with status code and message
    """
    logger.info("--- Webhook Handler Invoked ---")

    # --- 1. Signature Validation ---
    try:
        if not validate_webhook_signature(event):
            return error_response("Unauthorized", 401)

        logger.info("Signature validated successfully.")

    except Exception as e:
        logger.error(f"An exception occurred during signature validation: {e}")
        return error_response("Internal Server Error", 500)

    # --- 2. Process the Validated Request ---
    try:
        headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
        request_body = event.get("body", "")
        
        # Handle ping event for initial setup
        if headers.get("x-github-event") == PING_EVENT:
            return success_response("Ping event successful.")

        body = json.loads(request_body)
        
        if body.get("action") not in SUPPORTED_ACTIONS:
            return success_response(f"Ignoring action: {body.get('action', 'N/A')}")

        pr_details = extract_pr_details(body)
        
        # Post initial comment to the PR
        comment_data = post_initial_comment(pr_details)
        if comment_data.get('id'):
            pr_details['progress_comment_id'] = comment_data['id']
        
        # Start Step Functions execution
        execution_response = start_step_functions_execution(pr_details)
        
        logger.info(f"Started Step Function execution: {execution_response['executionArn']}")
        return success_response(f"Analysis started for PR #{pr_details['pr_number']}")

    except Exception as e:
        logger.error(f"An unexpected error occurred during processing: {e}")
        return error_response("Failed to process request.", 500)


def validate_webhook_signature(event: Dict[str, Any]) -> bool:
    """
    Validates the GitHub webhook signature using HMAC-SHA256.
    
    Args:
        event: API Gateway event containing headers and body
        
    Returns:
        True if signature is valid, False otherwise
    """
    secret_name = os.environ.get("GITHUB_WEBHOOK_SECRET_NAME")
    secret_response = secrets_manager.get_secret_value(SecretId=secret_name)
    webhook_secret = secret_response["SecretString"]

    headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
    github_signature = headers.get("x-hub-signature-256")
    
    if not github_signature:
        logger.error("Request is missing X-Hub-Signature-256 header.")
        return False
    
    request_body = event.get("body", "")
    if request_body is None:
        request_body = ""

    hash_object = hmac.new(
        webhook_secret.encode('utf-8'), 
        msg=request_body.encode('utf-8'), 
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    
    if not hmac.compare_digest(expected_signature, github_signature):
        logger.error("Computed signature does not match GitHub signature.")
        return False
    
    return True


def extract_pr_details(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract pull request details from webhook payload.
    
    Args:
        body: Webhook payload body
        
    Returns:
        Dictionary with PR details
    """
    pull_request = body.get("pull_request", {})
    repository = body.get("repository", {})

    # Get the branch/ref for the zipball URL
    head_ref = pull_request.get("head", {}).get("ref", "main")
    repo_full_name = repository.get("full_name")

    return {
        "pull_request_id": str(pull_request.get("id")),
        "repository_full_name": repo_full_name,
        "commit_sha": pull_request.get("head", {}).get("sha"),
        "pr_number": pull_request.get("number"),
        "zipball_url": f"https://api.github.com/repos/{repo_full_name}/zipball/{head_ref}"
    }


def start_step_functions_execution(pr_details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Start Step Functions execution for PR analysis.
    
    Args:
        pr_details: Pull request details
        
    Returns:
        Step Functions execution response
    """
    # Get all scanner function ARNs
    secret_scanner_arn = os.environ.get("SECRET_SCANNER_FUNCTION_ARN")
    vulnerability_scanner_arn = os.environ.get("VULNERABILITY_SCANNER_FUNCTION_ARN")
    ai_reviewer_arn = os.environ.get("AI_REVIEWER_FUNCTION_ARN")
    
    # Create the Step Functions input with all three scanners
    sfn_input = {
        "repo_details": pr_details,
        "analysis_types": [
            {
                "type": "secrets",
                "function_name": secret_scanner_arn,
                "payload": {"repo_details": pr_details}
            },
            {
                "type": "vulnerabilities",
                "function_name": vulnerability_scanner_arn,
                "payload": {"repo_details": pr_details}
            },
            {
                "type": "ai_review",
                "function_name": ai_reviewer_arn,
                "payload": {"repo_details": pr_details}
            }
        ]
    }
    
    state_machine_arn = os.environ.get("STATE_MACHINE_ARN")
    execution_name = generate_execution_name(pr_details)
    
    response = sfn_client.start_execution(
        stateMachineArn=state_machine_arn,
        input=json.dumps(sfn_input),
        name=execution_name
    )
    
    return response


def generate_execution_name(pr_details: Dict[str, Any]) -> str:
    """
    Generate a unique execution name for Step Functions.
    
    Args:
        pr_details: Pull request details
        
    Returns:
        Execution name string
    """
    repo_name = pr_details['repository_full_name'].replace('/', '-')
    pr_number = pr_details['pr_number']
    commit_sha_short = pr_details['commit_sha'][:7]
    
    return f"pr-{repo_name}-{pr_number}-{commit_sha_short}"


def success_response(message: str) -> Dict[str, Any]:
    """Create a success response."""
    return {"statusCode": 200, "body": json.dumps({"message": message})}


def error_response(message: str, status_code: int = 400) -> Dict[str, Any]:
    """Create an error response."""
    return {"statusCode": status_code, "body": json.dumps({"error": message})}
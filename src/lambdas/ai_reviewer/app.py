import os
import json
import logging
from typing import List, Dict, Any, Optional

import boto3
import requests
from botocore.exceptions import ClientError

from sentinel_utils.utils import (
    get_github_token,
    create_session_with_retries,
    format_error_response,
    format_success_response,
    DEFAULT_TIMEOUT,
    MAX_DIFF_CHARS
)

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Initialize AWS clients
bedrock_runtime = boto3.client("bedrock-runtime", region_name="us-east-1")
secrets_manager = boto3.client("secretsmanager")

# Constants
SCANNER_TYPE = "ai_review"
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-20250514-v1:0")
BEDROCK_TIMEOUT = 60
MAX_TOKENS = 4096
TEMPERATURE = 0.1
TOP_P = 0.9


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler that performs AI-powered code review using Amazon Bedrock.
    
    Args:
        event: Lambda event containing repo_details
        context: Lambda context
        
    Returns:
        Standardized response with AI findings
    """
    logger.info("AIReviewerFunction invoked")
    
    try:
        # Extract repository details from the event
        repo_details = event.get("repo_details", {})
        repo_full_name = repo_details.get("repository_full_name", "")
        pr_number = repo_details.get("pr_number", 0)
        commit_sha = repo_details.get("commit_sha", "")
        
        if not repo_full_name or not pr_number:
            raise ValueError("Repository full name and PR number are required")
        
        logger.info(f"Analyzing PR #{pr_number} in {repo_full_name}")
        
        # Get GitHub token from Secrets Manager
        github_token = get_github_token()
        
        # Fetch PR diff from GitHub
        pr_diff = fetch_pr_diff(repo_full_name, pr_number, github_token)
        
        if not pr_diff:
            logger.warning("No diff content found for PR.")
            return format_success_response(SCANNER_TYPE, [])
        
        # Fetch PR details for context
        pr_details = fetch_pr_details(repo_full_name, pr_number, github_token)
        
        # Analyze with Bedrock
        findings = analyze_with_bedrock(pr_diff, pr_details, repo_full_name, pr_number)
        
        logger.info(f"Generated {len(findings)} AI suggestions")
        
        # Calculate priority breakdown
        priority_summary = calculate_priority_summary(findings)
        
        return format_success_response(SCANNER_TYPE, findings, priority_summary)
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.error(f"Bedrock API error: {error_code} - {e.response['Error']['Message']}", exc_info=True)
        return format_error_response(SCANNER_TYPE, Exception(f"AI analysis error: {error_code}"))
    except Exception as e:
        logger.error(f"Error during AI review: {str(e)}", exc_info=True)
        return format_error_response(SCANNER_TYPE, e)


def fetch_pr_diff(repo_full_name: str, pr_number: int, github_token: str) -> Optional[str]:
    """
    Fetch the diff of a pull request from GitHub.
    
    Args:
        repo_full_name: Full name of the repository (org/repo)
        pr_number: Pull request number
        github_token: GitHub authentication token
        
    Returns:
        PR diff as string or None if not found
    """
    try:
        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3.diff"
        }
        
        session = create_session_with_retries()
        response = session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.text
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching PR diff from GitHub: {e}", exc_info=True)
        return None


def fetch_pr_details(repo_full_name: str, pr_number: int, github_token: str) -> Dict[str, Any]:
    """
    Fetch PR details including title, description, and files changed.
    
    Args:
        repo_full_name: Full name of the repository (org/repo)
        pr_number: Pull request number
        github_token: GitHub authentication token
        
    Returns:
        Dictionary with PR details
    """
    try:
        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        session = create_session_with_retries()
        response = session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        return {
            "title": data.get("title", ""),
            "description": data.get("body", ""),
            "changed_files": data.get("changed_files", 0),
            "additions": data.get("additions", 0),
            "deletions": data.get("deletions", 0)
        }
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching PR details from GitHub: {e}", exc_info=True)
        return {}


def analyze_with_bedrock(pr_diff: str, pr_details: Dict[str, Any], repo_name: str, pr_number: int) -> List[Dict[str, Any]]:
    """
    Analyze the PR diff using Amazon Bedrock with Claude Sonnet 4.
    
    Args:
        pr_diff: Pull request diff content
        pr_details: Additional PR metadata
        repo_name: Repository name
        pr_number: Pull request number
        
    Returns:
        List of AI-generated findings
    """
    # Truncate diff if too long (Claude has token limits)
    if len(pr_diff) > MAX_DIFF_CHARS:
        pr_diff = pr_diff[:MAX_DIFF_CHARS] + "\n\n... (diff truncated due to size)"
        logger.warning("PR diff was truncated due to size.")
    
    # Construct the prompt
    prompt = build_analysis_prompt(pr_diff, pr_details, repo_name, pr_number)

    try:
        # Call Bedrock with retry logic (using boto3's built-in retry)
        response = invoke_bedrock_with_retry(prompt)
        
        # Parse the response
        response_body = json.loads(response["body"].read())
        ai_response = response_body["content"][0]["text"]
        
        # Parse and format findings
        findings = parse_ai_response(ai_response)
        
        return findings
        
    except Exception as e:
        logger.error(f"Error calling Bedrock: {e}", exc_info=True)
        # Return a minimal finding to indicate the error
        return [{
            "type": "ai_suggestion",
            "category": "Error",
            "priority": "low",
            "description": "AI analysis failed",
            "recommendation": f"Error during AI analysis: {str(e)}"
        }]


def build_analysis_prompt(pr_diff: str, pr_details: Dict[str, Any], repo_name: str, pr_number: int) -> str:
    """Build the analysis prompt for the AI model."""
    return f"""You are an expert code reviewer analyzing a pull request. Your task is to provide actionable suggestions to improve code quality, security, performance, and maintainability.

Repository: {repo_name}
Pull Request: #{pr_number}
Title: {pr_details.get('title', 'N/A')}
Description: {pr_details.get('description', 'No description provided')}
Files Changed: {pr_details.get('changed_files', 0)}
Lines Added: {pr_details.get('additions', 0)}
Lines Deleted: {pr_details.get('deletions', 0)}

Please analyze the following code diff and provide specific, actionable suggestions. Focus on:
1. Security vulnerabilities or potential security issues
2. Performance improvements
3. Code maintainability and readability
4. Best practices violations
5. Potential bugs or logic errors

For each suggestion, provide:
- Category: One of [Security, Performance, Maintainability, Reliability, Best Practices]
- Priority: One of [high, medium, low]
- File and line number (if applicable)
- Specific description of the issue
- Concrete recommendation for improvement

Format your response as a JSON array of suggestions. Each suggestion should have:
{{
    "category": "Security|Performance|Maintainability|Reliability|Best Practices",
    "priority": "high|medium|low",
    "file": "path/to/file.py",
    "line": 42,
    "description": "Clear description of the issue",
    "recommendation": "Specific recommendation to fix"
}}

Here is the code diff to analyze:

{pr_diff}

Provide only the JSON array in your response, no additional text."""


def invoke_bedrock_with_retry(prompt: str, max_retries: int = 3) -> Dict[str, Any]:
    """
    Invoke Bedrock with retry logic for transient errors.
    
    Args:
        prompt: The prompt to send to Bedrock
        max_retries: Maximum number of retry attempts
        
    Returns:
        Bedrock response
    """
    last_error = None
    
    for attempt in range(max_retries):
        try:
            response = bedrock_runtime.invoke_model(
                modelId=BEDROCK_MODEL_ID,
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": MAX_TOKENS,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": TEMPERATURE,
                    "top_p": TOP_P
                })
            )
            return response
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['ThrottlingException', 'ServiceUnavailable'] and attempt < max_retries - 1:
                # Exponential backoff
                wait_time = (2 ** attempt) + 1
                logger.warning(f"Bedrock API throttled, retrying in {wait_time} seconds...")
                import time
                time.sleep(wait_time)
                last_error = e
            else:
                raise
    
    if last_error:
        raise last_error


def parse_ai_response(ai_response: str) -> List[Dict[str, Any]]:
    """
    Parse the AI response and format it into standardized findings.
    
    Args:
        ai_response: Raw response from the AI model
        
    Returns:
        List of formatted findings
    """
    try:
        # Clean the response - sometimes Claude adds explanation before/after JSON
        json_start = ai_response.find('[')
        json_end = ai_response.rfind(']') + 1
        if json_start >= 0 and json_end > json_start:
            json_str = ai_response[json_start:json_end]
            suggestions = json.loads(json_str)
        else:
            suggestions = json.loads(ai_response)
    except json.JSONDecodeError:
        logger.error("Failed to parse AI response as JSON.", exc_info=True)
        suggestions = [{
            "category": "Maintainability",
            "priority": "medium",
            "description": "AI analysis completed but response parsing failed",
            "recommendation": "Review the code manually for the AI insights: " + ai_response[:200]
        }]
    
    # Format findings for our standard response
    findings = []
    for suggestion in suggestions:
        finding = {
            "type": "ai_suggestion",
            "category": suggestion.get("category", "General"),
            "priority": suggestion.get("priority", "medium"),
            "file": suggestion.get("file", ""),
            "line": suggestion.get("line", 0),
            "description": suggestion.get("description", ""),
            "recommendation": suggestion.get("recommendation", "")
        }
        findings.append(finding)
    
    return findings


def calculate_priority_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculate the breakdown of findings by priority."""
    return {
        "high_priority": len([f for f in findings if f.get("priority") == "high"]),
        "medium_priority": len([f for f in findings if f.get("priority") == "medium"]),
        "low_priority": len([f for f in findings if f.get("priority") == "low"])
    } 
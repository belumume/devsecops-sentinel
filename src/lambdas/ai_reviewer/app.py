import os
import json
import logging
from typing import List, Dict, Any
import boto3
import requests

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Initialize AWS clients
bedrock_runtime = boto3.client("bedrock-runtime", region_name="us-east-1")
secrets_manager = boto3.client("secretsmanager")

def lambda_handler(event, context):
    """
    Lambda handler that performs AI-powered code review using Amazon Bedrock.
    Now with REAL AI analysis using Claude 3.5 Sonnet!
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
        from sentinel_utils.python.utils import get_github_token
        github_token = get_github_token()
        
        # Fetch PR diff from GitHub
        pr_diff = fetch_pr_diff(repo_full_name, pr_number, github_token)
        
        if not pr_diff:
            logger.warning("No diff content found for PR.")
            return {
                "statusCode": 200,
                "scanner_type": "ai_review",
                "findings": [],
                "summary": {"total_findings": 0}
            }
        
        # Fetch PR details for context
        pr_details = fetch_pr_details(repo_full_name, pr_number, github_token)
        
        # Analyze with Bedrock
        findings = analyze_with_bedrock(pr_diff, pr_details, repo_full_name, pr_number)
        
        logger.info(f"Generated {len(findings)} AI suggestions")
        
        response = {
            "statusCode": 200,
            "scanner_type": "ai_review",
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "high_priority": len([f for f in findings if f.get("priority") == "high"]),
                "medium_priority": len([f for f in findings if f.get("priority") == "medium"]),
                "low_priority": len([f for f in findings if f.get("priority") == "low"])
            }
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Error during AI review: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "scanner_type": "ai_review",
            "error": str(e),
            "findings": [],
            "summary": {"total_findings": 0}
        }

def fetch_pr_diff(repo_full_name: str, pr_number: int, github_token: str) -> str:
    """
    Fetch the diff of a pull request from GitHub.
    """
    try:
        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3.diff"
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching PR diff from GitHub: {e}", exc_info=True)
        return None

def fetch_pr_details(repo_full_name: str, pr_number: int, github_token: str) -> Dict[str, Any]:
    """
    Fetch PR details including title, description, and files changed.
    """
    try:
        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(url, headers=headers, timeout=30)
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
    Analyze the PR diff using Amazon Bedrock with Claude 3.5 Sonnet.
    """
    # Truncate diff if too long (Claude has token limits)
    max_diff_chars = 30000  # Conservative limit
    if len(pr_diff) > max_diff_chars:
        pr_diff = pr_diff[:max_diff_chars] + "\n\n... (diff truncated due to size)"
        logger.warning("PR diff was truncated due to size.")
    
    # Construct the prompt
    prompt = f"""You are an expert code reviewer analyzing a pull request. Your task is to provide actionable suggestions to improve code quality, security, performance, and maintainability.

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

    try:
        # Call Bedrock
        response = bedrock_runtime.invoke_model(
            modelId="anthropic.claude-3-5-sonnet-20240620-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.1,  # Low temperature for consistent analysis
                "top_p": 0.9
            })
        )
        
        # Parse the response
        response_body = json.loads(response["body"].read())
        ai_response = response_body["content"][0]["text"]
        
        # Parse the JSON response
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
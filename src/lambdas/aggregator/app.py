import json
import logging
import os
from typing import Dict, List, Any, Optional

import boto3
import requests
from botocore.exceptions import ClientError

from sentinel_utils.utils import (
    get_github_token,
    create_session_with_retries,
    DEFAULT_TIMEOUT
)

# Configure logging following AWS best practices
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS clients
secrets_manager = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")

# Constants
COMMENT_MAX_SECRETS = 5
COMMENT_MAX_VULNERABILITIES = 5
COMMENT_MAX_AI_SUGGESTIONS = 6


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Aggregates scan results, posts a consolidated report to a GitHub PR,
    and logs a summary to DynamoDB.
    
    Args:
        event: Lambda event containing scan_results and repo_details
        context: Lambda context
        
    Returns:
        Response indicating success or failure of aggregation
    """
    logger.info("--- AggregatorFunction Invoked ---")
    logger.info(f"Received event: {json.dumps(event, indent=2)}")
    
    try:
        scan_results = event.get("scan_results", [])
        repo_details = event.get("repo_details", {})
        
        logger.info(f"Processing {len(scan_results)} scan results for PR #{repo_details.get('pr_number')}")
        
        aggregated_findings = aggregate_scan_results(scan_results)
        comment_body = format_github_comment(aggregated_findings, repo_details)
        
        # Always post a comment, even if there are no findings.
        github_response = post_github_comment(repo_details, comment_body)
        log_scan_summary(repo_details, aggregated_findings, context)
        
        logger.info("Successfully aggregated results and posted to GitHub.")
        
        return {
            'statusCode': 200,
            'aggregation_complete': True,
            'findings_summary': {
                'secrets_found': len(aggregated_findings.get('secrets', [])),
                'vulnerabilities_found': len(aggregated_findings.get('vulnerabilities', [])),
                'ai_suggestions': len(aggregated_findings.get('ai_suggestions', []))
            },
            'github_comment_posted': github_response.get('success', False)
        }
        
    except Exception as e:
        logger.error(f"Error in AggregatorFunction: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e),
            'aggregation_complete': False
        }


def aggregate_scan_results(scan_results: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """
    Consolidates findings from all individual scanner results.
    
    Args:
        scan_results: List of scanner results from Step Functions
        
    Returns:
        Dictionary with aggregated findings by type
    """
    aggregated = {'secrets': [], 'vulnerabilities': [], 'ai_suggestions': [], 'errors': []}
    
    for result in scan_results:
        try:
            # Handle cases where the payload is already a dict or a JSON string
            payload_raw = result.get('Payload', {})
            if isinstance(payload_raw, str):
                payload = json.loads(payload_raw)
            else:
                payload = payload_raw  # It's already a dict
            
            scanner_type = payload.get('scanner_type', 'unknown')
            findings = payload.get('findings', [])
            
            if payload.get('statusCode', 200) != 200:
                error_msg = payload.get('error', 'Unknown scanner error')
                aggregated['errors'].append({'scanner': scanner_type, 'error': error_msg})
                logger.warning(f"Received error from {scanner_type} scanner: {error_msg}")
                continue

            if scanner_type == 'secrets': 
                aggregated['secrets'].extend(findings)
            elif scanner_type == 'vulnerabilities': 
                aggregated['vulnerabilities'].extend(findings)
            elif scanner_type == 'ai_review': 
                aggregated['ai_suggestions'].extend(findings)
            
            logger.info(f"Processed {len(findings)} findings from {scanner_type} scanner.")
            
        except Exception as e:
            logger.error(f"Error processing a scan result: {str(e)}", exc_info=True)
            aggregated['errors'].append({'scanner': 'unknown', 'error': f"Failed to process result: {str(e)}"})
    
    return aggregated


def format_github_comment(findings: Dict[str, List[Any]], repo_details: Dict[str, Any]) -> str:
    """
    Formats the aggregated findings into a clear and actionable GitHub comment in Markdown.
    
    Args:
        findings: Aggregated findings from all scanners
        repo_details: Repository and PR details
        
    Returns:
        Formatted Markdown comment
    """
    secrets_count = len(findings.get('secrets', []))
    vulns_count = len(findings.get('vulnerabilities', []))
    ai_count = len(findings.get('ai_suggestions', []))
    errors_count = len(findings.get('errors', []))
    
    # Build the comment sections
    sections = []
    
    # Header
    sections.append(format_header())
    
    # Summary table
    sections.append(format_summary_table(secrets_count, vulns_count, ai_count))
    
    # Secret findings
    if secrets_count > 0:
        sections.append(format_secrets_section(findings['secrets'], secrets_count))
    
    # Vulnerability findings
    if vulns_count > 0:
        sections.append(format_vulnerabilities_section(findings['vulnerabilities'], vulns_count))
    
    # AI suggestions
    if ai_count > 0:
        sections.append(format_ai_suggestions_section(findings['ai_suggestions'], ai_count))
    
    # Errors section
    if errors_count > 0:
        sections.append(format_errors_section(findings['errors']))
    
    # Footer
    sections.append(format_footer(repo_details))
    
    return '\n'.join(sections)


def format_header() -> str:
    """Format the comment header."""
    return "## 🔍 DevSecOps Sentinel Analysis Report"


def format_summary_table(secrets_count: int, vulns_count: int, ai_count: int) -> str:
    """Format the summary table section."""
    secrets_icon = "🔴" if secrets_count > 0 else "✅"
    vulns_icon = "🟡" if vulns_count > 0 else "✅"
    ai_icon = "💡" if ai_count > 0 else "✅"
    
    return f"""
### 📊 Summary
| Scanner | Status | Findings |
|:---|:---:|:---|
| {secrets_icon} Secret Scanner | {'**Action Required**' if secrets_count > 0 else 'Clean'} | {secrets_count} secrets found |
| {vulns_icon} Vulnerability Scanner | {'**Review Needed**' if vulns_count > 0 else 'Clean'} | {vulns_count} vulnerabilities found |
| {ai_icon} AI Code Review | {'**Improvements Available**' if ai_count > 0 else 'Good Quality'} | {ai_count} suggestions |"""


def format_secrets_section(secrets: List[Dict[str, Any]], total_count: int) -> str:
    """Format the secrets findings section."""
    section = "\n### 🔴 Critical: Hardcoded Secrets Detected\n"
    section += "**Immediate action required:** Remove these secrets and rotate them.\n\n"
    
    for i, secret in enumerate(secrets[:COMMENT_MAX_SECRETS], 1):
        secret_type = secret.get('type', 'Secret')
        file_path = secret.get('file', 'unknown')
        line_num = secret.get('line', '?')
        section += f"{i}. **{secret_type}** found in `{file_path}` at line `{line_num}`\n"
    
    if total_count > COMMENT_MAX_SECRETS:
        section += f"\n*... and {total_count - COMMENT_MAX_SECRETS} more secrets found.*\n"
    
    return section


def format_vulnerabilities_section(vulnerabilities: List[Dict[str, Any]], total_count: int) -> str:
    """Format the vulnerabilities findings section."""
    section = "\n### 🟡 Dependency Vulnerabilities Detected\n"
    section += "**Action needed:** Update the following packages to their secure versions.\n\n"
    
    for i, vuln in enumerate(vulnerabilities[:COMMENT_MAX_VULNERABILITIES], 1):
        severity = vuln.get('severity', 'UNKNOWN')
        severity_emoji = "🔴" if severity == 'HIGH' else "🟡"
        
        package = vuln.get('package', 'unknown')
        installed_version = vuln.get('installed_version', vuln.get('version', '?'))
        fixed_version = vuln.get('fixed_version', '?')
        vulnerability = vuln.get('vulnerability', vuln.get('vulnerability_id', 'Unknown CVE'))
        description = vuln.get('description', 'No description')
        
        section += f"{i}. {severity_emoji} **{package}** `{installed_version}` → `{fixed_version}`\n"
        section += f"   - {vulnerability}: {description}\n"
    
    if total_count > COMMENT_MAX_VULNERABILITIES:
        section += f"\n*... and {total_count - COMMENT_MAX_VULNERABILITIES} more vulnerabilities found.*\n"
    
    return section


def format_ai_suggestions_section(suggestions: List[Dict[str, Any]], total_count: int) -> str:
    """Format the AI suggestions section."""
    section = "\n### 💡 AI Code Review Suggestions\n"
    section += "**Recommendations to improve code quality:**\n\n"
    
    # Group by priority
    high_priority = [s for s in suggestions if s.get('priority') == 'high']
    medium_priority = [s for s in suggestions if s.get('priority') == 'medium']
    low_priority = [s for s in suggestions if s.get('priority') == 'low']
    
    suggestions_shown = 0
    
    if high_priority:
        section += "#### 🔴 High Priority\n"
        for suggestion in high_priority[:3]:
            section += format_single_ai_suggestion(suggestion)
            suggestions_shown += 1
    
    if medium_priority and suggestions_shown < COMMENT_MAX_AI_SUGGESTIONS:
        section += "#### 🟡 Medium Priority\n"
        remaining_slots = COMMENT_MAX_AI_SUGGESTIONS - suggestions_shown
        for suggestion in medium_priority[:remaining_slots]:
            section += format_single_ai_suggestion(suggestion)
            suggestions_shown += 1
    
    if total_count > suggestions_shown:
        section += f"*... and {total_count - suggestions_shown} more suggestions available.*\n"
    
    return section


def format_single_ai_suggestion(suggestion: Dict[str, Any]) -> str:
    """Format a single AI suggestion."""
    category = suggestion.get('category', 'General')
    file_path = suggestion.get('file', 'unknown')
    line_num = suggestion.get('line', '?')
    description = suggestion.get('description', 'No description provided')
    recommendation = suggestion.get('recommendation', 'No recommendation provided')
    
    result = f"- **{category}**"
    if file_path != 'unknown' and file_path:
        result += f" in `{file_path}:{line_num}`"
    result += f"\n  {description}\n"
    result += f"  💡 {recommendation}\n\n"
    
    return result


def format_errors_section(errors: List[Dict[str, Any]]) -> str:
    """Format the errors section."""
    section = "\n### ⚠️ Scanner Errors\n"
    section += "Some scanners encountered errors during analysis:\n\n"
    
    for error in errors:
        scanner = error.get('scanner', 'Unknown')
        error_msg = error.get('error', 'Unknown error')
        section += f"- **{scanner} scanner:** {error_msg}\n"
    
    return section


def format_footer(repo_details: Dict[str, Any]) -> str:
    """Format the comment footer."""
    commit_sha = repo_details.get('commit_sha', 'unknown')[:7]
    return f"\n---\n*🚀 Analysis completed for commit `{commit_sha}` • Powered by [DevSecOps Sentinel](https://github.com/belumume/devsecops-sentinel)*"


def post_github_comment(repo_details: Dict[str, Any], comment_body: str) -> Dict[str, Any]:
    """
    Posts the formatted comment to the GitHub PR using the GitHub REST API.
    
    Args:
        repo_details: Repository and PR information
        comment_body: Formatted comment content
        
    Returns:
        Dictionary with success status and response
    """
    try:
        token = get_github_token()
        repo_full_name = repo_details.get("repository_full_name")
        pr_number = repo_details.get("pr_number")

        if not repo_full_name or not pr_number:
            raise ValueError("Missing repository name or PR number.")

        url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        payload = {"body": comment_body}
        
        logger.info(f"Posting comment to {url}")
        
        # Use session with retries
        session = create_session_with_retries()
        response = session.post(url, headers=headers, json=payload, timeout=DEFAULT_TIMEOUT)
        
        response.raise_for_status()
        
        logger.info(f"Successfully posted comment to PR #{pr_number}. Response: {response.status_code}")
        return {'success': True, 'response': response.json()}

    except requests.exceptions.HTTPError as e:
        logger.error(f"GitHub API HTTP error: {e.response.status_code} - {e.response.text}", exc_info=True)
        return {'success': False, 'error': f"GitHub API error: {e.response.status_code}"}
    except Exception as e:
        logger.error(f"Failed to post comment to GitHub: {str(e)}", exc_info=True)
        return {'success': False, 'error': str(e)}


def log_scan_summary(repo_details: Dict[str, Any], findings: Dict[str, List[Any]], context: Any) -> None:
    """
    Logs a summary of the scan to a DynamoDB table for auditing.
    
    Args:
        repo_details: Repository and PR information
        findings: Aggregated findings
        context: Lambda context for request ID
    """
    try:
        table_name = os.environ.get('SCANS_TABLE_NAME', 'ScansTable')
        table = dynamodb.Table(table_name)
        
        scan_record = {
            'pull_request_id': str(repo_details.get('pull_request_id')),
            'repository_full_name': repo_details.get('repository_full_name'),
            'pr_number': int(repo_details.get('pr_number')),
            'commit_sha': repo_details.get('commit_sha'),
            'secrets_found': len(findings.get('secrets', [])),
            'vulnerabilities_found': len(findings.get('vulnerabilities', [])),
            'ai_suggestions': len(findings.get('ai_suggestions', [])),
            'errors_count': len(findings.get('errors', [])),
            'scan_timestamp': str(context.aws_request_id),
        }
        
        table.put_item(Item=scan_record)
        logger.info(f"Logged scan summary to DynamoDB for PR #{repo_details.get('pr_number')}")
        
    except ClientError as e:
        logger.error(f"DynamoDB error: {e.response['Error']['Message']}", exc_info=True)
    except Exception as e:
        logger.error(f"Failed to log scan summary to DynamoDB: {str(e)}", exc_info=True)

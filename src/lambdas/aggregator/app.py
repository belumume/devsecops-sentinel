import json
import os
import boto3
import logging
import requests
from typing import Dict, List, Any

# Configure logging following AWS best practices
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS clients
secrets_manager = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")


from sentinel_utils.python.utils import get_github_token


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Aggregates scan results, posts a consolidated report to a GitHub PR,
    and logs a summary to DynamoDB.
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
    """Consolidates findings from all individual scanner results."""
    aggregated = {'secrets': [], 'vulnerabilities': [], 'ai_suggestions': [], 'errors': []}
    
    for result in scan_results:
        try:
            # BUG FIX: Handle cases where the payload is already a dict or a JSON string
            payload_raw = result.get('Payload', {})
            if isinstance(payload_raw, str):
                payload = json.loads(payload_raw)
            else:
                payload = payload_raw # It's already a dict
            
            scanner_type = payload.get('scanner_type', 'unknown')
            findings = payload.get('findings', [])
            
            if payload.get('statusCode', 200) != 200:
                error_msg = payload.get('error', 'Unknown scanner error')
                aggregated['errors'].append({'scanner': scanner_type, 'error': error_msg})
                logger.warning(f"Received error from {scanner_type} scanner: {error_msg}")
                continue

            if scanner_type == 'secrets': aggregated['secrets'].extend(findings)
            elif scanner_type == 'vulnerabilities': aggregated['vulnerabilities'].extend(findings)
            elif scanner_type == 'ai_review': aggregated['ai_suggestions'].extend(findings)
            
            logger.info(f"Processed {len(findings)} findings from {scanner_type} scanner.")
            
        except Exception as e:
            logger.error(f"Error processing a scan result: {str(e)}", exc_info=True)
            aggregated['errors'].append({'scanner': 'unknown', 'error': f"Failed to process result: {str(e)}"})
    
    return aggregated


def format_github_comment(findings: Dict[str, List[Any]], repo_details: Dict[str, Any]) -> str:
    """Formats the aggregated findings into a clear and actionable GitHub comment in Markdown."""
    secrets_count = len(findings.get('secrets', []))
    vulns_count = len(findings.get('vulnerabilities', []))
    ai_count = len(findings.get('ai_suggestions', []))
    errors_count = len(findings.get('errors', []))
    
    secrets_icon = "🔴" if secrets_count > 0 else "✅"
    vulns_icon = "🟡" if vulns_count > 0 else "✅"
    ai_icon = "💡" if ai_count > 0 else "✅"
    
    comment = f"""## 🔍 DevSecOps Sentinel Analysis Report

### 📊 Summary
| Scanner | Status | Findings |
|:---|:---:|:---|
| {secrets_icon} Secret Scanner | {'**Action Required**' if secrets_count > 0 else 'Clean'} | {secrets_count} secrets found |
| {vulns_icon} Vulnerability Scanner | {'**Review Needed**' if vulns_count > 0 else 'Clean'} | {vulns_count} vulnerabilities found |
| {ai_icon} AI Code Review | {'**Improvements Available**' if ai_count > 0 else 'Good Quality'} | {ai_count} suggestions |
"""
    
    # Secret findings
    if secrets_count > 0:
        comment += "\n### 🔴 Critical: Hardcoded Secrets Detected\n"
        comment += "**Immediate action required:** Remove these secrets and rotate them.\n\n"
        for i, secret in enumerate(findings['secrets'][:5], 1):
            comment += f"{i}. **{secret.get('type', 'Secret')}** found in `{secret.get('file', 'unknown')}` at line `{secret.get('line', '?')}`\n"
        if secrets_count > 5:
            comment += f"\n*... and {secrets_count - 5} more secrets found.*\n"
    
    # Vulnerability findings
    if vulns_count > 0:
        comment += "\n### 🟡 Dependency Vulnerabilities Detected\n"
        comment += "**Action needed:** Update the following packages to their secure versions.\n\n"
        for i, vuln in enumerate(findings['vulnerabilities'][:5], 1):
            severity_emoji = "🔴" if vuln.get('severity') == 'HIGH' else "🟡"
            comment += f"{i}. {severity_emoji} **{vuln.get('package', 'unknown')}** `{vuln.get('installed_version', '?')}` → `{vuln.get('fixed_version', '?')}`\n"
            comment += f"   - {vuln.get('vulnerability', 'Unknown CVE')}: {vuln.get('description', 'No description')}\n"
        if vulns_count > 5:
            comment += f"\n*... and {vulns_count - 5} more vulnerabilities found.*\n"
    
    # AI suggestions
    if ai_count > 0:
        comment += "\n### 💡 AI Code Review Suggestions\n"
        comment += "**Recommendations to improve code quality:**\n\n"
        
        # Group by priority (AI reviewer uses 'priority' not 'severity')
        high_priority = [s for s in findings['ai_suggestions'] if s.get('priority') == 'high']
        medium_priority = [s for s in findings['ai_suggestions'] if s.get('priority') == 'medium']
        low_priority = [s for s in findings['ai_suggestions'] if s.get('priority') == 'low']
        
        if high_priority:
            comment += "#### 🔴 High Priority\n"
            for suggestion in high_priority[:3]:
                comment += f"- **{suggestion.get('category', 'General')}** in `{suggestion.get('file', 'unknown')}:{suggestion.get('line', '?')}`\n"
                comment += f"  {suggestion.get('description', 'No description provided')}\n"
                comment += f"  💡 {suggestion.get('recommendation', 'No recommendation provided')}\n\n"
        
        if medium_priority:
            comment += "#### 🟡 Medium Priority\n"
            for suggestion in medium_priority[:3]:
                comment += f"- **{suggestion.get('category', 'General')}** in `{suggestion.get('file', 'unknown')}:{suggestion.get('line', '?')}`\n"
                comment += f"  {suggestion.get('description', 'No description provided')}\n"
                comment += f"  💡 {suggestion.get('recommendation', 'No recommendation provided')}\n\n"
        
        if ai_count > 6:
            comment += f"*... and {ai_count - 6} more suggestions available.*\n"
    
    # Errors section
    if errors_count > 0:
        comment += f"\n### ⚠️ Scanner Errors\n"
        comment += "Some scanners encountered errors during analysis:\n\n"
        for error in findings['errors']:
            comment += f"- **{error.get('scanner', 'Unknown')} scanner:** {error.get('error', 'Unknown error')}\n"
    
    comment += f"\n---\n"
    comment += f"*🚀 Analysis completed for commit `{repo_details.get('commit_sha', 'unknown')[:7]}` • Powered by [DevSecOps Sentinel](https://github.com/aws-lambda-hackathon/devsecops-sentinel)*"
    
    return comment


def post_github_comment(repo_details: Dict[str, Any], comment_body: str) -> Dict[str, Any]:
    """Posts the formatted comment to the GitHub PR using the GitHub REST API."""
    try:
        token = get_github_token()
        repo_full_name = repo_details.get("repository_full_name")
        pr_number = repo_details.get("pr_number")

        if not repo_full_name or not pr_number:
            raise ValueError("Missing repository name or PR number.")

        url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        payload = {"body": comment_body}
        
        logger.info(f"Posting comment to {url}")
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        response.raise_for_status()
        
        logger.info(f"Successfully posted comment to PR #{pr_number}. Response: {response.status_code}")
        return {'success': True, 'response': response.json()}

    except Exception as e:
        logger.error(f"Failed to post comment to GitHub: {str(e)}", exc_info=True)
        return {'success': False, 'error': str(e)}


def log_scan_summary(repo_details: Dict[str, Any], findings: Dict[str, List[Any]], context: Any) -> None:
    """Logs a summary of the scan to a DynamoDB table for auditing."""
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
        
    except Exception as e:
        logger.error(f"Failed to log scan summary to DynamoDB: {str(e)}", exc_info=True)

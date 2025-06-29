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
COMMENT_MAX_SECRETS = 10
COMMENT_MAX_VULNERABILITIES = 10
# Removed COMMENT_MAX_AI_SUGGESTIONS - now using collapsible sections for all suggestions


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
    aggregated = {
        'secrets': [], 
        'vulnerabilities': [], 
        'ai_suggestions': [], 
        'errors': [],
        'tool_errors': []  # Add separate category for tool availability issues
    }
    
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

            # Separate tool_error findings from actual findings
            tool_errors = [f for f in findings if f.get('type') == 'tool_error']
            actual_findings = [f for f in findings if f.get('type') != 'tool_error']

            if tool_errors:
                aggregated['tool_errors'].extend(tool_errors)
                logger.warning(f"{scanner_type} scanner reported {len(tool_errors)} tool errors")

            if scanner_type == 'secrets':
                aggregated['secrets'].extend(actual_findings)
            elif scanner_type == 'vulnerabilities':
                # Handle both 'vulnerability' and 'dependency_vulnerability' types
                vuln_findings = [f for f in actual_findings if f.get('type') in ['vulnerability', 'dependency_vulnerability']]
                aggregated['vulnerabilities'].extend(vuln_findings)
                logger.info(f"Added {len(vuln_findings)} vulnerability findings")
            elif scanner_type == 'ai_review':
                aggregated['ai_suggestions'].extend(actual_findings)
            
            logger.info(f"Processed {len(actual_findings)} findings from {scanner_type} scanner.")
            
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
    vulns_list = findings.get('vulnerabilities', [])
    vulns_count = len(vulns_list)  # Total vulnerabilities for logging
    ai_count = len(findings.get('ai_suggestions', []))
    errors_count = len(findings.get('errors', []))
    tool_errors_count = len(findings.get('tool_errors', []))
    
    # Count unique packages affected by vulnerabilities
    unique_packages = set()
    for vuln in vulns_list:
        package = vuln.get('package', 'unknown')
        version = vuln.get('installed_version', vuln.get('version', '?'))
        key = f"{package}@{version}"
        unique_packages.add(key)
    
    package_count = len(unique_packages)
    
    # Build the comment sections
    sections = []
    
    # Header
    sections.append(format_header())
    
    # Tool errors warning (show prominently if tools are missing)
    if tool_errors_count > 0:
        sections.append(format_tool_errors_section(findings['tool_errors']))
    
    # Summary table - use package count for display
    sections.append(format_summary_table(secrets_count, package_count, ai_count))
    
    # Secret findings
    if secrets_count > 0:
        sections.append(format_secrets_section(findings['secrets'], secrets_count))
    
    # Vulnerability findings - pass full list but display will group by package
    if vulns_count > 0:
        sections.append(format_vulnerabilities_section(vulns_list, vulns_count))
    
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


def format_summary_table(secrets_count: int, vulnerable_packages_count: int, ai_count: int) -> str:
    """Format the summary table section - Enhanced to match README example."""
    # Determine status for each scanner
    if secrets_count > 0:
        secrets_icon = "🔴"
        secrets_status = "**Action Required**"
    else:
        secrets_icon = "✅"
        secrets_status = "Clean"
    
    if vulnerable_packages_count > 0:
        vulns_icon = "🟡"
        vulns_status = "**Review Needed**"
    else:
        vulns_icon = "✅"
        vulns_status = "Clean"
    
    if ai_count > 0:
        ai_icon = "💡"
        ai_status = "**Improvements Available**"
    else:
        ai_icon = "✅"
        ai_status = "Good Quality"
    
    return f"""
### 📊 Summary
| Scanner | Status | Findings |
|:---|:---:|:---|
| {secrets_icon} Secret Scanner | {secrets_status} | {secrets_count} secrets found |
| {vulns_icon} Vulnerability Scanner | {vulns_status} | {vulnerable_packages_count} vulnerable packages |
| {ai_icon} AI Code Review | {ai_status} | {ai_count} suggestions |"""


def format_secrets_section(secrets: List[Dict[str, Any]], total_count: int) -> str:
    """Format the secrets findings section - Enhanced with better formatting."""
    section = "\n### 🔴 Critical: Hardcoded Secrets Detected\n"
    section += "**Immediate action required:** Remove these secrets and rotate them.\n\n"
    
    for i, secret in enumerate(secrets[:COMMENT_MAX_SECRETS], 1):
        # Handle both 'type' and 'secret_type' fields, and format properly
        raw_type = secret.get('type', secret.get('secret_type', 'Secret'))
        # Convert enum values like "SecretType.API_KEY" to readable format
        if 'SecretType.' in str(raw_type):
            secret_type = str(raw_type).replace('SecretType.', '').replace('_', ' ').title()
        else:
            secret_type = str(raw_type).replace('_', ' ').title()
        # Handle "unknown" as a special case
        if secret_type.lower() == 'unknown':
            secret_type = 'Secret'
        file_path = secret.get('file', 'unknown')
        line_num = secret.get('line', '?')
        # Format exactly like README example
        section += f"{i}. **{secret_type}** found in `{file_path}` at line `{line_num}`\n"
    
    if total_count > COMMENT_MAX_SECRETS:
        # Use collapsible section for remaining secrets
        section += f"\n<details>\n<summary>... and {total_count - COMMENT_MAX_SECRETS} more secrets found</summary>\n\n"
        for i, secret in enumerate(secrets[COMMENT_MAX_SECRETS:], COMMENT_MAX_SECRETS + 1):
            # Handle both 'type' and 'secret_type' fields, and format properly
            raw_type = secret.get('type', secret.get('secret_type', 'Secret'))
            # Convert enum values like "SecretType.API_KEY" to readable format
            if 'SecretType.' in str(raw_type):
                secret_type = str(raw_type).replace('SecretType.', '').replace('_', ' ').title()
            else:
                secret_type = str(raw_type).replace('_', ' ').title()
            # Handle "unknown" as a special case
            if secret_type.lower() == 'unknown':
                secret_type = 'Secret'
            file_path = secret.get('file', 'unknown')
            line_num = secret.get('line', '?')
            section += f"{i}. **{secret_type}** found in `{file_path}` at line `{line_num}`\n"
        section += "\n</details>\n"
    
    return section


def format_vulnerabilities_section(vulnerabilities: List[Dict[str, Any]], total_count: int) -> str:
    """Format the vulnerabilities findings section - Enhanced formatting with grouping by package."""
    section = "\n### 🟡 Dependency Vulnerabilities Detected\n"
    
    # Group vulnerabilities by package and version
    package_vulns = {}
    for vuln in vulnerabilities:
        package = vuln.get('package', 'unknown')
        version = vuln.get('installed_version', vuln.get('version', '?'))
        key = f"{package}@{version}"
        
        if key not in package_vulns:
            package_vulns[key] = {
                'package': package,
                'version': version,
                'fixed_versions': [],
                'vulnerabilities': []
            }
        
        # Collect fixed versions
        fixed_version = vuln.get('fixed_version', '')
        if fixed_version and fixed_version != '?' and fixed_version not in package_vulns[key]['fixed_versions']:
            package_vulns[key]['fixed_versions'].append(fixed_version)
        
        # Add vulnerability details
        package_vulns[key]['vulnerabilities'].append({
            'id': vuln.get('vulnerability', vuln.get('vulnerability_id', 'Unknown')),
            'severity': vuln.get('severity', 'UNKNOWN'),
            'description': vuln.get('description', 'No description')
        })
    
    # Sort packages by number of vulnerabilities (most vulnerable first)
    sorted_packages = sorted(package_vulns.items(), key=lambda x: len(x[1]['vulnerabilities']), reverse=True)
    
    # Count affected packages
    package_count = len(sorted_packages)
    section += f"**Action needed:** Update the following {package_count} packages to their secure versions.\n\n"
    
    # Show first 10 packages directly
    for i, (key, pkg_info) in enumerate(sorted_packages[:COMMENT_MAX_VULNERABILITIES], 1):
        # Determine severity emoji based on highest severity vulnerability
        severities = [v['severity'] for v in pkg_info['vulnerabilities']]
        severity_emoji = "🔴" if any(s in ['HIGH', 'CRITICAL'] for s in severities) else "🟡"
        
        # Determine fixed version (prefer latest if multiple)
        if pkg_info['fixed_versions']:
            # Filter out non-version strings and sort actual versions
            actual_versions = []
            guidance_messages = []
            
            for v in pkg_info['fixed_versions']:
                if v and any(char in v for char in ['.', '-', '+']) and v[0].isdigit():
                    # Looks like an actual version number
                    actual_versions.append(v)
                elif v and ('check' in v.lower() or 'update' in v.lower() or 'latest' in v.lower()):
                    # It's a guidance message
                    guidance_messages.append(v)
            
            if actual_versions:
                # Sort and take the latest actual version
                fixed_version = sorted(actual_versions)[-1]
            elif guidance_messages:
                # Use the first guidance message
                fixed_version = guidance_messages[0]
            else:
                # Fallback
                fixed_version = pkg_info['fixed_versions'][-1]
        else:
            fixed_version = "check for updates"
        
        section += f"{i}. {severity_emoji} **{pkg_info['package']}** `{pkg_info['version']}` → `{fixed_version}`\n"
        
        # Show up to 3 vulnerabilities directly
        vuln_list = pkg_info['vulnerabilities']
        for j, vuln in enumerate(vuln_list[:3]):
            section += f"   - {vuln['id']}: {vuln['description']}\n"
        
        # If more than 3 vulnerabilities, show count
        if len(vuln_list) > 3:
            section += f"   - ... and {len(vuln_list) - 3} more vulnerabilities\n"
    
    # Remaining packages in collapsible section
    if package_count > COMMENT_MAX_VULNERABILITIES:
        section += f"\n<details>\n<summary>... and {package_count - COMMENT_MAX_VULNERABILITIES} more vulnerable packages found</summary>\n\n"
        
        for i, (key, pkg_info) in enumerate(sorted_packages[COMMENT_MAX_VULNERABILITIES:], COMMENT_MAX_VULNERABILITIES + 1):
            # Determine severity emoji
            severities = [v['severity'] for v in pkg_info['vulnerabilities']]
            severity_emoji = "🔴" if any(s in ['HIGH', 'CRITICAL'] for s in severities) else "🟡"
            
            # Determine fixed version
            if pkg_info['fixed_versions']:
                # Filter out non-version strings and sort actual versions
                actual_versions = []
                guidance_messages = []
                
                for v in pkg_info['fixed_versions']:
                    if v and any(char in v for char in ['.', '-', '+']) and v[0].isdigit():
                        # Looks like an actual version number
                        actual_versions.append(v)
                    elif v and ('check' in v.lower() or 'update' in v.lower() or 'latest' in v.lower()):
                        # It's a guidance message
                        guidance_messages.append(v)
                
                if actual_versions:
                    # Sort and take the latest actual version
                    fixed_version = sorted(actual_versions)[-1]
                elif guidance_messages:
                    # Use the first guidance message
                    fixed_version = guidance_messages[0]
                else:
                    # Fallback
                    fixed_version = pkg_info['fixed_versions'][-1]
            else:
                fixed_version = "check for updates"
            
            section += f"{i}. {severity_emoji} **{pkg_info['package']}** `{pkg_info['version']}` → `{fixed_version}`\n"
            
            # Show vulnerabilities
            vuln_list = pkg_info['vulnerabilities']
            for j, vuln in enumerate(vuln_list[:3]):
                section += f"   - {vuln['id']}: {vuln['description']}\n"
            
            if len(vuln_list) > 3:
                section += f"   - ... and {len(vuln_list) - 3} more vulnerabilities\n"
        
        section += "\n</details>\n"
    
    # Add total vulnerability count at the end
    section += f"\n*Total: {total_count} vulnerabilities across {package_count} packages*\n"
    
    return section


def format_ai_suggestions_section(suggestions: List[Dict[str, Any]], total_count: int) -> str:
    """Format the AI suggestions section - Now with collapsible details for all suggestions."""
    section = "\n### 💡 AI Code Review Suggestions\n"
    section += "**Recommendations to improve code quality:**\n\n"
    
    # Group by priority
    high_priority = [s for s in suggestions if s.get('priority') == 'high']
    medium_priority = [s for s in suggestions if s.get('priority') == 'medium']
    low_priority = [s for s in suggestions if s.get('priority') == 'low']
    
    # Show high priority suggestions directly (first 3-5)
    if high_priority:
        section += "#### 🔴 High Priority\n"
        for suggestion in high_priority[:3]:
            section += format_single_ai_suggestion(suggestion)
    
    # Show some medium priority if room
    shown_count = min(3, len(high_priority))
    if medium_priority and shown_count < 5:
        section += "\n#### 🟡 Medium Priority\n"
        remaining_slots = 5 - shown_count
        for suggestion in medium_priority[:remaining_slots]:
            section += format_single_ai_suggestion(suggestion)
        shown_count += min(remaining_slots, len(medium_priority))
    
    # Calculate remaining suggestions
    remaining_high = high_priority[3:] if len(high_priority) > 3 else []
    remaining_medium = medium_priority[max(0, 5-len(high_priority[:3])):] if medium_priority else []
    remaining_suggestions = remaining_high + remaining_medium + low_priority
    
    # Put remaining in collapsible section
    if remaining_suggestions:
        section += f"\n<details>\n<summary><strong>... and {len(remaining_suggestions)} more suggestions available</strong> (click to expand)</summary>\n\n"
        
        # Add remaining high priority
        if remaining_high:
            section += "#### 🔴 High Priority (continued)\n"
            for suggestion in remaining_high:
                section += format_single_ai_suggestion(suggestion)
        
        # Add remaining medium priority
        if remaining_medium:
            section += "\n#### 🟡 Medium Priority" + (" (continued)" if shown_count > len(high_priority) else "") + "\n"
            for suggestion in remaining_medium:
                section += format_single_ai_suggestion(suggestion)
        
        # Add low priority
        if low_priority:
            section += "\n#### 🟢 Low Priority\n"
            for suggestion in low_priority:
                section += format_single_ai_suggestion(suggestion)
        
        section += "\n</details>\n"
    
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


def format_tool_errors_section(tool_errors: List[Dict[str, Any]]) -> str:
    """Format the tool errors section - shown when scanner tools are missing."""
    section = "\n### ⚠️ Scanner Tools Not Available\n"
    section += "**Important:** Some security scanning tools are not available in the current environment. This may result in incomplete security analysis.\n\n"
    
    # Group by scanner type
    tool_issues = {}
    for error in tool_errors:
        desc = error.get('raw', error.get('description', 'Tool not available'))
        if 'npm' in desc.lower():
            tool_issues['Node.js Scanner'] = "npm tool not available - Node.js vulnerability scanning skipped"
        elif 'safety' in desc.lower():
            tool_issues['Python Scanner'] = "safety tool not available - Python vulnerability scanning skipped" 
        elif 'trufflehog' in desc.lower():
            tool_issues['Secret Scanner'] = "TruffleHog tool not available - Secret detection may be limited"
    
    for scanner, issue in tool_issues.items():
        section += f"- **{scanner}:** {issue}\n"
    
    section += "\n**To fix this:** Deploy the scanner tools Lambda layer. See [deployment instructions](https://github.com/belumume/devsecops-sentinel/blob/main/docs/SCANNER_TOOLS_FIX.md).\n"
    
    return section


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
    Updates existing comment if progress_comment_id is provided.
    
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
        progress_comment_id = repo_details.get("progress_comment_id")

        if not repo_full_name or not pr_number:
            raise ValueError("Missing repository name or PR number.")

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        payload = {"body": comment_body}
        
        # Use session with retries
        session = create_session_with_retries()
        
        if progress_comment_id:
            # Update existing comment
            url = f"https://api.github.com/repos/{repo_full_name}/issues/comments/{progress_comment_id}"
            logger.info(f"Updating existing comment {progress_comment_id} at {url}")
            response = session.patch(url, headers=headers, json=payload, timeout=DEFAULT_TIMEOUT)
        else:
            # Create new comment
            url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
            logger.info(f"Posting new comment to {url}")
            response = session.post(url, headers=headers, json=payload, timeout=DEFAULT_TIMEOUT)
        
        response.raise_for_status()
        
        action = "Updated" if progress_comment_id else "Posted"
        logger.info(f"Successfully {action} comment to PR #{pr_number}. Response: {response.status_code}")
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

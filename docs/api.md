# DevSecOps Sentinel - API Reference

## Overview

DevSecOps Sentinel exposes a single webhook endpoint for GitHub integration and uses the GitHub API for posting results.

## Webhook Endpoint

### POST /webhook

Receives GitHub webhook events for pull request actions.

**Endpoint**: `https://{api-id}.execute-api.{region}.amazonaws.com/Prod/webhook`

#### Request Headers

| Header | Type | Required | Description |
|--------|------|----------|-------------|
| `X-Hub-Signature-256` | string | Yes | HMAC hex digest of the request body |
| `X-GitHub-Event` | string | Yes | GitHub event type (must be "pull_request") |
| `Content-Type` | string | Yes | Must be "application/json" |

#### Request Body

GitHub Pull Request event payload:

```json
{
  "action": "opened" | "synchronize" | "reopened",
  "pull_request": {
    "number": 123,
    "title": "Add new feature",
    "state": "open",
    "head": {
      "ref": "feature-branch",
      "sha": "abc123def456"
    },
    "base": {
      "ref": "main",
      "sha": "789ghi012jkl"
    },
    "diff_url": "https://github.com/owner/repo/pull/123.diff",
    "user": {
      "login": "username"
    }
  },
  "repository": {
    "name": "repo-name",
    "owner": {
      "login": "owner-name"
    },
    "full_name": "owner/repo"
  }
}
```

#### Response

##### Success Response (200 OK)

```json
{
  "statusCode": 200,
  "body": {
    "message": "Webhook processed successfully",
    "execution_arn": "arn:aws:states:region:account:execution:StateMachine:execution-id"
  }
}
```

##### Error Responses

**400 Bad Request**
```json
{
  "statusCode": 400,
  "body": {
    "error": "Invalid signature"
  }
}
```

**500 Internal Server Error**
```json
{
  "statusCode": 500,
  "body": {
    "error": "Internal server error",
    "details": "Error message"
  }
}
```

#### Webhook Security

All webhook requests are validated using HMAC-SHA256:

```python
# Signature validation example
import hmac
import hashlib

def validate_signature(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(
        f"sha256={expected}",
        signature
    )
```

## GitHub API Integration

DevSecOps Sentinel uses the GitHub API v3 for posting analysis results.

### Authentication

Uses Personal Access Token (PAT) stored in AWS Secrets Manager.

Required scopes:
- `repo` - Full control of private repositories
- `write:discussion` - Write access to discussions (for PR comments)

### API Endpoints Used

#### Create Issue Comment

**POST** `/repos/{owner}/{repo}/issues/{issue_number}/comments`

```json
{
  "body": "## 🔍 DevSecOps Sentinel Analysis\n\n..."
}
```

#### Update Issue Comment

**PATCH** `/repos/{owner}/{repo}/issues/comments/{comment_id}`

```json
{
  "body": "## 🔍 DevSecOps Sentinel Analysis\n\n✅ Analysis complete!..."
}
```

## Internal Lambda APIs

### Scanner Lambda Input Format

All scanner Lambdas receive the same input structure:

```json
{
  "repository": "owner/repo",
  "pr_number": 123,
  "base_branch": "main",
  "head_branch": "feature-branch",
  "diff_url": "https://github.com/owner/repo/pull/123.diff"
}
```

### Scanner Lambda Output Format

#### SecretScanner Output

```json
{
  "scanner": "secrets",
  "findings": [
    {
      "type": "secret",
      "severity": "high",
      "secret_type": "API Key",
      "file": "config/settings.py",
      "line": 42,
      "column": 15,
      "evidence": "api_key = 'sk-...'",
      "confidence": 0.95
    }
  ],
  "summary": {
    "total_secrets": 1,
    "high_severity": 1,
    "medium_severity": 0,
    "low_severity": 0
  },
  "scan_duration_ms": 1234
}
```

#### VulnerabilityScanner Output

```json
{
  "scanner": "vulnerabilities",
  "findings": [
    {
      "type": "vulnerability",
      "package": "requests",
      "version": "2.20.0",
      "vulnerability_id": "CVE-2023-32681",
      "severity": "high",
      "description": "Security vulnerability in requests",
      "fixed_version": "2.31.0",
      "cvss_score": 7.5
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "packages_scanned": 45,
  "scan_duration_ms": 2345
}
```

#### AIReviewer Output

```json
{
  "scanner": "ai_review",
  "findings": [
    {
      "type": "ai_suggestion",
      "category": "Security",
      "priority": "high",
      "file": "app.py",
      "line": 100,
      "description": "SQL injection vulnerability",
      "recommendation": "Use parameterized queries"
    }
  ],
  "summary": {
    "total_findings": 1,
    "high_priority": 1,
    "medium_priority": 0,
    "low_priority": 0
  },
  "scan_duration_ms": 5000
}
```

### Aggregator Lambda Input

Receives results from all scanners via Step Functions:

```json
[
  {
    "Payload": { /* SecretScanner output */ }
  },
  {
    "Payload": { /* VulnerabilityScanner output */ }
  },
  {
    "Payload": { /* AIReviewer output */ }
  }
]
```

### DynamoDB Schema

#### ScansTable

| Attribute | Type | Description |
|-----------|------|-------------|
| `pr_id` (PK) | String | Format: "{owner}/{repo}/pull/{number}" |
| `scan_timestamp` (SK) | String | ISO 8601 timestamp |
| `repository` | String | Repository full name |
| `pr_number` | Number | Pull request number |
| `scan_results` | Map | Complete scan findings |
| `scan_duration_ms` | Number | Total scan duration |
| `scanner_durations` | Map | Individual scanner timings |

## Environment Variables

### WebhookHandler
- `STATE_MACHINE_ARN`: Step Functions state machine ARN
- `GITHUB_WEBHOOK_SECRET_NAME`: Secrets Manager secret name
- `GITHUB_TOKEN_SECRET_NAME`: Secrets Manager secret name

### Scanner Lambdas
- `GITHUB_TOKEN_SECRET_NAME`: Secrets Manager secret name

### Aggregator
- `GITHUB_TOKEN_SECRET_NAME`: Secrets Manager secret name
- `DYNAMODB_TABLE_NAME`: DynamoDB table name

## Rate Limits

### API Gateway
- 10,000 requests per second (burst)
- 5,000 requests per second (steady state)

### GitHub API
- 5,000 requests per hour (authenticated)
- 60 requests per hour per IP (unauthenticated)

### Lambda Concurrency
- 1,000 concurrent executions (default)
- Can be increased via AWS support

## Error Handling

All Lambda functions implement exponential backoff and retry logic:

```python
@backoff.on_exception(
    backoff.expo,
    requests.exceptions.RequestException,
    max_tries=3,
    max_time=30
)
def make_github_request():
    # API call implementation
```

## Webhook Configuration

To configure GitHub webhook:

1. Go to Repository Settings → Webhooks
2. Add webhook:
   - **Payload URL**: Your API Gateway endpoint
   - **Content type**: `application/json`
   - **Secret**: Your webhook secret
   - **Events**: Select "Pull requests"
   - **Active**: ✓

## Testing

### Local Testing

```bash
# Test webhook signature validation
curl -X POST https://your-api.execute-api.region.amazonaws.com/Prod/webhook \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=..." \
  -H "X-GitHub-Event: pull_request" \
  -d @test-payload.json
```

### Integration Testing

See `tests/integration/test_end_to_end.py` for complete examples.

---

**API Version**: 1.0.0  
**Last Updated**: December 2024 
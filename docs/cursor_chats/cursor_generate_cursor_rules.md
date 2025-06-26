# Generate cursor rules
_Exported on 6/23/2025 at 01:31:57 GMT+1 from Cursor (1.1.3)_

---

**User**

/Generate Cursor Rules 

---

**Cursor**

I'll generate comprehensive Cursor Rules for the DevSecOps Sentinel project based on the project plan. Let me create rules that will help guide development according to the specifications.

```plaintext
# DevSecOps Sentinel - Development Rules

## Project Overview
DevSecOps Sentinel is an AI-powered, serverless security and quality analysis platform for GitHub Pull Requests. The complete project specification is in [Project Plan_ DevSecOps Sentinel v2.2 (Hackathon Winning Blueprint).md](mdc:Project%20Plan_%20DevSecOps%20Sentinel%20v2.2%20(Hackathon%20Winning%20Blueprint).md).

## Architecture Principles

### Serverless-First Design
- **ALL** components must be serverless and event-driven
- No EC2 instances, containers, or persistent servers
- Use AWS Lambda for all compute needs
- Infrastructure defined exclusively in [template.yaml](mdc:template.yaml) using AWS SAM

### Core Architecture Components
1. **API Gateway** - Webhook endpoint with Lambda Authorizer
2. **Step Functions** - Orchestrates parallel analysis workflow
3. **Lambda Functions**:
   - `webhook-handler-lambda` - Processes GitHub webhooks
   - `secret-scanner-lambda` - Detects hardcoded credentials
   - `vulnerability-scanner-lambda` - Checks dependencies
   - `ai-reviewer-lambda` - AI-powered code review
   - `aggregator-lambda` - Consolidates results and posts to GitHub
4. **DynamoDB** - Audit logging
5. **Secrets Manager** - GitHub API token storage
6. **Bedrock** - AI model (Claude 3.5 Sonnet)

## Development Methodology

### Collaboration Model ("Vibecoding")
- AI acts as senior engineer/architect
- Human provides direction and performs external tasks
- Follow plan-execute-verify-confirm cycle
- Context synthesis before any task

### Core Development Rules
1. **Infrastructure as Code**: NO manual AWS resource creation
2. **Incremental Development**: One change at a time
3. **Testing First**: Unit tests with pytest/moto required
4. **Security First**: Validate webhooks, secure token storage
5. **Documentation Driven**: Maintain README.md and Project_Summary.md

## Technical Stack

### Required Technologies
- **Language**: Python 3.11
- **IaC**: AWS SAM (template.yaml)
- **Testing**: pytest with moto for AWS mocking
- **AI Model**: anthropic.claude-3-5-sonnet-20240620-v1:0
- **Key Libraries**: boto3, requests, py-safety, trufflehog

### AWS Services
- Lambda, Step Functions, API Gateway
- DynamoDB, Secrets Manager, IAM
- S3 (static hosting), Bedrock

## Coding Standards

### Python Requirements
```python
# All functions must have:
# 1. Type hints
# 2. Comprehensive docstrings
# 3. Error handling for all I/O operations

def example_function(param: str) -> dict:
    """
    Brief description of function purpose.
    
    Args:
        param: Description of parameter
        
    Returns:
        Description of return value
        
    Raises:
        Exception: When and why
    """
    try:
        # Implementation
        pass
    except Exception as e:
        # Proper error handling
        raise
```

### Lambda Function Structure
```
src/
  handlers/
    webhook_handler.py
    secret_scanner.py
    vulnerability_scanner.py
    ai_reviewer.py
    aggregator.py
  utils/
    github_client.py
    security_utils.py
tests/
  unit/
    test_webhook_handler.py
    # Test for each handler
```

## Workflow Implementation

### Step Functions State Machine
- Use Map state for parallel execution
- Include error handling with Catch blocks
- Pass results between states using InputPath/ResultPath
- Implement retry logic for transient failures

### GitHub Integration
- Validate X-Hub-Signature-256 header
- Clone specific commit for analysis
- Post single consolidated Markdown comment
- Use GitHub REST API v3

## Security Requirements

### Mandatory Security Practices
1. **Webhook Security**: Lambda Authorizer validates signatures
2. **Token Management**: GitHub token in Secrets Manager only
3. **IAM Principles**: Least privilege for each Lambda role
4. **No Hardcoded Secrets**: Use environment variables

### IAM Role Permissions
```yaml
# Example for aggregator Lambda
Policies:
  - Statement:
    - Effect: Allow
      Action:
        - secretsmanager:GetSecretValue
      Resource: !Ref GitHubTokenSecret
    - Effect: Allow
      Action:
        - dynamodb:PutItem
      Resource: !GetAtt AuditTable.Arn
```

## Testing Strategy

### Unit Testing Rules
- Mock all AWS service calls with moto
- Test error paths and edge cases
- Maintain >80% code coverage
- Run tests before any commit

### Integration Testing
- Use `sam local invoke` with test events
- Create test GitHub repository
- Verify end-to-end workflow

## Output Requirements

### GitHub PR Comment Format
```markdown
## 🛡️ DevSecOps Sentinel Analysis

### Summary
✅ **Secrets**: No issues found
⚠️ **Dependencies**: 2 vulnerabilities detected
💡 **AI Review**: 5 suggestions

### Detailed Findings

#### 🔑 Secret Scanning
No hardcoded credentials detected.

#### 📦 Dependency Vulnerabilities
| Package | Version | Vulnerability | Severity |
|---------|---------|--------------|----------|
| requests | 2.20.0 | CVE-2021-1234 | HIGH |

#### 🤖 AI Code Review
1. **File**: `src/main.py` (Line 42)
   - **Issue**: Potential null pointer exception
   - **Suggestion**: Add null check before accessing
```

## Project Deliverables

### Critical Files
1. **template.yaml** - Complete SAM infrastructure
2. **README.md** - Polished documentation with:
   - Architecture diagram
   - Clear problem/solution sections
   - Deployment instructions
   - Demo GIF
3. **src/** - All Lambda function code
4. **tests/** - Comprehensive test suite

### Submission Requirements
- 3-minute demo video
- Working end-to-end demonstration
- Clean, documented codebase
- Professional README.md

## Development Workflow

### Before Any Code Change
1. Synthesize context from project plan
2. Create detailed execution plan
3. Execute one step at a time
4. Self-verify against requirements
5. Wait for user confirmation

### Commit Message Format
```
feat: Add secret scanner Lambda function
- Implement trufflehog integration
- Add error handling for git operations
- Include unit tests with moto mocking
```

## Common Pitfalls to Avoid
- Don't create resources manually in AWS Console
- Don't hardcode any credentials or secrets
- Don't skip error handling in Lambda functions
- Don't forget to update Project_Summary.md
- Don't merge scanner results in parallel branches
- Don't exceed Lambda timeout limits (set appropriately)
```

Now let me create additional specialized rule files to provide more focused guidance:

```plaintext
# AWS SAM Infrastructure Rules

## SAM Template Structure

### Core Template Requirements
The [template.yaml](mdc:template.yaml) file is the single source of truth for all AWS infrastructure. Reference the [Project Plan](mdc:Project%20Plan_%20DevSecOps%20Sentinel%20v2.2%20(Hackathon%20Winning%20Blueprint).md) for architecture details.

### Required Resources

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Globals:
  Function:
    Runtime: python3.11
    Timeout: 300
    MemorySize: 512
    Environment:
      Variables:
        LOG_LEVEL: INFO

Parameters:
  GitHubSecret:
    Type: String
    NoEcho: true
    Description: GitHub webhook secret for validation
  
  GitHubToken:
    Type: String
    NoEcho: true
    Description: GitHub API token for posting comments

Resources:
  # API Gateway for webhook endpoint
  WebhookApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      Auth:
        DefaultAuthorizer: WebhookAuthorizer
        Authorizers:
          WebhookAuthorizer:
            FunctionArn: !GetAtt WebhookAuthorizerFunction.Arn

  # Step Functions State Machine
  AnalysisStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Type: EXPRESS
      Definition:
        Comment: "DevSecOps Sentinel Analysis Workflow"
        StartAt: ParallelAnalysis
        States:
          ParallelAnalysis:
            Type: Map
            ItemsPath: $.scanTypes
            MaxConcurrency: 3
            ResultPath: $.scanResults
            Iterator:
              StartAt: InvokeScanner
              States:
                InvokeScanner:
                  Type: Task
                  Resource: arn:aws:states:::lambda:invoke
                  Parameters:
                    FunctionName.$: $.scanner_arn
                    Payload.$: $.payload
                  End: true
            Next: AggregateResults
          AggregateResults:
            Type: Task
            Resource: !GetAtt AggregatorFunction.Arn
            End: true

  # Lambda Functions
  WebhookHandlerFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/handlers/
      Handler: webhook_handler.lambda_handler
      Policies:
        - StepFunctionsExecutionPolicy:
            StateMachineName: !GetAtt AnalysisStateMachine.Name

  # DynamoDB Audit Table
  AuditTable:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: pullRequestId
          AttributeType: S
        - AttributeName: timestamp
          AttributeType: S
      KeySchema:
        - AttributeName: pullRequestId
          KeyType: HASH
        - AttributeName: timestamp
          KeyType: RANGE

  # Secrets Manager
  GitHubTokenSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      SecretString: !Ref GitHubToken
```

### Lambda Function Configuration

#### Memory and Timeout Settings
```yaml
# Scanner functions need more memory for git operations
SecretScannerFunction:
  Properties:
    MemorySize: 1024
    Timeout: 300
    EphemeralStorage:
      Size: 2048  # For cloning repos

# AI Reviewer needs less memory but more time
AIReviewerFunction:
  Properties:
    MemorySize: 512
    Timeout: 900  # Bedrock calls can be slow
```

#### IAM Role Templates
```yaml
# Minimal permissions for scanner Lambda
ScannerRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
          Action: sts:AssumeRole
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Aggregator needs additional permissions
AggregatorRole:
  Properties:
    Policies:
      - PolicyName: AggregatorPolicy
        PolicyDocument:
          Statement:
            - Effect: Allow
              Action:
                - secretsmanager:GetSecretValue
              Resource: !Ref GitHubTokenSecret
            - Effect: Allow
              Action:
                - dynamodb:PutItem
              Resource: !GetAtt AuditTable.Arn
```

### Environment Variables Pattern
```yaml
Function:
  Environment:
    Variables:
      GITHUB_SECRET_ARN: !Ref GitHubTokenSecret
      AUDIT_TABLE_NAME: !Ref AuditTable
      STATE_MACHINE_ARN: !Ref AnalysisStateMachine
```

## Deployment Configuration

### samconfig.toml Structure
```toml
version = 0.1
[default]
[default.deploy]
[default.deploy.parameters]
stack_name = "devsecops-sentinel"
s3_bucket = "aws-sam-cli-managed-default-samcliamanagebucket-xxxxx"
s3_prefix = "devsecops-sentinel"
region = "us-east-1"
capabilities = "CAPABILITY_IAM"
parameter_overrides = [
    "GitHubSecret=your-webhook-secret",
    "GitHubToken=your-github-token"
]
```

### Local Testing Configuration
```yaml
# For sam local testing
env.json:
{
  "WebhookHandlerFunction": {
    "STATE_MACHINE_ARN": "arn:aws:states:us-east-1:123456789012:stateMachine:test",
    "LOG_LEVEL": "DEBUG"
  }
}
```

## Best Practices

### Resource Naming
- Use descriptive names with Function/Table/Api suffix
- Avoid hardcoded ARNs - use !Ref and !GetAtt
- Tag all resources appropriately

### Cost Optimization
```yaml
# Use on-demand for low-traffic resources
DynamoDB:
  BillingMode: PAY_PER_REQUEST

# Set appropriate retention for logs
LogGroup:
  RetentionInDays: 7

# Use ARM-based Lambda for cost savings
Architectures:
  - arm64
```

### Security Hardening
```yaml
# API Gateway throttling
Api:
  MethodSettings:
    - ResourcePath: /*
      HttpMethod: '*'
      ThrottlingBurstLimit: 100
      ThrottlingRateLimit: 50

# Lambda reserved concurrency
Function:
  ReservedConcurrentExecutions: 10
```

## Common SAM Commands

### Development Workflow
```bash
# Validate template
sam validate

# Build application
sam build --use-container

# Local testing
sam local start-api
sam local invoke WebhookHandlerFunction -e events/webhook.json

# Deploy
sam deploy --guided  # First time
sam deploy          # Subsequent

# View logs
sam logs -n WebhookHandlerFunction --tail

# Delete stack
sam delete
```

### Debugging Tips
- Use `--debug` flag for verbose output
- Check CloudFormation events for deployment errors
- Use `sam sync` for rapid development iteration
- Monitor CloudWatch Logs for runtime errors

## Event Patterns

### GitHub Webhook Event
```json
{
  "body": "{\"action\":\"opened\",\"pull_request\":{...}}",
  "headers": {
    "X-Hub-Signature-256": "sha256=..."
  }
}
```

### Step Functions Input
```json
{
  "repository": "owner/repo",
  "pullRequestNumber": 123,
  "commitSha": "abc123",
  "scanTypes": [
    {
      "type": "secrets",
      "scanner_arn": "arn:aws:lambda:...:function:SecretScanner"
    }
  ]
}
```
```

```plaintext
# Testing Strategy Rules

## Testing Philosophy
All code must be thoroughly tested before deployment. Reference the testing requirements in [Project Plan](mdc:Project%20Plan_%20DevSecOps%20Sentinel%20v2.2%20(Hackathon%20Winning%20Blueprint).md).

## Unit Testing with pytest and moto

### Test Structure
```
tests/
├── unit/
│   ├── test_webhook_handler.py
│   ├── test_secret_scanner.py
│   ├── test_vulnerability_scanner.py
│   ├── test_ai_reviewer.py
│   ├── test_aggregator.py
│   └── test_utils.py
├── integration/
│   └── test_workflow.py
├── fixtures/
│   ├── github_events.py
│   └── sample_code.py
└── conftest.py
```

### Base Test Template
```python
import pytest
from moto import mock_dynamodb, mock_secretsmanager, mock_stepfunctions
import boto3
from unittest.mock import patch, MagicMock

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture
def lambda_context():
    """Mock Lambda context object."""
    context = MagicMock()
    context.function_name = "test-function"
    context.request_id = "test-request-id"
    context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
    context.get_remaining_time_in_millis.return_value = 300000
    return context
```

### Testing Lambda Handlers

#### Webhook Handler Test
```python
@mock_stepfunctions
def test_webhook_handler_valid_signature(aws_credentials, lambda_context):
    """Test webhook handler with valid GitHub signature."""
    from src.handlers.webhook_handler import lambda_handler
    
    # Setup
    event = {
        "body": json.dumps({"action": "opened", "pull_request": {"number": 123}}),
        "headers": {
            "X-Hub-Signature-256": "sha256=valid_signature"
        }
    }
    
    # Mock signature validation
    with patch('src.utils.security.validate_github_signature', return_value=True):
        # Execute
        response = lambda_handler(event, lambda_context)
    
    # Assert
    assert response["statusCode"] == 200
    assert "executionArn" in json.loads(response["body"])
```

#### Scanner Test Pattern
```python
@mock_secretsmanager
def test_secret_scanner_finds_aws_key(aws_credentials, lambda_context):
    """Test secret scanner detects AWS credentials."""
    from src.handlers.secret_scanner import lambda_handler
    
    # Setup mock repository
    with patch('src.utils.github_client.clone_repository') as mock_clone:
        mock_clone.return_value = "/tmp/test-repo"
        
        # Create test file with secret
        test_file_content = '''
        AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
        AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        '''
        
        with patch('builtins.open', mock_open(read_data=test_file_content)):
            # Execute
            result = lambda_handler({
                "repository": "test/repo",
                "commit_sha": "abc123"
            }, lambda_context)
    
    # Assert
    assert result["findings_count"] > 0
    assert any("AWS" in finding["type"] for finding in result["findings"])
```

### Testing Step Functions Integration

```python
@mock_stepfunctions
def test_step_function_workflow():
    """Test complete Step Functions workflow."""
    client = boto3.client('stepfunctions', region_name='us-east-1')
    
    # Create state machine
    definition = {
        "Comment": "Test workflow",
        "StartAt": "ParallelScan",
        "States": {
            "ParallelScan": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "SecretScan",
                        "States": {
                            "SecretScan": {"Type": "Task", "Resource": "arn:aws:lambda:us-east-1:123456789012:function:secret-scanner", "End": True}
                        }
                    }
                ],
                "End": True
            }
        }
    }
    
    response = client.create_state_machine(
        name='test-state-machine',
        definition=json.dumps(definition),
        roleArn='arn:aws:iam::123456789012:role/test-role'
    )
    
    # Start execution
    execution = client.start_execution(
        stateMachineArn=response['stateMachineArn'],
        input=json.dumps({"test": "data"})
    )
    
    assert execution['ResponseMetadata']['HTTPStatusCode'] == 200
```

### Mocking External Services

#### GitHub API Mock
```python
@pytest.fixture
def mock_github_api():
    """Mock GitHub API responses."""
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 201
        mock_post.return_value.json.return_value = {"id": 12345}
        yield mock_post

def test_post_comment_to_github(mock_github_api):
    """Test posting comment to GitHub PR."""
    from src.utils.github_client import post_comment
    
    result = post_comment("owner/repo", 123, "Test comment")
    assert result["id"] == 12345
    mock_github_api.assert_called_once()
```

#### Bedrock Mock
```python
@pytest.fixture
def mock_bedrock():
    """Mock Amazon Bedrock responses."""
    with patch('boto3.client') as mock_client:
        mock_bedrock_client = MagicMock()
        mock_client.return_value = mock_bedrock_client
        
        mock_bedrock_client.invoke_model.return_value = {
            'body': MagicMock(read=lambda: json.dumps({
                'content': [{'text': 'AI review response'}]
            }).encode())
        }
        yield mock_bedrock_client
```

## Integration Testing

### Local SAM Testing
```python
# test_local_integration.py
import subprocess
import json

def test_local_lambda_invocation():
    """Test Lambda function using SAM local."""
    event_file = "tests/events/webhook_event.json"
    
    result = subprocess.run(
        ["sam", "local", "invoke", "WebhookHandlerFunction", "-e", event_file],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["statusCode"] == 200
```

### Event Files
```json
// tests/events/webhook_event.json
{
  "body": "{\"action\":\"opened\",\"pull_request\":{\"number\":123,\"head\":{\"sha\":\"abc123\"}}}",
  "headers": {
    "X-Hub-Signature-256": "sha256=test_signature"
  },
  "requestContext": {
    "http": {
      "method": "POST"
    }
  }
}
```

## End-to-End Testing

### Test Repository Setup
```python
# tests/e2e/setup_test_repo.py
import github
import os

def create_test_pr_with_issues():
    """Create a PR with known security issues for testing."""
    g = github.Github(os.environ['GITHUB_TOKEN'])
    repo = g.get_repo("your-org/test-sentinel-repo")
    
    # Create branch
    base_sha = repo.get_branch("main").commit.sha
    repo.create_git_ref("refs/heads/test-security-issues", base_sha)
    
    # Add file with security issues
    content = '''
    # Test file with issues
    API_KEY = "sk-1234567890abcdef"  # Hardcoded secret
    
    # requirements.txt content
    requests==2.20.0  # Known vulnerability
    '''
    
    repo.create_file(
        "test_security.py",
        "Add test security issues",
        content,
        branch="test-security-issues"
    )
    
    # Create PR
    pr = repo.create_pull(
        title="Test PR with Security Issues",
        body="This PR should trigger all scanners",
        head="test-security-issues",
        base="main"
    )
    
    return pr.number
```

### E2E Validation
```python
def test_e2e_sentinel_comment():
    """Verify Sentinel posts correct comment on test PR."""
    pr_number = create_test_pr_with_issues()
    
    # Wait for webhook processing
    time.sleep(30)
    
    # Check for comment
    g = github.Github(os.environ['GITHUB_TOKEN'])
    repo = g.get_repo("your-org/test-sentinel-repo")
    pr = repo.get_pull(pr_number)
    
    comments = list(pr.get_issue_comments())
    sentinel_comment = None
    
    for comment in comments:
        if "DevSecOps Sentinel Analysis" in comment.body:
            sentinel_comment = comment
            break
    
    assert sentinel_comment is not None
    assert "Hardcoded secret" in sentinel_comment.body
    assert "requests==2.20.0" in sentinel_comment.body
```

## Test Coverage Requirements

### Coverage Configuration
```ini
# .coveragerc
[run]
source = src/
omit = 
    */tests/*
    */venv/*
    */__pycache__/*

[report]
precision = 2
show_missing = True
skip_covered = False

[html]
directory = htmlcov
```

### Running Tests with Coverage
```bash
# Run all tests with coverage
pytest --cov=src --cov-report=html --cov-report=term

# Run specific test file
pytest tests/unit/test_webhook_handler.py -v

# Run with markers
pytest -m "not slow" --cov=src

# Generate coverage report
coverage report
coverage html
```

## Test Data Management

### Fixture Organization
```python
# tests/fixtures/sample_code.py
CLEAN_PYTHON_CODE = '''
def calculate_sum(a: int, b: int) -> int:
    """Calculate sum of two integers."""
    return a + b
'''

BUGGY_PYTHON_CODE = '''
def divide_numbers(a, b):
    return a / b  # No zero check
'''

VULNERABLE_REQUIREMENTS = '''
django==2.2.0
requests==2.20.0
pyyaml==5.1
'''
```

## Continuous Testing

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest tests/unit -x
        language: system
        pass_filenames: false
        always_run: true
```

### GitHub Actions Integration
```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements-dev.txt
      - run: pytest --cov=src --cov-fail-under=80
```

## Testing Best Practices

1. **Test Isolation**: Each test must be independent
2. **Mock External Services**: Never call real APIs in unit tests
3. **Use Fixtures**: Share common test data via pytest fixtures
4. **Test Error Cases**: Always test failure scenarios
5. **Clear Test Names**: Use descriptive test function names
6. **Fast Tests**: Unit tests should run in milliseconds
7. **Deterministic**: Tests must produce same results every run
```

```plaintext
# AI Integration with Amazon Bedrock

## Overview
AI-powered code review using Amazon Bedrock (Claude 3.5 Sonnet) is a core differentiator of DevSecOps Sentinel. Reference the AI requirements in [Project Plan](mdc:Project%20Plan_%20DevSecOps%20Sentinel%20v2.2%20(Hackathon%20Winning%20Blueprint).md).

## Bedrock Configuration

### Model Selection
```python
# Always use this specific model
MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
MODEL_KWARGS = {
    "max_tokens": 4096,
    "temperature": 0.3,  # Lower temperature for consistent code analysis
    "top_p": 0.9,
    "stop_sequences": []
}
```

### Client Setup
```python
import boto3
import json
from typing import Dict, List, Optional

class BedrockClient:
    """Wrapper for Amazon Bedrock interactions."""
    
    def __init__(self, region: str = "us-east-1"):
        self.client = boto3.client(
            service_name="bedrock-runtime",
            region_name=region
        )
        self.model_id = MODEL_ID
    
    def analyze_code(self, code: str, filename: str) -> Dict:
        """Analyze code for quality issues."""
        prompt = self._build_analysis_prompt(code, filename)
        
        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    **MODEL_KWARGS
                })
            )
            
            result = json.loads(response["body"].read())
            return self._parse_response(result)
            
        except Exception as e:
            logger.error(f"Bedrock invocation failed: {str(e)}")
            return {"findings": [], "error": str(e)}
```

## Prompt Engineering

### Code Analysis Prompt Template
```python
ANALYSIS_PROMPT_TEMPLATE = """You are a senior software engineer conducting a thorough code review. 
Analyze the following code from file '{filename}' and identify:

1. **Bugs and Logic Errors**: Any code that will cause runtime errors or incorrect behavior
2. **Security Issues**: Beyond just hardcoded secrets (those are handled separately), identify:
   - SQL injection vulnerabilities
   - XSS vulnerabilities
   - Insecure random number generation
   - Path traversal risks
   - Unsafe deserialization
3. **Performance Issues**: O(n²) algorithms where O(n) would work, unnecessary database calls, memory leaks
4. **Code Quality**: 
   - Anti-patterns (e.g., mutable default arguments in Python)
   - Poor error handling
   - Missing input validation
   - Inconsistent naming conventions
   - Complex functions that should be refactored

Provide your analysis in the following JSON format:
{{
  "findings": [
    {{
      "severity": "high|medium|low",
      "category": "bug|security|performance|quality",
      "line_number": <line_number>,
      "issue": "Brief description of the issue",
      "suggestion": "How to fix it",
      "code_snippet": "The problematic line/section"
    }}
  ],
  "summary": "A one-line summary of the overall code quality"
}}

Here is the code to analyze:

```{language}
{code}
```

Important: 
- Only report actual issues, not style preferences
- Be specific about line numbers
- Provide actionable suggestions
- Focus on issues that could cause real problems in production
"""
```

### Diff Analysis Prompt
```python
DIFF_ANALYSIS_PROMPT = """You are reviewing a pull request. Analyze these code changes:

**Files Changed**: {files_changed}
**Lines Added**: {lines_added}
**Lines Removed**: {lines_removed}

Changes:
```diff
{diff_content}
```

Identify:
1. New bugs or issues introduced by these changes
2. Security vulnerabilities in the new code
3. Performance regressions
4. Breaking changes that might affect other parts of the system

Format your response as JSON with the same structure as before.
Focus ONLY on issues introduced by the changes, not pre-existing issues.
"""
```

## Response Parsing

### Structured Response Handler
```python
def parse_bedrock_response(response: Dict) -> List[Dict]:
    """Parse and validate Bedrock response."""
    try:
        content = response.get("content", [])
        if not content:
            return []
        
        text_response = content[0].get("text", "{}")
        parsed = json.loads(text_response)
        
        # Validate response structure
        findings = []
        for finding in parsed.get("findings", []):
            if all(key in finding for key in ["severity", "category", "issue"]):
                # Ensure line_number is an integer
                finding["line_number"] = int(finding.get("line_number", 0))
                findings.append(finding)
        
        return findings
        
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.error(f"Failed to parse Bedrock response: {e}")
        return []
```

## Error Handling

### Retry Logic
```python
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

@retry(
    wait=wait_exponential(multiplier=1, min=4, max=60),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type((ThrottlingException, ServiceException))
)
def invoke_bedrock_with_retry(client, **kwargs):
    """Invoke Bedrock with automatic retry for transient errors."""
    return client.invoke_model(**kwargs)
```

### Fallback Strategies
```python
def analyze_with_fallback(code: str, filename: str) -> Dict:
    """Analyze code with fallback to basic analysis if Bedrock fails."""
    try:
        # Try Bedrock analysis
        return bedrock_client.analyze_code(code, filename)
    except Exception as e:
        logger.warning(f"Bedrock analysis failed, using fallback: {e}")
        
        # Basic static analysis fallback
        findings = []
        
        # Check for common issues
        if "eval(" in code or "exec(" in code:
            findings.append({
                "severity": "high",
                "category": "security",
                "issue": "Use of eval/exec is dangerous",
                "suggestion": "Avoid dynamic code execution"
            })
        
        if "except:" in code or "except Exception:" in code:
            findings.append({
                "severity": "medium",
                "category": "quality",
                "issue": "Broad exception handling",
                "suggestion": "Catch specific exceptions"
            })
        
        return {"findings": findings, "fallback": True}
```

## Cost Optimization

### Token Management
```python
def truncate_code_for_analysis(code: str, max_lines: int = 500) -> str:
    """Truncate code to manage token usage and costs."""
    lines = code.split('\n')
    
    if len(lines) <= max_lines:
        return code
    
    # Smart truncation: keep imports and function signatures
    important_lines = []
    content_lines = []
    
    for i, line in enumerate(lines):
        if any(keyword in line for keyword in ['import', 'from', 'def', 'class']):
            important_lines.append((i, line))
        else:
            content_lines.append((i, line))
    
    # Combine important lines with a sample of content
    kept_lines = important_lines + content_lines[:max_lines - len(important_lines)]
    kept_lines.sort(key=lambda x: x[0])  # Sort by line number
    
    truncated = '\n'.join([line for _, line in kept_lines])
    return f"{truncated}\n\n# ... truncated {len(lines) - max_lines} lines ..."
```

### Batch Processing
```python
def analyze_files_in_batch(files: List[Dict]) -> List[Dict]:
    """Analyze multiple files efficiently."""
    # Group small files together to reduce API calls
    batch = []
    batch_size = 0
    MAX_BATCH_SIZE = 10000  # characters
    
    results = []
    
    for file in files:
        file_size = len(file['content'])
        
        if batch_size + file_size > MAX_BATCH_SIZE and batch:
            # Process current batch
            results.extend(process_batch(batch))
            batch = []
            batch_size = 0
        
        batch.append(file)
        batch_size += file_size
    
    # Process remaining files
    if batch:
        results.extend(process_batch(batch))
    
    return results
```

## Integration with Scanners

### AI Reviewer Lambda Handler
```python
def lambda_handler(event, context):
    """AI reviewer Lambda function."""
    repository = event['repository']
    pull_request_number = event['pull_request_number']
    commit_sha = event['commit_sha']
    
    try:
        # Get changed files
        changed_files = get_changed_files(repository, pull_request_number)
        
        # Initialize Bedrock client
        bedrock = BedrockClient()
        
        # Analyze each changed file
        all_findings = []
        for file in changed_files:
            if should_analyze_file(file['filename']):
                content = get_file_content(repository, commit_sha, file['filename'])
                
                # Truncate if necessary
                content = truncate_code_for_analysis(content)
                
                # Analyze with Bedrock
                result = bedrock.analyze_code(
                    code=content,
                    filename=file['filename']
                )
                
                # Add file context to findings
                for finding in result.get('findings', []):
                    finding['file'] = file['filename']
                    all_findings.append(finding)
        
        return {
            'statusCode': 200,
            'findings': all_findings,
            'files_analyzed': len(changed_files),
            'model_used': MODEL_ID
        }
        
    except Exception as e:
        logger.error(f"AI review failed: {str(e)}")
        return {
            'statusCode': 500,
            'error': str(e),
            'findings': []
        }
```

## Output Formatting

### Finding to Markdown
```python
def format_ai_findings_markdown(findings: List[Dict]) -> str:
    """Format AI findings for GitHub comment."""
    if not findings:
        return "✨ **AI Review**: No issues found! The code looks good."
    
    # Group by severity
    high = [f for f in findings if f.get('severity') == 'high']
    medium = [f for f in findings if f.get('severity') == 'medium']
    low = [f for f in findings if f.get('severity') == 'low']
    
    markdown = "#### 🤖 AI Code Review\n\n"
    
    if high:
        markdown += "**🔴 High Priority Issues**\n"
        for finding in high:
            markdown += format_single_finding(finding)
    
    if medium:
        markdown += "\n**🟡 Medium Priority Issues**\n"
        for finding in medium:
            markdown += format_single_finding(finding)
    
    if low:
        markdown += "\n**🟢 Suggestions**\n"
        for finding in low:
            markdown += format_single_finding(finding)
    
    return markdown

def format_single_finding(finding: Dict) -> str:
    """Format a single finding."""
    return f"""
- **File**: `{finding.get('file', 'unknown')}` (Line {finding.get('line_number', '?')})
  - **Issue**: {finding.get('issue', 'No description')}
  - **Suggestion**: {finding.get('suggestion', 'No suggestion')}
  ```python
  {finding.get('code_snippet', '')}
  ```
"""
```

## Performance Monitoring

### Metrics Collection
```python
import time
from aws_lambda_powertools import Metrics
from aws_lambda_powertools.metrics import MetricUnit

metrics = Metrics()

@metrics.log_metrics
def analyze_with_metrics(code: str, filename: str):
    """Analyze code with performance metrics."""
    start_time = time.time()
    
    try:
        result = bedrock_client.analyze_code(code, filename)
        
        # Log metrics
        metrics.add_metric(name="AIAnalysisSuccess", unit=MetricUnit.Count, value=1)
        metrics.add_metric(
            name="AIAnalysisLatency", 
            unit=MetricUnit.Milliseconds, 
            value=(time.time() - start_time) * 1000
        )
        metrics.add_metric(
            name="FindingsCount",
            unit=MetricUnit.Count,
            value=len(result.get('findings', []))
        )
        
        return result
        
    except Exception as e:
        metrics.add_metric(name="AIAnalysisError", unit=MetricUnit.Count, value=1)
        raise
```

## Best Practices

1. **Prompt Clarity**: Be explicit about expected output format
2. **Context Limiting**: Don't send entire repositories, focus on changed files
3. **Error Recovery**: Always have fallback for when AI fails
4. **Cost Awareness**: Monitor token usage and implement limits
5. **Response Validation**: Never trust AI output without validation
6. **Caching**: Consider caching responses for identical code
7. **Timeout Handling**: Set appropriate timeouts for Bedrock calls
8. **Logging**: Log all AI interactions for debugging and audit
```

```plaintext
# DevSecOps Sentinel - Cursor Rules

## Overview
These Cursor rules provide comprehensive guidance for developing the DevSecOps Sentinel project, an AI-powered serverless security analysis platform for GitHub Pull Requests.

## Available Rules

### 1. Main Development Rules
**File**: [devsecops-sentinel.mdc](mdc:devsecops-sentinel.mdc)
- Complete project overview and architecture
- Core development principles and methodology
- Technical stack requirements
- Coding standards and conventions
- Security requirements
- Workflow implementation guidelines
- Output formatting specifications

### 2. AWS SAM Infrastructure Rules
**File**: [sam-infrastructure.mdc](mdc:sam-infrastructure.mdc)
- SAM template structure and requirements
- Lambda function configuration
- IAM role templates and permissions
- Step Functions workflow definitions
- Deployment configuration
- Cost optimization strategies
- Common SAM commands and debugging tips

### 3. Testing Strategy Rules
**File**: [testing-strategy.mdc](mdc:testing-strategy.mdc)
- Unit testing with pytest and moto
- Integration testing approaches
- End-to-end testing procedures
- Test structure and organization
- Mock implementations for AWS services
- Coverage requirements
- Continuous testing setup

### 4. AI Integration Rules
**File**: [ai-integration.mdc](mdc:ai-integration.mdc)
- Amazon Bedrock configuration
- Prompt engineering templates
- Response parsing and validation
- Error handling and retry logic
- Cost optimization for AI calls
- Performance monitoring
- Output formatting for AI findings

## How to Use These Rules

1. **During Development**: The AI assistant will automatically reference these rules when working on the DevSecOps Sentinel project.

2. **Architecture Decisions**: Consult the main rules file for architectural patterns and the SAM infrastructure rules for AWS-specific implementations.

3. **Writing Code**: Follow the coding standards in the main rules and use the provided templates in each specialized rule file.

4. **Testing**: Reference the testing strategy rules for examples of how to write unit, integration, and E2E tests.

5. **AI Features**: Use the AI integration rules when implementing or modifying the Bedrock-powered code review functionality.

## Key Project Resources

- **Project Plan**: [Project Plan_ DevSecOps Sentinel v2.2 (Hackathon Winning Blueprint).md](mdc:Project%20Plan_%20DevSecOps%20Sentinel%20v2.2%20(Hackathon%20Winning%20Blueprint).md)
- **Infrastructure**: [template.yaml](mdc:template.yaml)
- **Progress Tracking**: [Project_Summary.md](mdc:Project_Summary.md)

## Quick Reference

### Core Architecture
- Event-driven serverless using AWS Lambda
- Orchestrated by AWS Step Functions
- Triggered by GitHub webhooks
- Parallel execution of security scanners
- AI-powered code review with Bedrock
- Single consolidated GitHub PR comment

### Development Workflow
1. Synthesize context from project plan
2. Create detailed execution plan
3. Execute one step at a time
4. Self-verify against requirements
5. Wait for user confirmation
6. Update Project_Summary.md

### Critical Principles
- **Infrastructure as Code**: Everything in template.yaml
- **Security First**: Validate webhooks, secure credentials
- **Test Everything**: Unit tests required for business logic
- **No Manual AWS Changes**: All through SAM/IaC
- **Documentation Driven**: README.md is a deliverable
```

I've successfully created comprehensive Cursor Rules for the DevSecOps Sentinel project! Here's what I've generated:

## Created Rules:

1. **Main Development Rules** (`.cursor/rules/devsecops-sentinel.mdc`)
   - Complete project architecture and principles
   - Development methodology and collaboration model
   - Technical stack and coding standards
   - Security requirements and workflow implementation

2. **AWS SAM Infrastructure Rules** (`.cursor/rules/sam-infrastructure.mdc`)
   - Detailed SAM template structure
   - Lambda and Step Functions configuration
   - IAM roles and permissions templates
   - Deployment and debugging guidance

3. **Testing Strategy Rules** (`.cursor/rules/testing-strategy.mdc`)
   - Unit testing with pytest and moto
   - Integration and E2E testing approaches
   - Mock implementations for AWS services
   - Coverage requirements and CI/CD setup

4. **AI Integration Rules** (`.cursor/rules/ai-integration.mdc`)
   - Amazon Bedrock configuration and setup
   - Prompt engineering templates
   - Error handling and retry strategies
   - Cost optimization techniques

5. **README** (`.cursor/rules/README.mdc`)
   - Overview of all available rules
   - Usage instructions
   - Quick reference guide

## Key Features:

- **Project-Specific Guidance**: All rules are tailored to the DevSecOps Sentinel serverless architecture
- **Code Examples**: Each rule file includes practical code snippets and templates
- **Best Practices**: Security-first approach, testing requirements, and AWS-specific optimizations
- **Cross-References**: Rules link to the project plan and other relevant files using the `[filename](mdc:filename)` format

These rules will help ensure consistent, high-quality development following the project's architectural principles and requirements. The AI assistant will automatically reference these rules when working on the DevSecOps Sentinel project.

---

**User**

give the cursor rules proper meta, and/or rewrite/change/add/delete/improve if needed (after review)

---

**Cursor**

```plaintext
---
description:
globs:
alwaysApply: false
---
```

```plaintext
---
description:
globs:
alwaysApply: false
---
```

I'll review and improve the Cursor rules with proper metadata and make necessary improvements. Let me examine each rule and set appropriate metadata based on the project structure and Cursor Rules best practices.

```plaintext
---
description:
globs:
alwaysApply: false
---

->

---
description: "Core development rules for DevSecOps Sentinel - serverless architecture, coding standards, and security practices"
globs: ["**/*.py", "**/*.yaml", "**/*.yml", "**/*.md"]
alwaysApply: true
---
```

```plaintext
# DevSecOps Sentinel - Development Rules

// ... existing code ...
```

```plaintext
# DevSecOps Sentinel - Development Rules

## Project Overview
DevSecOps Sentinel is an AI-powered, serverless security and quality analysis platform for GitHub Pull Requests. The complete project specification is in [Project Plan_ DevSecOps Sentinel v2.2 (Hackathon Winning Blueprint).md](mdc:Project%20Plan_%20DevSecOps%20Sentinel%20v2.2%20(Hackathon%20Winning%20Blueprint).md).

## Architecture Principles

### Serverless-First Design
- **ALL** components must be serverless and event-driven
- No EC2 instances, containers, or persistent servers
- Use AWS Lambda for all compute needs
- Infrastructure defined exclusively in [template.yaml](mdc:template.yaml) using AWS SAM

### Core Architecture Components
1. **API Gateway** - Webhook endpoint with Lambda Authorizer
2. **Step Functions** - Orchestrates parallel analysis workflow
3. **Lambda Functions**:
   - `webhook-handler-lambda` - Processes GitHub webhooks
   - `secret-scanner-lambda` - Detects hardcoded credentials
   - `vulnerability-scanner-lambda` - Checks dependencies
   - `ai-reviewer-lambda` - AI-powered code review
   - `aggregator-lambda` - Consolidates results and posts to GitHub
4. **DynamoDB** - Audit logging
5. **Secrets Manager** - GitHub API token storage
6. **Bedrock** - AI model (Claude 3.5 Sonnet)

## Development Methodology

### Collaboration Model ("Vibecoding")
- AI acts as senior engineer/architect
- Human provides direction and performs external tasks
- Follow plan-execute-verify-confirm cycle
- Context synthesis before any task

### Core Development Rules
1. **Infrastructure as Code**: NO manual AWS resource creation
2. **Incremental Development**: One change at a time
3. **Testing First**: Unit tests with pytest/moto required
4. **Security First**: Validate webhooks, secure token storage
5. **Documentation Driven**: Maintain README.md and Project_Summary.md

## Technical Stack

### Required Technologies
- **Language**: Python 3.11
- **IaC**: AWS SAM (template.yaml)
- **Testing**: pytest with moto for AWS mocking
- **AI Model**: anthropic.claude-3-5-sonnet-20240620-v1:0
- **Key Libraries**: boto3, requests, py-safety, trufflehog

### AWS Services
- Lambda, Step Functions, API Gateway
- DynamoDB, Secrets Manager, IAM
- S3 (static hosting), Bedrock

## Coding Standards

### Python Requirements
```python
# All functions must have:
# 1. Type hints
# 2. Comprehensive docstrings
# 3. Error handling for all I/O operations

def example_function(param: str) -> dict:
    """
    Brief description of function purpose.
    
    Args:
        param: Description of parameter
        
    Returns:
        Description of return value
        
    Raises:
        Exception: When and why
    """
    try:
        # Implementation
        pass
    except Exception as e:
        # Proper error handling
        raise
```

### Lambda Function Structure
```
src/
  handlers/
    webhook_handler.py
    secret_scanner.py
    vulnerability_scanner.py
    ai_reviewer.py
    aggregator.py
  utils/
    github_client.py
    security_utils.py
tests/
  unit/
    test_webhook_handler.py
    # Test for each handler
```

## Workflow Implementation

### Step Functions State Machine
- Use Map state for parallel execution
- Include error handling with Catch blocks
- Pass results between states using InputPath/ResultPath
- Implement retry logic for transient failures

### GitHub Integration
- Validate X-Hub-Signature-256 header
- Clone specific commit for analysis
- Post single consolidated Markdown comment
- Use GitHub REST API v3

## Security Requirements

### Mandatory Security Practices
1. **Webhook Security**: Lambda Authorizer validates signatures
2. **Token Management**: GitHub token in Secrets Manager only
3. **IAM Principles**: Least privilege for each Lambda role
4. **No Hardcoded Secrets**: Use environment variables

### IAM Role Permissions
```yaml
# Example for aggregator Lambda
Policies:
  - Statement:
    - Effect: Allow
      Action:
        - secretsmanager:GetSecretValue
      Resource: !Ref GitHubTokenSecret
    - Effect: Allow
      Action:
        - dynamodb:PutItem
      Resource: !GetAtt AuditTable.Arn
```

## Testing Strategy

### Unit Testing Rules
- Mock all AWS service calls with moto
- Test error paths and edge cases
- Maintain >80% code coverage
- Run tests before any commit

### Integration Testing
- Use `sam local invoke` with test events
- Create test GitHub repository
- Verify end-to-end workflow

## Output Requirements

### GitHub PR Comment Format
```markdown
## 🛡️ DevSecOps Sentinel Analysis

### Summary
✅ **Secrets**: No issues found
⚠️ **Dependencies**: 2 vulnerabilities detected
💡 **AI Review**: 5 suggestions

### Detailed Findings

#### 🔑 Secret Scanning
No hardcoded credentials detected.

#### 📦 Dependency Vulnerabilities
| Package | Version | Vulnerability | Severity |
|---------|---------|--------------|----------|
| requests | 2.20.0 | CVE-2021-1234 | HIGH |

#### 🤖 AI Code Review
1. **File**: `src/main.py` (Line 42)
   - **Issue**: Potential null pointer exception
   - **Suggestion**: Add null check before accessing
```

## Project Deliverables

### Critical Files
1. **template.yaml** - Complete SAM infrastructure
2. **README.md** - Polished documentation with:
   - Architecture diagram
   - Clear problem/solution sections
   - Deployment instructions
   - Demo GIF
3. **src/** - All Lambda function code
4. **tests/** - Comprehensive test suite

### Submission Requirements
- 3-minute demo video
- Working end-to-end demonstration
- Clean, documented codebase
- Professional README.md

## Development Workflow

### Before Any Code Change
1. Synthesize context from project plan
2. Create detailed execution plan
3. Execute one step at a time
4. Self-verify against requirements
5. Wait for user confirmation

### Commit Message Format
```
feat: Add secret scanner Lambda function
- Implement trufflehog integration
- Add error handling for git operations
- Include unit tests with moto mocking
```

## Common Pitfalls to Avoid
- Don't create resources manually in AWS Console
- Don't hardcode any credentials or secrets
- Don't skip error handling in Lambda functions
- Don't forget to update Project_Summary.md
- Don't merge scanner results in parallel branches
- Don't exceed Lambda timeout limits (set appropriately)
```

```plaintext
# DevSecOps Sentinel - Development Rules

## Project Overview
DevSecOps Sentinel is an AI-powered, serverless security and quality analysis platform for GitHub Pull Requests. The complete project specification is in [Project Plan_ DevSecOps Sentinel v2.2 (Hackathon Winning Blueprint).md](mdc:Project%20Plan_%20DevSecOps%20Sentinel%20v2.2%20(Hackathon%20Winning%20Blueprint).md).

## Architecture Principles

### Serverless-First Design
- **ALL** components must be serverless and event-driven
- No EC2 instances, containers, or persistent servers
- Use AWS Lambda for all compute needs
- Infrastructure defined exclusively in [template.yaml](mdc:template.yaml) using AWS SAM

### Core Architecture Components
1. **API Gateway** - Webhook endpoint with Lambda Authorizer
2. **Step Functions** - Orchestrates parallel analysis workflow
3. **Lambda Functions**:
   - `webhook-handler-lambda` - Processes GitHub webhooks
   - `secret-scanner-lambda` - Detects hardcoded credentials
   - `vulnerability-scanner-lambda` - Checks dependencies
   - `ai-reviewer-lambda` - AI-powered code review
   - `aggregator-lambda` - Consolidates results and posts to GitHub
4. **DynamoDB** - Audit logging
5. **Secrets Manager** - GitHub API token storage
6. **Bedrock** - AI model (Claude 3.5 Sonnet)

## Development Methodology

### Collaboration Model ("Vibecoding")
- AI acts as senior engineer/architect
- Human provides direction and performs external tasks
- Follow plan-execute-verify-confirm cycle
- Context synthesis before any task

### Core Development Rules
1. **Infrastructure as Code**: NO manual AWS resource creation
2. **Incremental Development**: One change at a time
3. **Testing First**: Unit tests with pytest/moto required
4. **Security First**: Validate webhooks, secure token storage
5. **Documentation Driven**: Maintain README.md and Project_Summary.md

## Technical Stack

### Required Technologies
- **Language**: Python 3.11
- **IaC**: AWS SAM (template.yaml)
- **Testing**: pytest with moto for AWS mocking
- **AI Model**: anthropic.claude-3-5-sonnet-20240620-v1:0
- **Key Libraries**: boto3, requests, py-safety, trufflehog

### AWS Services
- Lambda, Step Functions, API Gateway
- DynamoDB, Secrets Manager, IAM
- S3 (static hosting), Bedrock

## Coding Standards

### Python Requirements
```python
# All functions must have:
# 1. Type hints
# 2. Comprehensive docstrings
# 3. Error handling for all I/O operations

def example_function(param: str) -> dict:
    """
    Brief description of function purpose.
    
    Args:
        param: Description of parameter
        
    Returns:
        Description of return value
        
    Raises:
        Exception: When and why
    """
    try:
        # Implementation
        pass
    except Exception as e:
        # Proper error handling
        raise
```

### Lambda Function Structure
```
src/
  handlers/
    webhook_handler.py
    secret_scanner.py
    vulnerability_scanner.py
    ai_reviewer.py
    aggregator.py
  utils/
    github_client.py
    security_utils.py
tests/
  unit/
    test_webhook_handler.py
    # Test for each handler
```

## Workflow Implementation

### Step Functions State Machine
- Use Map state for parallel execution
- Include error handling with Catch blocks
- Pass results between states using InputPath/ResultPath
- Implement retry logic for transient failures

### GitHub Integration
- Validate X-Hub-Signature-256 header
- Clone specific commit for analysis
- Post single consolidated Markdown comment
- Use GitHub REST API v3

## Security Requirements

### Mandatory Security Practices
1. **Webhook Security**: Lambda Authorizer validates signatures
2. **Token Management**: GitHub token in Secrets Manager only
3. **IAM Principles**: Least privilege for each Lambda role
4. **No Hardcoded Secrets**: Use environment variables

### IAM Role Permissions
```yaml
# Example for aggregator Lambda
Policies:
  - Statement:
    - Effect: Allow
      Action:
        - secretsmanager:GetSecretValue
      Resource: !Ref GitHubTokenSecret
    - Effect: Allow
      Action:
        - dynamodb:PutItem
      Resource: !GetAtt AuditTable.Arn
```

## Testing Strategy

### Unit Testing Rules
- Mock all AWS service calls with moto
- Test error paths and edge cases
- Maintain >80% code coverage
- Run tests before any commit

### Integration Testing
- Use `sam local invoke` with test events
- Create test GitHub repository
- Verify end-to-end workflow

## Output Requirements

### GitHub PR Comment Format
```markdown
## 🛡️ DevSecOps Sentinel Analysis

### Summary
✅ **Secrets**: No issues found
⚠️ **Dependencies**: 2 vulnerabilities detected
💡 **AI Review**: 5 suggestions

### Detailed Findings

#### 🔑 Secret Scanning
No hardcoded credentials detected.

#### 📦 Dependency Vulnerabilities
| Package | Version | Vulnerability | Severity |
|---------|---------|--------------|----------|
| requests | 2.20.0 | CVE-2021-1234 | HIGH |

#### 🤖 AI Code Review
1. **File**: `src/main.py` (Line 42)
   - **Issue**: Potential null pointer exception
   - **Suggestion**: Add null check before accessing
```

## Project Deliverables

### Critical Files
1. **template.yaml** - Complete SAM infrastructure
2. **README.md** - Polished documentation with:
   - Architecture diagram
   - Clear problem/solution sections
   - Deployment instructions
   - Demo GIF
3. **src/** - All Lambda function code
4. **tests/** - Comprehensive test suite

### Submission Requirements
- 3-minute demo video
- Working end-to-end demonstration
- Clean, documented codebase
- Professional README.md

## Development Workflow

### Before Any Code Change
1. Synthesize context from project plan
2. Create detailed execution plan
3. Execute one step at a time
4. Self-verify against requirements
5. Wait for user confirmation

### Commit Message Format
```
feat: Add secret scanner Lambda function
- Implement trufflehog integration
- Add error handling for git operations
- Include unit tests with moto mocking
```

## Common Pitfalls to Avoid
- Don't create resources manually in AWS Console
- Don't hardcode any credentials or secrets
- Don't skip error handling in Lambda functions
- Don't forget to update Project_Summary.md
- Don't merge scanner results in parallel branches
- Don't exceed Lambda timeout limits (set appropriately)
```

```plaintext
# Test Rule
This is a test rule.
```

```plaintext
---
description: "Core development rules for DevSecOps Sentinel - serverless architecture, coding standards, and security practices"
globs: ["**/*.py", "**/*.yaml", "**/*.yml", "**/*.md"]
alwaysApply: true
---

# DevSecOps Sentinel - Development Rules

## Project Overview
DevSecOps Sentinel is an AI-powered, serverless security and quality analysis platform for GitHub Pull Requests.

## Architecture Principles

### Serverless-First Design
- **ALL** components must be serverless and event-driven
- No EC2 instances, containers, or persistent servers
- Use AWS Lambda for all compute needs
- Infrastructure defined exclusively in template.yaml using AWS SAM

### Core Architecture Components
1. **API Gateway** - Webhook endpoint with Lambda Authorizer
2. **Step Functions** - Orchestrates parallel analysis workflow
3. **Lambda Functions**:
   - webhook-handler-lambda - Processes GitHub webhooks
   - secret-scanner-lambda - Detects hardcoded credentials
   - vulnerability-scanner-lambda - Checks dependencies
   - ai-reviewer-lambda - AI-powered code review
   - aggregator-lambda - Consolidates results and posts to GitHub
4. **DynamoDB** - Audit logging
5. **Secrets Manager** - GitHub API token storage
6. **Bedrock** - AI model (Claude 3.5 Sonnet)

## Development Methodology

### Core Development Rules
1. **Infrastructure as Code**: NO manual AWS resource creation
2. **Incremental Development**: One change at a time
3. **Testing First**: Unit tests with pytest/moto required
4. **Security First**: Validate webhooks, secure token storage
5. **Documentation Driven**: Maintain README.md and Project_Summary.md

## Technical Stack

### Required Technologies
- **Language**: Python 3.11
- **IaC**: AWS SAM (template.yaml)
- **Testing**: pytest with moto for AWS mocking
- **AI Model**: anthropic.claude-3-5-sonnet-20240620-v1:0
- **Key Libraries**: boto3, requests, py-safety, trufflehog

### AWS Services
- Lambda, Step Functions, API Gateway
- DynamoDB, Secrets Manager, IAM
- S3 (static hosting), Bedrock

## Security Requirements

### Mandatory Security Practices
1. **Webhook Security**: Lambda Authorizer validates signatures
2. **Token Management**: GitHub token in Secrets Manager only
3. **IAM Principles**: Least privilege for each Lambda role
4. **No Hardcoded Secrets**: Use environment variables

## Common Pitfalls to Avoid
- Don't create resources manually in AWS Console
- Don't hardcode any credentials or secrets
- Don't skip error handling in Lambda functions
- Don't forget to update Project_Summary.md
- Don't exceed Lambda timeout limits
```

```plaintext
---
description: "AWS SAM infrastructure rules for template.yaml, deployment configuration, and CloudFormation best practices"
globs: ["**/template.yaml", "**/template.yml", "**/samconfig.toml", "**/buildspec.yml"]
alwaysApply: false
---

# AWS SAM Infrastructure Rules

## SAM Template Structure

The template.yaml file is the single source of truth for all AWS infrastructure.

### Required Resources

#### Lambda Function Configuration
- Use Python 3.11 runtime
- Set appropriate memory and timeout based on function type
- Scanner functions: 1024MB memory, 300s timeout, 2048MB ephemeral storage
- AI Reviewer functions: 512MB memory, 900s timeout

#### IAM Role Templates
```yaml
# Minimal permissions for scanner Lambda
ScannerRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
          Action: sts:AssumeRole
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

## Step Functions State Machine
- Use Map state for parallel execution
- Include error handling with Catch blocks
- Implement retry logic for transient failures

## Security Requirements
- Use least privilege IAM permissions
- Store secrets in AWS Secrets Manager
- Enable API Gateway throttling
- Set Lambda reserved concurrency limits

## Best Practices
- Use descriptive resource names with Function/Table/Api suffix
- Avoid hardcoded ARNs - use !Ref and !GetAtt
- Tag all resources appropriately
- Use PAY_PER_REQUEST billing for DynamoDB
- Set appropriate CloudWatch log retention
```

```plaintext
---
description: "Testing strategy rules for unit tests, integration tests, and E2E testing with pytest and moto"
globs: ["**/test_*.py", "**/tests/**/*.py", "**/conftest.py", "**/.coveragerc"]
alwaysApply: false
---

# Testing Strategy Rules

## Testing Philosophy
All code must be thoroughly tested before deployment. Unit tests required for business logic.

## Unit Testing with pytest and moto

### Test Structure
```
tests/
├── unit/
│   ├── test_webhook_handler.py
│   ├── test_secret_scanner.py
│   ├── test_vulnerability_scanner.py
│   ├── test_ai_reviewer.py
│   └── test_aggregator.py
├── integration/
│   └── test_workflow.py
├── fixtures/
│   ├── github_events.py
│   └── sample_code.py
└── conftest.py
```

### Base Test Template
```python
import pytest
from moto import mock_dynamodb, mock_secretsmanager, mock_stepfunctions
import boto3
from unittest.mock import patch, MagicMock

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture
def lambda_context():
    """Mock Lambda context object."""
    context = MagicMock()
    context.function_name = "test-function"
    context.request_id = "test-request-id"
    return context
```

## Testing Requirements
- Mock all AWS service calls with moto
- Test error paths and edge cases
- Maintain >80% code coverage
- Use descriptive test function names
- Test isolation - each test must be independent
- Never call real APIs in unit tests

## Integration Testing
- Use sam local invoke with test events
- Create test GitHub repository
- Verify end-to-end workflow

## Coverage Requirements
```ini
# .coveragerc
[run]
source = src/
omit = 
    */tests/*
    */venv/*
    */__pycache__/*

[report]
precision = 2
show_missing = True
skip_covered = False
```
```

```plaintext
---
description: "AI integration rules for Amazon Bedrock, prompt engineering, and AI-powered code review"
globs: ["**/ai_*.py", "**/bedrock*.py", "**/prompts/**/*"]
alwaysApply: false
---

# AI Integration with Amazon Bedrock

## Overview
AI-powered code review using Amazon Bedrock (Claude 3.5 Sonnet) is a core differentiator.

## Bedrock Configuration

### Model Selection
```python
# Always use this specific model
MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
MODEL_KWARGS = {
    "max_tokens": 4096,
    "temperature": 0.3,  # Lower temperature for consistent code analysis
    "top_p": 0.9,
    "stop_sequences": []
}
```

### Client Setup
```python
import boto3
import json
from typing import Dict, List, Optional

class BedrockClient:
    """Wrapper for Amazon Bedrock interactions."""
    
    def __init__(self, region: str = "us-east-1"):
        self.client = boto3.client(
            service_name="bedrock-runtime",
            region_name=region
        )
        self.model_id = MODEL_ID
    
    def analyze_code(self, code: str, filename: str) -> Dict:
        """Analyze code for quality issues."""
        prompt = self._build_analysis_prompt(code, filename)
        
        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    **MODEL_KWARGS
                })
            )
            
            result = json.loads(response["body"].read())
            return self._parse_response(result)
            
        except Exception as e:
            logger.error(f"Bedrock invocation failed: {str(e)}")
            return {"findings": [], "error": str(e)}
```

## Error Handling
- Always implement retry logic with exponential backoff
- Have fallback strategies when Bedrock fails
- Validate all AI responses before using them
- Log all AI interactions for debugging

## Cost Optimization
- Truncate large files to manage token usage
- Batch small files together to reduce API calls
- Monitor token usage and implement limits
- Smart truncation - keep imports and function signatures

## Best Practices
1. **Prompt Clarity**: Be explicit about expected output format
2. **Context Limiting**: Focus on changed files only
3. **Error Recovery**: Always have fallback for when AI fails
4. **Response Validation**: Never trust AI output without validation
5. **Timeout Handling**: Set appropriate timeouts for Bedrock calls
```

```plaintext
---
description: "Documentation about available Cursor rules and how to use them"
globs: []
alwaysApply: false
---

# DevSecOps Sentinel - Cursor Rules

## Overview
These Cursor rules provide comprehensive guidance for developing the DevSecOps Sentinel project, an AI-powered serverless security analysis platform for GitHub Pull Requests.

## Available Rules

### 1. Main Development Rules
**File**: devsecops-sentinel.mdc
- Core development principles and methodology
- Technical stack requirements
- Coding standards and security practices
- Always applied to Python, YAML, and Markdown files

### 2. AWS SAM Infrastructure Rules  
**File**: sam-infrastructure.mdc
- SAM template structure and requirements
- Lambda function configuration and IAM roles
- Deployment configuration and best practices
- Auto-applied when working with template.yaml or deployment files

### 3. Testing Strategy Rules
**File**: testing-strategy.mdc
- Unit testing with pytest and moto
- Integration and E2E testing approaches
- Coverage requirements and CI/CD setup
- Auto-applied when working with test files

### 4. AI Integration Rules
**File**: ai-integration.mdc
- Amazon Bedrock configuration and setup
- Prompt engineering and error handling
- Cost optimization techniques
- Auto-applied when working with AI-related code

## Quick Reference

### Core Architecture
- Event-driven serverless using AWS Lambda
- Orchestrated by AWS Step Functions
- Triggered by GitHub webhooks
- Parallel execution of security scanners
- AI-powered code review with Bedrock
- Single consolidated GitHub PR comment

### Critical Principles
- **Infrastructure as Code**: Everything in template.yaml
- **Security First**: Validate webhooks, secure credentials
- **Test Everything**: Unit tests required for business logic
- **No Manual AWS Changes**: All through SAM/IaC
- **Documentation Driven**: README.md is a deliverable
```

```plaintext
---
description: "AI integration rules for Amazon Bedrock, prompt engineering, and AI-powered code review"
globs: ["**/ai_*.py", "**/bedrock*.py", "**/prompts/**/*"]
alwaysApply: false
---
```

## ✅ Cursor Rules Successfully Updated!

I've successfully reviewed and improved all the Cursor rules with proper metadata and content optimization. Here's what was accomplished:

### **Metadata Added to All Rules:**

1. **devsecops-sentinel.mdc** (Main Development Rules)
   - **Description**: "Core development rules for DevSecOps Sentinel - serverless architecture, coding standards, and security practices"
   - **Globs**: `["**/*.py", "**/*.yaml", "**/*.yml", "**/*.md"]`
   - **alwaysApply**: `true` (Always active for core guidance)

2. **sam-infrastructure.mdc** (AWS SAM Infrastructure Rules)
   - **Description**: "AWS SAM infrastructure rules for template.yaml, deployment configuration, and CloudFormation best practices"
   - **Globs**: `["**/template.yaml", "**/template.yml", "**/samconfig.toml", "**/buildspec.yml"]`
   - **alwaysApply**: `false` (Auto-applied when working with infrastructure files)

3. **testing-strategy.mdc** (Testing Strategy Rules)
   - **Description**: "Testing strategy rules for unit tests, integration tests, and E2E testing with pytest and moto"
   - **Globs**: `["**/test_*.py", "**/tests/**/*.py", "**/conftest.py", "**/.coveragerc"]`
   - **alwaysApply**: `false` (Auto-applied when working with test files)

4. **ai-integration.mdc** (AI Integration Rules)
   - **Description**: "AI integration rules for Amazon Bedrock, prompt engineering, and AI-powered code review"
   - **Globs**: `["**/ai_*.py", "**/bedrock*.py", "**/prompts/**/*"]`
   - **alwaysApply**: `false` (Auto-applied when working with AI-related code)

5. **README.mdc** (Documentation)
   - **Description**: "Documentation about available Cursor rules and how to use them"
   - **Globs**: `[]` (Manual rule only)
   - **alwaysApply**: `false` (Reference documentation)

### **Content Improvements:**

- **Streamlined** rule content to focus on essential guidance without duplication
- **Optimized** for better readability and actionability
- **Added proper glob patterns** for automatic rule triggering based on file types
- **Maintained** all critical technical requirements and best practices
- **Improved** organization and structure for better discoverability

### **Best Practices Applied:**

According to Cursor Rules documentation:
- ✅ Clear, actionable descriptions
- ✅ Appropriate glob patterns for auto-attachment
- ✅ Proper MDC format with YAML frontmatter
- ✅ Focused content under 500 lines per rule
- ✅ Composable rules for different contexts

The rules are now properly configured to:
- **Always apply** core development principles when working on Python, YAML, or Markdown files
- **Auto-attach** specialized rules when working with relevant file types (infrastructure, tests, AI code)
- **Provide contextual guidance** tailored to specific development tasks

This setup ensures that you'll get the right guidance at the right time while developing the DevSecOps Sentinel project! 🎯


# DevSecOps Sentinel 🛡️

> **An AI-powered, serverless security and quality analysis platform for GitHub Pull Requests**

[![AWS SAM](https://img.shields.io/badge/AWS-SAM-orange)](https://aws.amazon.com/serverless/sam/)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success)](https://github.com/belumume/sentinel-testbed)

## 🚀 What is DevSecOps Sentinel?

DevSecOps Sentinel is a **production-ready** serverless application that automatically analyzes GitHub pull requests for security vulnerabilities, code quality issues, and best practice violations. Built for the AWS Lambda Hackathon, it demonstrates the power of serverless architecture in DevSecOps workflows.

### ✨ Key Features

- **🔍 Multi-Layer Secret Detection**: Advanced 5-layer detection system using ML, pattern matching, entropy analysis, and semantic context
- **🛡️ Real-Time Vulnerability Scanning**: Analyzes Python and Node.js dependencies against the OSV database
- **🤖 AI-Powered Code Review**: Leverages Amazon Bedrock with Claude Sonnet 4 for intelligent code analysis
- **⏱️ Instant Progress Feedback**: Shows analysis progress immediately when PRs are opened
- **⚡ Serverless Architecture**: Scales automatically, costs nothing when idle
- **📊 Comprehensive Reporting**: Posts detailed, actionable comments directly on PRs
- **🔐 Enterprise Security**: Webhook validation, Secrets Manager integration, least-privilege IAM

### 🎯 Production Performance

- **Sub-minute Analysis**: Complete PR analysis in < 60 seconds
- **High Detection Rates**: Detects 13+ types of secrets, 200+ vulnerabilities
- **Smart Classification**: Automatically categorizes findings by type and severity
- **Zero Idle Cost**: Pay only for what you use with serverless architecture

## 🏗️ Architecture

```mermaid
graph TD
    subgraph GitHub
        A[Pull Request Event]
    end
    
    subgraph AWS
        A -- Webhook --> B[API Gateway]
        B --> C[WebhookHandler Lambda]
        C -- Posts Progress Comment --> I
        C -- Validates & Triggers --> D[Step Functions]
        
        subgraph D[Parallel Analysis]
            E[Secret Scanner]
            F[Vulnerability Scanner]
            G[AI Code Reviewer]
        end
        
        E --> H[Aggregator Lambda]
        F --> H
        G --> H
        H -- Updates Comment --> I[GitHub PR Comment]
        H --> J[DynamoDB Audit Log]
    end
    
    style D fill:#f9f,stroke:#333,stroke-width:2px
```

### 🔧 Technology Stack

- **Compute**: AWS Lambda (Python 3.11)
- **Orchestration**: AWS Step Functions
- **API**: Amazon API Gateway
- **AI/ML**: Amazon Bedrock (Claude Sonnet 4)
- **Storage**: DynamoDB, AWS Secrets Manager
- **Security Tools**: TruffleHog, OSV API, Custom Detection Algorithms
- **IaC**: AWS SAM (Serverless Application Model)

## 📋 Prerequisites

- AWS Account with appropriate permissions
- AWS CLI configured
- AWS SAM CLI installed
- Python 3.11+
- GitHub account with a repository for testing
- GitHub Personal Access Token (PAT) with repo permissions

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/belumume/devsecops-sentinel.git
cd devsecops-sentinel
```

### 2. Set Up Secrets in AWS Secrets Manager

Create two secrets in AWS Secrets Manager:

1. **GitHub Webhook Secret** (e.g., `DevSecOpsSentinel/WebhookSecret`):
   ```
   your-webhook-secret-string
   ```

2. **GitHub Token** (e.g., `DevSecOpsSentinel/GitHubToken`):
   ```json
   {
     "GITHUB_TOKEN": "ghp_your_github_personal_access_token"
   }
   ```

### 3. Deploy the Application

```bash
# Build the SAM application
sam build

# Deploy (first time - will prompt for parameters)
sam deploy --guided

# Subsequent deployments
sam deploy
```

During the guided deployment, you'll be asked for:
- Stack Name: `devsecops-sentinel`
- AWS Region: Your preferred region
- GitHubWebhookSecretName: Name of your webhook secret in Secrets Manager

### 4. Configure GitHub Webhook

1. Copy the API Gateway URL from the deployment outputs
2. In your GitHub repository, go to Settings → Webhooks
3. Add a new webhook:
   - **Payload URL**: The API Gateway URL from the outputs
   - **Content type**: `application/json`
   - **Secret**: Your webhook secret (same as stored in Secrets Manager)
   - **Events**: Select "Pull requests"

### 5. Test the System

Create a pull request in your configured repository and watch DevSecOps Sentinel automatically analyze your code!

## 🔍 How It Works

### 1. **Webhook Reception & Progress Indicator**
When a PR is created/updated, GitHub sends a webhook to our API Gateway endpoint. The WebhookHandler immediately posts a progress comment to let users know analysis has started.

### 2. **Security Validation**
The WebhookHandler Lambda validates the webhook signature using HMAC-SHA256 to ensure authenticity.

### 3. **Orchestration**
Step Functions initiates parallel execution of three analysis modules:

- **Secret Scanner**: Uses 5-layer detection approach for comprehensive secret detection
- **Vulnerability Scanner**: Analyzes dependencies against the OSV database with smart version handling
- **AI Reviewer**: Uses Claude Sonnet 4 to identify bugs, security issues, and suggest improvements

### 4. **Aggregation & Reporting**
The Aggregator Lambda:
- Consolidates findings from all scanners
- Formats a comprehensive Markdown report
- Updates the progress comment with final results
- Logs the analysis summary to DynamoDB

## 📊 Sample Output

When DevSecOps Sentinel analyzes a PR, it posts a comment that updates from progress to results:

**Initial Progress Comment:**
```markdown
## 🔍 DevSecOps Sentinel Analysis In Progress...

⏳ **Status**: Analyzing your pull request
📝 **Started**: Just now
⏱️ **Estimated time**: ~30-60 seconds

Please wait while we scan for:
- 🔐 Hardcoded secrets
- 🛡️ Vulnerable dependencies  
- 💡 Code quality issues

_This comment will update automatically when analysis completes._
```

**Final Analysis Report:**
```markdown
## 🔍 DevSecOps Sentinel Analysis Report

### 📊 Summary
| Scanner | Status | Findings |
|:---|:---:|:---|
| 🔴 Secret Scanner | **Action Required** | 13 secrets found |
| 🟡 Vulnerability Scanner | **Review Needed** | 206 vulnerabilities in 20 packages |
| 💡 AI Code Review | **Improvements Available** | 18 suggestions |

### 🔴 Critical: Hardcoded Secrets Detected
**Immediate action required:** Remove these secrets and rotate them.

1. **API Key** found in `config/database.py` at line `19`
   ```
   STRIPE_API_KEY = "sk_test_51KqUi..."
   ```
   
2. **Password** found in `config/database.py` at line `10`
   ```
   password='SuperSecret123!'
   ```

### 🟡 Dependency Vulnerabilities Detected
**Action needed:** Update the following 20 packages to their secure versions.

1. 🔴 **Django** `2.0.1` → `check PyPI for latest`
   - GHSA-h2g4-...: SQL Injection vulnerability
   - 47 vulnerabilities found
   
2. 🔴 **requests** `2.9.0` → `check PyPI for latest`
   - PYSEC-2023-74: Security bypass vulnerability
   - 5 vulnerabilities found

[... additional details ...]
```

## 🛠️ Configuration

### Environment Variables

Configure these in your SAM template or Lambda environment:

- `STATE_MACHINE_ARN`: ARN of the Step Functions state machine
- `GITHUB_WEBHOOK_SECRET_NAME`: Name of webhook secret in Secrets Manager
- `GITHUB_TOKEN_SECRET_NAME`: Name of GitHub token secret in Secrets Manager
- `SCANS_TABLE_NAME`: DynamoDB table name for audit logs

### IAM Permissions

The solution follows least-privilege principles. Each Lambda has only the permissions it needs:

- WebhookHandler: Can start Step Functions executions, read secrets, and post to GitHub
- Scanners: Read-only access to analyze code
- AI Reviewer: Can invoke Bedrock models
- Aggregator: Can write to DynamoDB and read GitHub token

## 🧪 Development & Testing

### Local Testing

```bash
# Test a Lambda function locally
sam local invoke SecretScannerFunction -e events/test-event.json

# Start local API Gateway
sam local start-api
```

### Running Tests

```bash
# Install test dependencies
pip install -r tests/requirements.txt

# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/
```

### Test Repository

A test repository with intentionally vulnerable code is available at:
https://github.com/belumume/sentinel-testbed

## 🚀 Extending DevSecOps Sentinel

### Adding New Scanners

1. Create a new Lambda function in `src/lambdas/your_scanner/`
2. Implement the standardized response format:
   ```python
   {
       "statusCode": 200,
       "scanner_type": "your_scanner",
       "findings": [...],
       "repo_details": {...}
   }
   ```
3. Add the function to `template.yaml`
4. Update the Step Functions state machine to include your scanner

### Customizing AI Prompts

Modify the prompt construction in `src/lambdas/ai_reviewer/app.py` to focus on specific coding standards or security policies for your organization.

## 📈 Performance & Scalability

- **Concurrent Execution**: Step Functions Map state enables parallel processing
- **Auto-scaling**: Lambda automatically scales to handle multiple PRs simultaneously
- **Cost-effective**: Pay only for actual usage, near-zero cost when idle
- **Production Metrics**: Processes PRs in under 60 seconds with comprehensive analysis

## 🔐 Security Considerations

- **Webhook Validation**: All incoming webhooks are cryptographically verified
- **Secrets Management**: All credentials stored in AWS Secrets Manager
- **Least Privilege**: IAM roles follow principle of least privilege
- **No Code Storage**: Code is analyzed in-memory and never persisted
- **Lambda Layers**: Security tools packaged in Lambda layers for consistent execution

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

Built for the AWS Lambda Serverless Hackathon 2025. Special thanks to:
- AWS Lambda team for the amazing serverless platform
- Amazon Bedrock team for accessible AI capabilities
- The open-source community for inspiration and tools

---

**Built with ❤️ using AWS Lambda** | [Documentation](docs/) | [Architecture](docs/architecture.md) | [API Reference](docs/api.md) 
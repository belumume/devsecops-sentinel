# DevSecOps Sentinel - Architecture Overview

## System Architecture

DevSecOps Sentinel is a 100% serverless, event-driven security analysis platform built on AWS Lambda and other managed services.

```
┌─────────────────┐
│     GitHub      │
│   Pull Request  │
└────────┬────────┘
         │ Webhook
         ▼
┌─────────────────┐
│   API Gateway   │
│    (HTTPS)      │
└────────┬────────┘
         │
         ▼
┌─────────────────────┐      ┌──────────────────┐
│  WebhookHandler     │      │ Secrets Manager  │
│     Lambda          │◄─────┤  - GitHub Token  │
│                     │      │  - Webhook Secret│
└──────────┬──────────┘      └──────────────────┘
           │ Start Execution
           ▼
┌──────────────────────────────────────────────┐
│           Step Functions State Machine        │
│                                              │
│  ┌────────────────────────────────────────┐ │
│  │         Parallel Map State              │ │
│  │                                         │ │
│  │  ┌─────────────┐  ┌─────────────────┐  │ │
│  │  │   Secret    │  │  Vulnerability  │  │ │
│  │  │  Scanner    │  │    Scanner      │  │ │
│  │  │   Lambda    │  │    Lambda       │  │ │
│  │  └─────────────┘  └─────────────────┘  │ │
│  │                                         │ │
│  │         ┌─────────────────┐            │ │
│  │         │   AI Reviewer   │            │ │
│  │         │     Lambda      │            │ │
│  │         └─────────────────┘            │ │
│  └────────────────────────────────────────┘ │
│                     │                        │
│                     ▼                        │
│           ┌─────────────────┐               │
│           │   Aggregator    │               │
│           │     Lambda      │               │
│           └────────┬────────┘               │
└────────────────────┼────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
┌──────────────┐         ┌────────────────┐
│   DynamoDB   │         │  GitHub API    │
│ (Audit Logs) │         │ (PR Comments)  │
└──────────────┘         └────────────────┘
```

## Core Components

### 1. API Gateway
- **Purpose**: HTTPS endpoint for GitHub webhooks
- **Security**: Webhook signature validation
- **Integration**: Direct Lambda proxy integration
- **Endpoint**: `/webhook` (POST)

### 2. WebhookHandler Lambda
- **Runtime**: Python 3.11
- **Memory**: 512 MB
- **Timeout**: 30 seconds
- **Responsibilities**:
  - Validate GitHub webhook signatures
  - Parse PR events
  - Post initial progress comment
  - Start Step Functions execution

### 3. Step Functions State Machine
- **Type**: Express workflow
- **Pattern**: Parallel Map state for concurrent execution
- **Error Handling**: Built-in retry logic
- **Timeout**: 5 minutes total

### 4. Scanner Lambda Functions

#### SecretScanner
- **Memory**: 1024 MB
- **Timeout**: 120 seconds
- **Tools**: TruffleHog + custom detection layers
- **Detection Methods**:
  - ML-based detection (TruffleHog)
  - Pattern matching
  - Entropy analysis
  - Semantic analysis
  - Custom algorithms

#### VulnerabilityScanner
- **Memory**: 512 MB
- **Timeout**: 120 seconds
- **Tools**: OSV API, pip-audit, npm audit
- **Capabilities**:
  - Python dependency scanning
  - JavaScript/npm scanning
  - Real-time vulnerability data

#### AIReviewer
- **Memory**: 512 MB
- **Timeout**: 60 seconds
- **Model**: Claude 3.5 Sonnet v2 (20241022) via Amazon Bedrock
- **Analysis**: Code quality, security, best practices

### 5. Aggregator Lambda
- **Memory**: 1024 MB
- **Timeout**: 60 seconds
- **Responsibilities**:
  - Consolidate results from all scanners
  - Format GitHub markdown comments
  - Update PR comments via GitHub API
  - Log results to DynamoDB

### 6. Lambda Layers
- **ScannerLayer**: ~77MB compressed
  - TruffleHog binary
  - Python dependencies (safety, bandit, pip-audit)
  - npm binary
  - git binary
- **SentinelUtils**: Shared utilities

### 7. Data Storage

#### DynamoDB - ScansTable
- **Partition Key**: `pr_id` (String)
- **Sort Key**: `scan_timestamp` (String)
- **Attributes**:
  - `repository`: Repository name
  - `pr_number`: Pull request number
  - `scan_results`: JSON with findings
  - `scan_duration_ms`: Performance metric

#### Secrets Manager
- **GitHubToken**: PAT for API access
- **GitHubWebhookSecret**: HMAC validation

## Security Architecture

### Authentication & Authorization
1. **Webhook Validation**: HMAC-SHA256 signature verification
2. **IAM Roles**: Least privilege per Lambda function
3. **Secrets Management**: All credentials in Secrets Manager
4. **No Hardcoded Values**: Environment variables reference secrets

### Network Security
- No VPC required (fully managed services)
- HTTPS only communication
- API Gateway with request validation

## Scalability & Performance

### Auto-Scaling
- Lambda: Automatic scaling (1000 concurrent executions)
- Step Functions: 1000 state transitions/second
- DynamoDB: On-demand pricing mode

### Performance Optimization
- Parallel processing via Map state
- Lambda layers for dependency caching
- Minimal cold starts with proper memory allocation
- Sub-minute end-to-end processing

## Cost Optimization

### Pay-Per-Use Model
- **Lambda**: $0.0000133/GB-second
- **Step Functions**: $0.025/1000 state transitions
- **API Gateway**: $3.50/million requests
- **DynamoDB**: On-demand pricing
- **Estimated Cost**: < $0.01 per PR scan

### Zero Idle Cost
- No running servers
- No minimum fees
- Resources only consumed during PR analysis

## Deployment Architecture

### Infrastructure as Code
```yaml
# SAM Template Structure
Resources:
  WebhookApi:         # API Gateway
  WebhookHandler:     # Lambda Function
  AnalysisStateMachine: # Step Functions
  SecretScanner:      # Lambda Function
  VulnerabilityScanner: # Lambda Function
  AIReviewer:         # Lambda Function
  Aggregator:         # Lambda Function
  ScansTable:         # DynamoDB Table
  ScannerLayer:       # Lambda Layer
```

### CI/CD Pipeline
```bash
# Build and Deploy
sam build --use-container
sam deploy --guided
```

## Monitoring & Observability

### CloudWatch Integration
- Lambda function logs
- Step Functions execution history
- API Gateway access logs
- Custom metrics for scan performance

### Audit Trail
- All scans logged to DynamoDB
- Webhook events tracked
- Error rates monitored

## Future Architecture Considerations

### Potential Enhancements
1. **SQS Queue**: For webhook buffering
2. **ElastiCache**: For caching vulnerability data
3. **EventBridge**: For additional integrations
4. **S3**: For large diff storage

### Scaling Considerations
- Current: Handles 100+ PRs/minute
- Future: Can scale to 1000s with SQS buffering
- Multi-region deployment possible

---

**Built with AWS Serverless** 🚀 
# 🚀 DevSecOps Sentinel Deployment Guide

This guide will walk you through deploying DevSecOps Sentinel to AWS for the hackathon submission.

## 📋 Prerequisites

### 1. AWS Account Setup
- AWS account with appropriate permissions
- AWS CLI configured (`aws configure`)
- AWS SAM CLI installed

### 2. GitHub Setup
- GitHub Personal Access Token with `repo` scope
- Repository where you want to test the system

### 3. Required Secrets in AWS Secrets Manager

Create these secrets in AWS Secrets Manager:

#### GitHub Token Secret
```bash
aws secretsmanager create-secret \
    --name "DevSecOpsSentinel/GitHubToken" \
    --description "GitHub Personal Access Token for DevSecOps Sentinel" \
    --secret-string '{"GITHUB_TOKEN":"ghp_your_github_personal_access_token"}' \
    --region us-east-1
```

#### Webhook Secret
```bash
aws secretsmanager create-secret \
    --name "DevSecOpsSentinel/WebhookSecret" \
    --description "GitHub Webhook Secret for DevSecOps Sentinel" \
    --secret-string "your-webhook-secret-string" \
    --region us-east-1
```

## 🚀 Deployment Options

### Option 1: Automated Deployment (Recommended)

Use the provided PowerShell script:

```powershell
# Deploy everything including Lambda layer
.\scripts\deploy.ps1

# Or deploy to a different region
.\scripts\deploy.ps1 -Region us-west-2

# Skip layer deployment if already exists
.\scripts\deploy.ps1 -SkipLayer
```

### Option 2: Manual Deployment

#### Step 1: Deploy Lambda Layer
```bash
aws lambda publish-layer-version \
    --layer-name DevSecOpsSentinel-Scanner \
    --description 'Scanner tools for DevSecOps Sentinel' \
    --zip-file fileb://scanner-layer.zip \
    --compatible-runtimes python3.11 \
    --region us-east-1
```

Note the returned Layer ARN (e.g., `arn:aws:lambda:us-east-1:123456789012:layer:DevSecOpsSentinel-Scanner:1`)

#### Step 2: Build and Deploy SAM Application
```bash
# Build the application
sam build

# Deploy with layer ARN
sam deploy --parameter-overrides ScannerLayerArn=arn:aws:lambda:us-east-1:123456789012:layer:DevSecOpsSentinel-Scanner:1

# Or deploy without layer (for testing)
sam deploy
```

## 🔗 GitHub Webhook Configuration

### 1. Get the API Gateway URL
After deployment, get the webhook URL:

```bash
aws cloudformation describe-stacks \
    --stack-name devsecops-sentinel \
    --query 'Stacks[0].Outputs[?OutputKey==`WebhookApiUrl`].OutputValue' \
    --output text \
    --region us-east-1
```

### 2. Configure GitHub Webhook

1. Go to your GitHub repository
2. Navigate to Settings → Webhooks
3. Click "Add webhook"
4. Configure:
   - **Payload URL**: The API Gateway URL from step 1
   - **Content type**: `application/json`
   - **Secret**: The webhook secret you stored in Secrets Manager
   - **Events**: Select "Pull requests"
5. Click "Add webhook"

## 🧪 Testing the Deployment

### 1. Create a Test Pull Request

Create a PR with some test content:

```python
# test_file.py
import os

# This should trigger the secret scanner
API_KEY = "sk-1234567890abcdef"  # Fake API key for testing

# This should trigger the vulnerability scanner (if you have requirements.txt)
import requests  # Add requests==2.25.1 to requirements.txt for vulnerability test

def test_function():
    # This should trigger AI suggestions
    x = 1
    y = 2
    z = x + y
    return z
```

### 2. Verify the System Works

1. Create the pull request
2. Check CloudWatch logs for the Lambda functions
3. Verify a comment appears on the PR with analysis results
4. Check DynamoDB for the audit log entry

## 🔍 Troubleshooting

### Common Issues

#### 1. Authentication Errors (401)
- Verify GitHub token is correctly stored in Secrets Manager
- Ensure token has `repo` scope
- Check the token format: `{"GITHUB_TOKEN": "ghp_..."}`

#### 2. Layer Not Found
- Ensure the Lambda layer was deployed successfully
- Verify the layer ARN is correct in the deployment
- Check the layer is in the same region as your functions

#### 3. Webhook Validation Fails
- Verify webhook secret matches what's stored in Secrets Manager
- Check the webhook is configured for "Pull requests" events
- Ensure Content-Type is set to `application/json`

#### 4. Scanner Tools Not Found
- Verify the Lambda layer contains the required binaries
- Check CloudWatch logs for specific error messages
- Ensure the layer was built correctly with the build script

### Debugging Commands

```bash
# Check CloudWatch logs
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/devsecops-sentinel"

# Check Step Functions executions
aws stepfunctions list-executions --state-machine-arn <your-state-machine-arn>

# Check DynamoDB table
aws dynamodb scan --table-name <your-scans-table-name>
```

## 📊 Monitoring

### CloudWatch Dashboards

The deployment creates CloudWatch logs for all Lambda functions:
- `/aws/lambda/devsecops-sentinel-WebhookHandlerFunction-*`
- `/aws/lambda/devsecops-sentinel-SecretScannerFunction-*`
- `/aws/lambda/devsecops-sentinel-VulnerabilityScannerFunction-*`
- `/aws/lambda/devsecops-sentinel-AIReviewerFunction-*`
- `/aws/lambda/devsecops-sentinel-AggregatorFunction-*`

### Step Functions Console

Monitor workflow executions in the AWS Step Functions console to see the parallel processing in action.

## 🎯 Ready for Hackathon!

Once deployed and tested, your DevSecOps Sentinel is ready to demonstrate:

1. **Real Security Scanning**: Actual secret detection with trufflehog
2. **Real Vulnerability Analysis**: Dependency scanning with safety/npm audit
3. **Real AI Code Review**: Intelligent analysis with Amazon Bedrock
4. **Serverless Excellence**: Scalable, cost-effective architecture
5. **Production Quality**: Complete error handling and monitoring

Your hackathon submission showcases a real, working DevSecOps tool that provides immediate value to development teams!

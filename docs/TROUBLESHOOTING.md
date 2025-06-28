# DevSecOps Sentinel - Troubleshooting Guide

## 🔧 Common Issues and Solutions

### 1. Scanner Tools Not Available

#### Symptoms
- Log messages: "Trufflehog tool not found"
- Log messages: "npm tool not available"  
- Log messages: "safety tool not available"
- Analysis reports show "Scanner Tools Not Available" warnings

#### Root Causes
- Lambda layer not properly attached
- Incorrect layer version being used
- PATH environment variable not configured
- Layer build failed or incomplete

#### Solutions

**Check Layer Attachment:**
```bash
aws lambda get-function --function-name devsecops-sentinel-SecretScannerFunction-XXXXX --query "Configuration.Layers"
```

**Verify Layer Contents:**
```bash
# Check if layer exists and has correct size (~77MB for full layer)
aws lambda list-layer-versions --layer-name DevSecOpsSentinel-Scanner --max-items 5
```

**Rebuild and Redeploy Layer:**
```powershell
# Rebuild the scanner layer
.\scripts\build-scanner-layer.ps1

# Redeploy with new layer
.\scripts\deploy.ps1
```

**Manual Layer Update:**
```bash
# If deployment script fails, manually update layer
sam deploy --parameter-overrides "ScannerLayerArn=arn:aws:lambda:us-east-1:ACCOUNT:layer:DevSecOpsSentinel-Scanner:VERSION"
```

### 2. Layer Upload Failures

#### Symptoms
- "Request entity too large" errors
- Layer upload timeouts
- "InvalidParameterValueException" during layer creation

#### Root Causes
- Layer size exceeds 50MB direct upload limit
- Network connectivity issues
- Insufficient permissions

#### Solutions

**Use S3 Upload Method:**
```bash
# Upload layer to S3 first
aws s3 cp scanner-layer.zip s3://your-bucket/scanner-layer.zip

# Create layer from S3
aws lambda publish-layer-version \
  --layer-name DevSecOpsSentinel-Scanner \
  --content S3Bucket=your-bucket,S3Key=scanner-layer.zip \
  --compatible-runtimes python3.11
```

**Check Permissions:**
```bash
# Verify you have required permissions
aws iam get-user
aws lambda list-layers
```

### 3. False Negatives (Missing Detections)

#### Symptoms
- Known secrets/vulnerabilities not detected
- "0 secrets found" when secrets are present
- "0 vulnerabilities found" for vulnerable dependencies

#### Root Causes
- Primary tools not finding issues (expected behavior)
- Fallback detection patterns need updates
- File types not being scanned

#### Solutions

**Verify Fallback Detection:**
```python
# Test fallback patterns locally
python test_enhanced_scanners.py
```

**Update Detection Patterns:**
```python
# Add new secret patterns in src/lambdas/secret_scanner/app.py
secret_patterns = [
    (r'your_new_pattern_here', 'Secret Type'),
    # ... existing patterns
]
```

**Check File Coverage:**
- Ensure target files are in supported formats
- Verify repository structure is correct
- Check file size limits (Lambda has 512MB /tmp limit)

### 4. Performance Issues

#### Symptoms
- Lambda timeouts (>15 minutes)
- High memory usage warnings
- Slow analysis completion

#### Root Causes
- Large repository size
- Insufficient memory allocation
- Tool execution bottlenecks

#### Solutions

**Increase Memory Allocation:**
```yaml
# In template.yaml
SecretScannerFunction:
  Properties:
    MemorySize: 1024  # Increase from 512MB
    Timeout: 900      # Increase timeout if needed
```

**Optimize Repository Scanning:**
- Implement file filtering for large repos
- Add timeout handling for tool execution
- Consider parallel processing for multiple files

### 5. GitHub Integration Issues

#### Symptoms
- Webhooks not triggering
- Comments not posting to PRs
- "Authentication failed" errors

#### Root Causes
- Invalid GitHub token
- Insufficient token permissions
- Webhook configuration issues

#### Solutions

**Verify GitHub Token:**
```bash
# Test token permissions
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/user
```

**Required Token Scopes:**
- `repo` - Repository access
- `repo:status` - Commit status access
- `repo_deployment` - Deployment access
- `public_repo` - Public repository access
- `repo:invite` - Repository invitations
- `security_events` - Security events

**Check Webhook Configuration:**
```bash
# List repository webhooks
curl -H "Authorization: token YOUR_TOKEN" \
  https://api.github.com/repos/OWNER/REPO/hooks
```

### 6. CloudFormation Deployment Failures

#### Symptoms
- Stack creation/update failures
- Resource creation errors
- Permission denied errors

#### Root Causes
- Insufficient IAM permissions
- Resource naming conflicts
- Parameter validation errors

#### Solutions

**Check IAM Permissions:**
```bash
# Verify CloudFormation permissions
aws iam list-attached-user-policies --user-name YOUR_USER
```

**Required Permissions:**
- CloudFormation full access
- Lambda full access
- IAM role creation
- S3 bucket access
- API Gateway management

**Clean Failed Deployments:**
```bash
# Delete failed stack
aws cloudformation delete-stack --stack-name devsecops-sentinel

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name devsecops-sentinel
```

## 🔍 Debugging Tools

### Log Analysis Commands

```bash
# Get recent secret scanner logs
aws logs filter-log-events \
  --log-group-name "/aws/lambda/devsecops-sentinel-SecretScannerFunction-*" \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --query 'events[*].message' \
  --output text

# Get vulnerability scanner logs
aws logs filter-log-events \
  --log-group-name "/aws/lambda/devsecops-sentinel-VulnerabilityScannerFunction-*" \
  --start-time $(date -d '1 hour ago' +%s)000

# Monitor real-time logs
aws logs tail /aws/lambda/devsecops-sentinel-SecretScannerFunction-* --follow
```

### Test Scripts

**Local Testing:**
```bash
# Test enhanced scanners locally
python test_enhanced_scanners.py

# Test vulnerability detection
python test_vuln_detection.py
```

**Lambda Testing:**
```bash
# Invoke function directly
sam local invoke SecretScannerFunction --event test-event.json

# Test API Gateway
sam local start-api
curl -X POST http://localhost:3000/webhook -d '{"test": true}'
```

### Health Check Commands

```bash
# Check all Lambda functions
aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `devsecops-sentinel`)].{Name:FunctionName,Runtime:Runtime,LastModified:LastModified}'

# Check Step Function executions
aws stepfunctions list-executions --state-machine-arn YOUR_STATE_MACHINE_ARN --max-items 10

# Verify API Gateway
aws apigateway get-rest-apis --query 'items[?name==`devsecops-sentinel`]'
```

## 📊 Monitoring Setup

### CloudWatch Alarms

```bash
# Create alarm for function errors
aws cloudwatch put-metric-alarm \
  --alarm-name "DevSecOps-Sentinel-Errors" \
  --alarm-description "Lambda function errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold

# Create alarm for duration
aws cloudwatch put-metric-alarm \
  --alarm-name "DevSecOps-Sentinel-Duration" \
  --alarm-description "Lambda function duration" \
  --metric-name Duration \
  --namespace AWS/Lambda \
  --statistic Average \
  --period 300 \
  --threshold 30000 \
  --comparison-operator GreaterThanThreshold
```

### Dashboard Creation

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/Lambda", "Invocations", "FunctionName", "devsecops-sentinel-SecretScannerFunction"],
          [".", "Errors", ".", "."],
          [".", "Duration", ".", "."]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "title": "DevSecOps Sentinel Metrics"
      }
    }
  ]
}
```

## 🆘 Emergency Procedures

### Rollback to Previous Version

```bash
# List previous layer versions
aws lambda list-layer-versions --layer-name DevSecOpsSentinel-Scanner

# Rollback to previous layer version
sam deploy --parameter-overrides "ScannerLayerArn=arn:aws:lambda:us-east-1:ACCOUNT:layer:DevSecOpsSentinel-Scanner:PREVIOUS_VERSION"
```

### Disable Webhook Temporarily

```bash
# Update webhook to return early
# Edit src/lambdas/webhook_handler/app.py to add:
# return {'statusCode': 200, 'body': 'Temporarily disabled'}

# Quick deploy
sam deploy
```

### Contact Information

For critical issues:
- **Email**: devops-support@example.com
- **Slack**: #devsecops-sentinel
- **On-call**: +1-555-DEVOPS

---

*This troubleshooting guide is regularly updated. Last updated: 2025-06-27*

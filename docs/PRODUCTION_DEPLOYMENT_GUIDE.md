# DevSecOps Sentinel - Production Deployment Guide

## 🚀 Current Production Configuration

### System Status
- **Status**: ✅ Fully Operational
- **API Endpoint**: `https://lbxly3f2e3.execute-api.us-east-1.amazonaws.com/prod/webhook`
- **Region**: us-east-1
- **Last Updated**: 2025-06-28

### Lambda Layer Architecture

The system uses an optimized 2-layer architecture:

#### Layer 1: Binary Tools Layer
- **Name**: `DevSecOps-Scanner-Layer:1`
- **Size**: 77.97 MB
- **Contents**: 
  - `git` - Version control operations
  - `trufflehog` - Secret detection
- **Purpose**: Provides binary executables for core scanning

#### Layer 2: Python Tools & Utilities Layer  
- **Name**: `DevSecOpsSentinel-Final:3`
- **Size**: 0.97 MB
- **Contents**:
  - `safety` - Python vulnerability scanner
  - `bandit` - Python security linter
  - `pip-audit` - Python package auditing
  - `npm` - Node.js vulnerability scanner (wrapper)
  - DevSecOps Sentinel utility functions
- **Purpose**: Lightweight layer with essential Python tools and utilities

### Scanner Tool Availability

| Tool | Status | Type | Purpose |
|------|--------|------|---------|
| trufflehog | ✅ Working | Binary | Secret detection |
| git | ✅ Working | Binary | Repository operations |
| safety | ✅ Working | Python wrapper | Python vulnerability scanning |
| bandit | ✅ Working | Python wrapper | Python security analysis |
| pip-audit | ✅ Working | Python wrapper | Python package auditing |
| npm | ✅ Working | Shell wrapper | Node.js vulnerability scanning |

## 🔧 Deployment Instructions

### Prerequisites
- AWS CLI configured with appropriate permissions
- SAM CLI installed
- Docker (for layer building if needed)

### Standard Deployment
```bash
# Build the application
sam build

# Deploy to production
sam deploy

# Verify deployment
aws lambda list-functions --region us-east-1 --query "Functions[?contains(FunctionName, 'devsecops-sentinel')]"
```

### Layer Management
```bash
# List current layers
aws lambda list-layers --region us-east-1

# Check layer versions
aws lambda list-layer-versions --layer-name DevSecOpsSentinel-Final --region us-east-1
```

## 🛠️ Troubleshooting Guide

### Common Issues

#### 1. Scanner Tools Not Available
**Symptoms**: "npm tool not available" or "safety tool not available" in PR comments

**Diagnosis**:
```bash
# Check function layers
aws lambda get-function --function-name devsecops-sentinel-VulnerabilityScannerFunction-XXX --region us-east-1 --query "Configuration.Layers"

# Test function directly
aws lambda invoke --function-name devsecops-sentinel-VulnerabilityScannerFunction-XXX --payload '{}' response.json
```

**Solution**: Verify both layers are attached and redeploy if necessary

#### 2. Layer Size Limit Exceeded
**Symptoms**: "Layers consume more than the available size of 262144000 bytes"

**Solution**: The current optimized configuration should avoid this. If it occurs:
1. Check if additional layers were added
2. Rebuild the optimized layer
3. Remove unnecessary dependencies

#### 3. Function Timeout
**Symptoms**: Lambda functions timing out during scanning

**Solution**:
```bash
# Increase timeout (current: 300 seconds)
aws lambda update-function-configuration --function-name FUNCTION_NAME --timeout 600
```

### Monitoring Commands

```bash
# Check recent logs
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/devsecops-sentinel"

# View specific function logs
aws logs tail /aws/lambda/devsecops-sentinel-VulnerabilityScannerFunction-XXX --follow

# Check CloudFormation stack status
aws cloudformation describe-stacks --stack-name devsecops-sentinel --region us-east-1
```

## 🔄 Maintenance Procedures

### Regular Updates

#### Monthly: Update Scanner Tools
1. Check for new versions of security tools
2. Rebuild layer with updated packages
3. Test in staging environment
4. Deploy to production

#### Weekly: Monitor Performance
1. Review CloudWatch metrics
2. Check error rates
3. Verify webhook response times

### Emergency Procedures

#### Rollback Deployment
```bash
# List stack events to find last good deployment
aws cloudformation describe-stack-events --stack-name devsecops-sentinel

# Rollback to previous version
aws cloudformation cancel-update-stack --stack-name devsecops-sentinel
```

#### Disable System Temporarily
```bash
# Remove webhook from GitHub repository settings
# Or disable API Gateway endpoint
aws apigateway update-stage --rest-api-id API_ID --stage-name prod --patch-ops op=replace,path=/throttle/rateLimit,value=0
```

## 📊 Performance Metrics

### Expected Performance
- **Secret Scanner**: < 30 seconds for typical PR
- **Vulnerability Scanner**: < 60 seconds for typical PR  
- **AI Reviewer**: < 45 seconds for typical PR
- **Total Analysis**: < 2 minutes end-to-end

### Resource Usage
- **Memory**: 512 MB per function (sufficient for current workload)
- **Storage**: Layers total ~79 MB (well under 250 MB limit)
- **Concurrent Executions**: 10 (current account limit)

## 🔐 Security Considerations

### Layer Security
- Layers contain only necessary tools and dependencies
- No sensitive data stored in layers
- Regular security updates applied

### Access Control
- Functions use least-privilege IAM roles
- GitHub webhook secret stored in AWS Secrets Manager
- API Gateway uses webhook signature validation

### Data Handling
- No persistent storage of repository data
- Temporary files cleaned up after analysis
- Logs automatically expire after 14 days

## 📞 Support Information

### Key Files
- **Main Template**: `template.yaml`
- **Layer Build Scripts**: `create_final_layer.py`
- **Deployment Script**: `scripts/deploy.ps1`

### Useful ARNs
- **Binary Layer**: `arn:aws:lambda:us-east-1:390402580689:layer:DevSecOps-Scanner-Layer:1`
- **Final Layer**: `arn:aws:lambda:us-east-1:390402580689:layer:DevSecOpsSentinel-Final:3`
- **API Gateway**: `https://lbxly3f2e3.execute-api.us-east-1.amazonaws.com/prod/webhook`

### Contact Information
- **System Owner**: DevSecOps Team
- **Emergency Contact**: On-call rotation
- **Documentation**: This guide + inline code comments

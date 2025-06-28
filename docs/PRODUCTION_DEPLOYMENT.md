# DevSecOps Sentinel - Production Deployment Guide

## 🚀 Production Setup Overview

This guide covers the complete production deployment of DevSecOps Sentinel with enhanced security scanning capabilities, including both primary security tools and robust fallback detection systems.

## 📋 Prerequisites

- **Docker Desktop** with WSL 2 backend (for building scanner layer)
- **AWS CLI** configured with appropriate permissions
- **SAM CLI** installed and configured
- **PowerShell** (for Windows deployment scripts)

## 🏗️ Production Architecture

### Enhanced Scanner Layer
The production deployment uses a comprehensive Lambda layer containing:

- **Primary Security Tools:**
  - `trufflehog` - Advanced secret detection
  - `npm` - Node.js vulnerability scanning  
  - `safety` - Python vulnerability scanning
  - `git` - Version control operations

- **Fallback Detection Systems:**
  - Pattern-based secret detection (10+ secret types)
  - CVE database for Python vulnerabilities (10+ packages)
  - CVE database for Node.js vulnerabilities (12+ packages)

### Layer Specifications
- **Size**: ~77MB (full production layer)
- **Runtime**: Python 3.11
- **Location**: `/opt/bin/` for executables, `/opt/python/` for Python packages
- **PATH**: Automatically configured to include `/opt/bin/`

## 🔧 Deployment Steps

### Step 1: Build Full Scanner Layer

```powershell
# Build the complete scanner layer with all security tools
.\scripts\build-scanner-layer.ps1
```

**What this does:**
- Creates Amazon Linux 2023 Docker container
- Installs git, Node.js, npm, Python, pip
- Downloads and installs trufflehog binary
- Installs Python safety package
- Creates properly structured Lambda layer zip (~77MB)

### Step 2: Deploy to AWS

```powershell
# Deploy the complete application stack
.\scripts\deploy.ps1
```

**What this does:**
- Uploads scanner layer to S3 (due to 50MB Lambda limit)
- Creates new layer version in AWS Lambda
- Updates all Lambda functions to use the new layer
- Deploys CloudFormation stack with latest code

### Step 3: Verify Deployment

Check that the layer is properly attached:

```bash
aws lambda get-function --function-name devsecops-sentinel-SecretScannerFunction-XXXXX --query "Configuration.Layers"
```

Expected output should show the scanner layer with ~77MB size.

## 🔍 Production Features

### Hybrid Detection System

The production system uses a sophisticated hybrid approach:

1. **Primary Tools First**: Attempts to use industry-standard tools
   - trufflehog for secrets
   - npm audit for Node.js vulnerabilities  
   - safety for Python vulnerabilities

2. **Fallback Detection**: When primary tools fail or find nothing
   - Pattern-based secret detection with 10+ secret types
   - Known CVE database with 22+ vulnerable package versions
   - Comprehensive logging for debugging

3. **Enhanced Reporting**: Professional analysis reports with
   - Tool availability status
   - Categorized findings (Critical/High/Medium/Low)
   - Actionable recommendations
   - Commit-specific analysis

### Secret Detection Capabilities

**Primary Tool (trufflehog):**
- 700+ built-in detectors
- Real-time verification
- Low false positive rate
- Industry-standard accuracy

**Fallback Patterns:**
- API Keys, Secret Keys, Database Passwords
- GitHub tokens, AWS credentials, JWT secrets
- OpenAI, SendGrid, Stripe keys
- Connection strings and more

### Vulnerability Detection Capabilities

**Primary Tools:**
- `npm audit` for Node.js packages
- `safety` for Python packages
- Real-time vulnerability databases

**Fallback CVE Database:**
- **Python**: django, requests, pillow, pyyaml, urllib3, jinja2, flask, etc.
- **Node.js**: lodash, moment, express, axios, jquery, webpack, debug, etc.
- **Coverage**: 22+ commonly vulnerable packages with known CVEs

## 📊 Monitoring and Logging

### CloudWatch Logs

Monitor the following log groups:
- `/aws/lambda/devsecops-sentinel-SecretScannerFunction-*`
- `/aws/lambda/devsecops-sentinel-VulnerabilityScannerFunction-*`
- `/aws/lambda/devsecops-sentinel-AggregatorFunction-*`

### Key Log Messages

**Successful Tool Execution:**
```
[INFO] Running trufflehog from /opt/bin/trufflehog on /tmp/...
[INFO] Git found at: /opt/bin/git
[INFO] Trufflehog return code: 0
```

**Fallback Activation:**
```
[INFO] Trufflehog found no secrets, trying fallback pattern detection...
[INFO] Fallback detection found API Key in file.txt:5
[INFO] Total secrets found: 2
```

**Tool Availability Issues:**
```
[WARNING] Trufflehog tool not found. Returning tool error finding.
[INFO] npm tool not available - using fallback vulnerability detection
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Tools Not Found
**Symptoms:** "tool not found" warnings in logs
**Solution:** 
- Verify layer is attached with correct version
- Check PATH environment variable includes `/opt/bin/`
- Rebuild and redeploy scanner layer

#### 2. Layer Size Limits
**Symptoms:** Layer upload failures
**Solution:**
- Use S3 upload method for layers >50MB
- Script automatically handles this for production layer

#### 3. Permission Issues
**Symptoms:** Tool execution failures
**Solution:**
- Verify Lambda execution role has required permissions
- Check file permissions in layer (should be executable)

### Debugging Commands

```bash
# Check layer contents
aws lambda get-layer-version --layer-name DevSecOpsSentinel-Scanner --version-number 8

# View recent logs
aws logs filter-log-events --log-group-name "/aws/lambda/devsecops-sentinel-SecretScannerFunction-*" --start-time $(date -d '1 hour ago' +%s)000

# Test webhook
curl -X POST https://your-api-gateway-url/prod/webhook \
  -H "Content-Type: application/json" \
  -d '{"test": true}'
```

## 🔄 Maintenance

### Regular Updates

1. **Monthly**: Update scanner layer with latest tool versions
2. **Quarterly**: Review and update fallback CVE databases
3. **As needed**: Update secret detection patterns

### Layer Updates

```powershell
# Rebuild with latest tools
.\scripts\build-scanner-layer.ps1

# Deploy updated layer
.\scripts\deploy.ps1
```

### Fallback Database Updates

Edit the vulnerability scanner fallback databases in:
- `src/lambdas/vulnerability_scanner/app.py`
- Functions: `scan_python_dependencies_fallback()` and `scan_node_dependencies_fallback()`

## 📈 Performance Metrics

### Expected Performance
- **Secret Scanning**: 2-15 seconds per repository
- **Vulnerability Scanning**: 1-5 seconds per repository  
- **Memory Usage**: 200-500MB per function
- **Layer Size**: ~77MB (production), ~8MB (minimal)

### Scaling Considerations
- Lambda functions auto-scale based on webhook volume
- Consider increasing memory allocation for large repositories
- Monitor CloudWatch metrics for optimization opportunities

## 🔐 Security Best Practices

1. **Layer Security**: Regularly update scanner tools for latest security patches
2. **Access Control**: Limit Lambda execution role permissions to minimum required
3. **Secrets Management**: Use AWS Secrets Manager for GitHub tokens
4. **Monitoring**: Set up CloudWatch alarms for function failures
5. **Backup**: Maintain versioned layers for rollback capability

---

*For additional support, see the [troubleshooting guide](TROUBLESHOOTING.md) or [contact the development team](mailto:support@example.com).*

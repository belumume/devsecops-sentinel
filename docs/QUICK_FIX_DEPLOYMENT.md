# Quick Fix Deployment Guide

## Immediate Fix for Secret Scanner Missing Test Secrets

This guide provides the fastest path to fix the secret scanner that's missing test secrets like `AKIAIOSFODNN7EXAMPLE`.

### Option 1: Quick Configuration Change (5 minutes)

1. **Update Lambda Environment Variable**
   ```bash
   aws lambda update-function-configuration \
     --function-name SecretScannerFunctionFixed \
     --environment Variables={ENABLE_FALLBACK_DETECTION=always,GITHUB_TOKEN_SECRET_NAME=DevSecOpsSentinel/GitHubToken,PATH=/opt/bin:/usr/local/bin:/usr/bin:/bin,SCAN_MODE=comprehensive}
   ```

2. **Test the Change**
   - Trigger a rescan on PR #34 in sentinel-testbed
   - Verify secrets are now detected

### Option 2: SAM Deployment with Enhanced Config (10 minutes)

1. **Ensure Latest Code**
   ```bash
   git pull origin main
   ```

2. **Build and Deploy**
   ```bash
   sam build --use-container
   sam deploy --no-confirm-changeset
   ```

3. **Verify Deployment**
   ```bash
   aws lambda get-function-configuration --function-name SecretScannerFunctionFixed \
     --query 'Environment.Variables'
   ```

### Option 3: Full Enhanced Layer Deployment (30 minutes)

1. **Build Enhanced Layer** (if not using existing layers)
   ```bash
   # Linux/WSL
   ./scripts/build-enhanced-layer.sh
   
   # Windows PowerShell
   .\scripts\build-enhanced-layer.ps1
   ```

2. **Upload Layer to S3**
   ```bash
   aws s3 cp enhanced-scanner-layer.zip s3://devsecops-sentinel-artifacts/layers/
   ```

3. **Create Lambda Layer**
   ```bash
   aws lambda publish-layer-version \
     --layer-name enhanced-scanner-layer \
     --content S3Bucket=devsecops-sentinel-artifacts,S3Key=layers/enhanced-scanner-layer.zip \
     --compatible-runtimes python3.11 \
     --description "Enhanced secret scanner with GitLeaks, Semgrep, and custom rules"
   ```

4. **Update Lambda Function**
   ```bash
   # Get the new layer ARN from previous command output
   LAYER_ARN="arn:aws:lambda:us-east-1:ACCOUNT:layer:enhanced-scanner-layer:1"
   
   # Update function to use new layer
   aws lambda update-function-configuration \
     --function-name SecretScannerFunctionFixed \
     --layers \
       "arn:aws:lambda:us-east-1:390402580689:layer:DevSecOps-Scanner-Layer:2" \
       "arn:aws:lambda:us-east-1:390402580689:layer:DevSecOpsSentinel-Final:3" \
       "$LAYER_ARN"
   ```

### Verification Steps

1. **Check Lambda Logs**
   ```bash
   aws logs tail "/aws/lambda/SecretScannerFunctionFixed" --follow
   ```

2. **Trigger Test Scan**
   - Comment on PR: `/sentinel rescan`
   - Or push a new commit to the test PR

3. **Expected Results**
   You should now see:
   - 9+ secrets detected (including test secrets)
   - Multiple tools reporting findings
   - Higher confidence scores

### Troubleshooting

**Issue: Still not detecting secrets**
- Check CloudWatch logs for errors
- Verify `ENABLE_FALLBACK_DETECTION=always`
- Ensure Lambda has sufficient memory (1024MB)

**Issue: Lambda timeout**
- Increase timeout to 300 seconds
- Consider using `SCAN_MODE=fast` for quick scans

**Issue: Layer too large**
- Use existing comprehensive layers
- Or build minimal layer with just GitLeaks

### Rollback Plan

If issues occur:
```bash
# Revert environment variables
aws lambda update-function-configuration \
  --function-name SecretScannerFunctionFixed \
  --environment Variables={ENABLE_FALLBACK_DETECTION=auto,GITHUB_TOKEN_SECRET_NAME=DevSecOpsSentinel/GitHubToken,PATH=/opt/bin:/usr/local/bin:/usr/bin:/bin}

# Or redeploy previous version
sam deploy --parameter-overrides ParameterKey=CodeVersion,ParameterValue=previous
```

### Long-term Solution

After immediate fix:
1. Build and test enhanced layer thoroughly
2. Update all scanner functions
3. Enable AWS integration for cloud-native detection
4. Set up monitoring dashboards
5. Create custom rules for your organization

### Support

If you encounter issues:
1. Check CloudWatch logs
2. Review `docs/ENHANCED_SECRET_SCANNER.md`
3. Open an issue with logs and error messages 
# Scanner Tools Fix Guide

## Issue Summary

The vulnerability and secret scanners are returning 0 findings because the required scanning tools (npm, safety, trufflehog) are not available in the Lambda environment.

### Root Causes:
1. The Lambda layer doesn't include the actual scanner binaries
2. The `build-scanner-layer.ps1` script requires Docker and Linux environment to build properly
3. The current deployment is using a minimal layer with only Python dependencies

## Solution Options

### Option 1: Deploy with Proper Scanner Layer (Recommended)

1. **Use the new deployment script:**
   ```powershell
   .\scripts\deploy-with-scanner-layer.ps1
   ```

2. **For full scanner functionality**, build the scanner layer on a Linux system:
   - Use WSL2, Docker, or an EC2 instance
   - Run `./scripts/build-scanner-layer.sh`
   - Deploy the resulting `scanner-layer.zip`

### Option 2: Use Cloud9 or EC2 for Layer Building

1. Launch an Amazon Linux 2 EC2 instance or Cloud9 environment
2. Clone your repository
3. Run:
   ```bash
   cd /path/to/devsecops-sentinel
   ./scripts/build-scanner-layer.sh
   aws lambda publish-layer-version \
     --layer-name DevSecOpsSentinel-Scanner \
     --zip-file fileb://scanner-layer.zip \
     --compatible-runtimes python3.11
   ```
4. Copy the Layer ARN and redeploy your SAM stack with it

### Option 3: Use Pre-built Layer (Quickest)

Use this pre-built layer ARN (example - you'd need to create this):
```
arn:aws:lambda:us-east-1:123456789012:layer:DevSecOpsSentinel-Scanner:1
```

Deploy with:
```powershell
sam deploy --parameter-overrides ScannerLayerArn=<LAYER_ARN>
```

## What the Scanner Layer Should Contain

```
/opt/
├── bin/
│   ├── trufflehog      # Secret detection
│   ├── git             # Required by trufflehog
│   ├── npm             # Node.js vulnerability scanning
│   └── safety          # Python vulnerability scanning
└── python/
    ├── requests/
    └── other dependencies...
```

## Verifying the Fix

After deployment, create a test PR with:
- Hardcoded secrets (AWS keys, passwords)
- Vulnerable dependencies in requirements.txt or package.json

The scanners should now report actual findings instead of "Clean" status.

## Temporary Workaround

The updated scanner code now handles missing tools gracefully by:
1. Checking multiple paths for tools
2. Returning warning messages when tools are missing
3. Showing "tool_error" findings instead of silently failing

This ensures users know when scanning isn't working properly. 
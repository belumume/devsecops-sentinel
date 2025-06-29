# Build Enhanced Lambda Layer with Multiple Security Tools
# PowerShell script for Windows users

$ErrorActionPreference = "Stop"

Write-Host "🚀 Building Enhanced Security Scanner Layer..." -ForegroundColor Green

# Configuration
$LAYER_NAME = "enhanced-scanner-layer"
$BUILD_DIR = "build\$LAYER_NAME"
$LAYER_DIR = "$BUILD_DIR\opt\bin"
$PYTHON_DIR = "$BUILD_DIR\python"
$OUTPUT_ZIP = "$LAYER_NAME.zip"

# Tool versions
$TRUFFLEHOG_VERSION = "3.89.2"
$GITLEAKS_VERSION = "8.20.1"
$SEMGREP_VERSION = "1.99.0"

# Architecture (x86_64 for Lambda)
$ARCH = "amd64"

# Clean build directory
if (Test-Path $BUILD_DIR) {
    Remove-Item -Recurse -Force $BUILD_DIR
}
New-Item -ItemType Directory -Path $LAYER_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $PYTHON_DIR -Force | Out-Null

Write-Host "📦 Installing security scanning tools..." -ForegroundColor Yellow

# 1. Install TruffleHog
Write-Host "🐷 Installing TruffleHog v$TRUFFLEHOG_VERSION..." -ForegroundColor Cyan
$trufflehogUrl = "https://github.com/trufflesecurity/trufflehog/releases/download/v$TRUFFLEHOG_VERSION/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz"
Invoke-WebRequest -Uri $trufflehogUrl -OutFile "$env:TEMP\trufflehog.tar.gz"

# Extract using WSL if available, otherwise use 7-Zip
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    wsl tar -xzf /mnt/c/Users/$env:USERNAME/AppData/Local/Temp/trufflehog.tar.gz -C /mnt/c/Users/$env:USERNAME/DEV/devsecops-sentinel/$LAYER_DIR trufflehog
} else {
    # Assume 7-Zip is installed
    & "C:\Program Files\7-Zip\7z.exe" x "$env:TEMP\trufflehog.tar.gz" -o"$env:TEMP" -y
    & "C:\Program Files\7-Zip\7z.exe" x "$env:TEMP\trufflehog.tar" -o"$LAYER_DIR" -y
}

# 2. Install GitLeaks
Write-Host "🔍 Installing GitLeaks v$GITLEAKS_VERSION..." -ForegroundColor Cyan
$gitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
Invoke-WebRequest -Uri $gitleaksUrl -OutFile "$env:TEMP\gitleaks.tar.gz"

if (Get-Command wsl -ErrorAction SilentlyContinue) {
    wsl tar -xzf /mnt/c/Users/$env:USERNAME/AppData/Local/Temp/gitleaks.tar.gz -C /mnt/c/Users/$env:USERNAME/DEV/devsecops-sentinel/$LAYER_DIR gitleaks
} else {
    & "C:\Program Files\7-Zip\7z.exe" x "$env:TEMP\gitleaks.tar.gz" -o"$env:TEMP" -y
    & "C:\Program Files\7-Zip\7z.exe" x "$env:TEMP\gitleaks.tar" -o"$LAYER_DIR" -y
}

# 3. Install Semgrep (using pip in WSL)
Write-Host "🔎 Installing Semgrep v$SEMGREP_VERSION..." -ForegroundColor Cyan
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    wsl pip install --target /mnt/c/Users/$env:USERNAME/DEV/devsecops-sentinel/$PYTHON_DIR "semgrep==$SEMGREP_VERSION"
} else {
    Write-Host "⚠️  WSL not found. Installing Semgrep requires WSL or Linux environment." -ForegroundColor Yellow
}

# Create wrapper script for Semgrep
$semgrepWrapper = @'
#!/bin/bash
export PYTHONPATH=/opt/python:$PYTHONPATH
python -m semgrep "$@"
'@
$semgrepWrapper | Out-File -FilePath "$LAYER_DIR\semgrep" -Encoding UTF8 -NoNewline

# 4. Install additional Python packages
Write-Host "📚 Installing Python dependencies..." -ForegroundColor Cyan
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    wsl pip install --target /mnt/c/Users/$env:USERNAME/DEV/devsecops-sentinel/$PYTHON_DIR detect-secrets safety bandit whispers
}

# 5. Add custom detection rules
Write-Host "📋 Adding custom detection rules..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path "$BUILD_DIR\opt\rules" -Force | Out-Null

# GitLeaks custom config
$gitleaksConfig = @'
# Custom GitLeaks configuration for enhanced detection
title = "Enhanced GitLeaks Config"

[[rules]]
description = "Generic API Key"
regex = '''(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{16,})'''
tags = ["key", "API", "generic"]

[[rules]]
description = "Generic Secret"
regex = '''(?i)(secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\"'\s]{8,})'''
tags = ["secret", "password"]

[[rules]]
description = "High Entropy String"
regex = '''[\"']([a-zA-Z0-9+/]{40,})[\"']'''
entropy = 4.5
tags = ["entropy"]

[[rules]]
description = "Test Secrets (Include)"
regex = '''(AKIA[0-9A-Z]{16}|sk_test_[a-zA-Z0-9]{24,}|ghp_[a-zA-Z0-9]{36,})'''
tags = ["test", "secret"]
'@
$gitleaksConfig | Out-File -FilePath "$BUILD_DIR\opt\rules\gitleaks.toml" -Encoding UTF8

# Semgrep rules
New-Item -ItemType Directory -Path "$BUILD_DIR\opt\rules\semgrep" -Force | Out-Null
$semgrepRules = @'
rules:
  - id: hardcoded-secret
    patterns:
      - pattern-either:
          - pattern: $KEY = "..."
          - pattern: $KEY = '...'
      - metavariable-regex:
          metavariable: $KEY
          regex: '.*(password|secret|key|token|credential).*'
      - metavariable-regex:
          metavariable: '...'
          regex: '.{8,}'
    message: Hardcoded secret detected
    languages: [python, javascript, java, go, ruby]
    severity: ERROR

  - id: test-api-keys
    patterns:
      - pattern-regex: '(AKIA[0-9A-Z]{16}|sk_test_[a-zA-Z0-9]{24,}|ghp_[a-zA-Z0-9]{36,})'
    message: Test API key detected (should be caught)
    languages: [generic]
    severity: ERROR
'@
$semgrepRules | Out-File -FilePath "$BUILD_DIR\opt\rules\semgrep\custom-secrets.yaml" -Encoding UTF8

# 6. Create tool orchestrator script
$orchestratorScript = @'
#!/bin/bash
# Multi-tool secret scanner orchestrator

TARGET="$1"
OUTPUT_FORMAT="${2:-json}"

echo "🔍 Running multi-tool secret scan on ${TARGET}..."

# Run all tools in parallel and collect results
{
    echo "=== TruffleHog Results ==="
    /opt/bin/trufflehog filesystem "$TARGET" --json --no-update --include-detectors=all --only-verified=false 2>/dev/null || true
    
    echo "=== GitLeaks Results ==="
    /opt/bin/gitleaks detect --source "$TARGET" --config /opt/rules/gitleaks.toml -f json --no-git 2>/dev/null || true
    
    echo "=== Semgrep Results ==="
    /opt/bin/semgrep --config=/opt/rules/semgrep --json "$TARGET" 2>/dev/null || true
} | jq -s '.'
'@
$orchestratorScript | Out-File -FilePath "$LAYER_DIR\scan-secrets" -Encoding UTF8 -NoNewline

# 7. Package the layer
Write-Host "📦 Creating layer package..." -ForegroundColor Yellow

# Use WSL to create Linux-compatible zip if available
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    Push-Location $BUILD_DIR
    wsl zip -r9 ../../$OUTPUT_ZIP .
    Pop-Location
} else {
    # Use PowerShell compression (may have compatibility issues)
    Compress-Archive -Path "$BUILD_DIR\*" -DestinationPath $OUTPUT_ZIP -Force
    Write-Host "⚠️  Note: ZIP created with PowerShell may have Linux compatibility issues" -ForegroundColor Yellow
}

# Calculate size
$layerSize = (Get-Item $OUTPUT_ZIP).Length / 1MB
Write-Host "✅ Enhanced scanner layer built successfully!" -ForegroundColor Green
Write-Host "📏 Layer size: $([math]::Round($layerSize, 2)) MB" -ForegroundColor Cyan
Write-Host "📍 Output: $OUTPUT_ZIP" -ForegroundColor Cyan

# List contents
Write-Host "`n🔍 Layer contents:" -ForegroundColor Yellow
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    wsl unzip -l $OUTPUT_ZIP | grep -E "(trufflehog|gitleaks|semgrep|scan-secrets)" | head -10
}

Write-Host "`n🚀 Next steps:" -ForegroundColor Green
Write-Host "1. Upload to S3: aws s3 cp $OUTPUT_ZIP s3://your-bucket/" -ForegroundColor White
Write-Host "2. Create layer: aws lambda publish-layer-version --layer-name $LAYER_NAME --content S3Bucket=your-bucket,S3Key=$OUTPUT_ZIP" -ForegroundColor White
Write-Host "3. Update your Lambda functions to use the new layer" -ForegroundColor White

Write-Host "`n💡 Tip: For best results, run this script in WSL for Linux compatibility" -ForegroundColor Yellow 
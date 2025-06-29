#!/bin/bash

# Build Enhanced Lambda Layer with Multiple Security Tools
# This script creates a comprehensive security scanning layer with multiple tools

set -e

echo "🚀 Building Enhanced Security Scanner Layer..."

# Configuration
LAYER_NAME="enhanced-scanner-layer"
BUILD_DIR="build/${LAYER_NAME}"
LAYER_DIR="${BUILD_DIR}/opt/bin"
PYTHON_DIR="${BUILD_DIR}/python"
OUTPUT_ZIP="${LAYER_NAME}.zip"

# Tool versions
TRUFFLEHOG_VERSION="3.89.2"
GITLEAKS_VERSION="8.20.1"
SEMGREP_VERSION="1.99.0"

# Architecture (x86_64 for Lambda)
ARCH="amd64"

# Clean build directory
rm -rf ${BUILD_DIR}
mkdir -p ${LAYER_DIR}
mkdir -p ${PYTHON_DIR}

echo "📦 Installing security scanning tools..."

# 1. Install TruffleHog
echo "🐷 Installing TruffleHog v${TRUFFLEHOG_VERSION}..."
wget -q "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz" -O /tmp/trufflehog.tar.gz
tar -xzf /tmp/trufflehog.tar.gz -C ${LAYER_DIR} trufflehog
chmod +x ${LAYER_DIR}/trufflehog

# 2. Install GitLeaks
echo "🔍 Installing GitLeaks v${GITLEAKS_VERSION}..."
wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -O /tmp/gitleaks.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C ${LAYER_DIR} gitleaks
chmod +x ${LAYER_DIR}/gitleaks

# 3. Install Semgrep
echo "🔎 Installing Semgrep v${SEMGREP_VERSION}..."
# Semgrep is Python-based, install via pip
pip install --target ${PYTHON_DIR} "semgrep==${SEMGREP_VERSION}"

# Create a wrapper script for Semgrep since it's Python-based
cat > ${LAYER_DIR}/semgrep << 'EOF'
#!/bin/bash
export PYTHONPATH=/opt/python:$PYTHONPATH
python -m semgrep "$@"
EOF
chmod +x ${LAYER_DIR}/semgrep

# 4. Install additional Python packages for enhanced detection
echo "📚 Installing Python dependencies..."
pip install --target ${PYTHON_DIR} \
    detect-secrets \
    safety \
    bandit \
    whispers

# 5. Add custom detection rules
echo "📋 Adding custom detection rules..."
mkdir -p ${BUILD_DIR}/opt/rules

# GitLeaks custom config
cat > ${BUILD_DIR}/opt/rules/gitleaks.toml << 'EOF'
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
EOF

# Semgrep rules
mkdir -p ${BUILD_DIR}/opt/rules/semgrep
cat > ${BUILD_DIR}/opt/rules/semgrep/custom-secrets.yaml << 'EOF'
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
EOF

# 6. Create tool orchestrator script
cat > ${LAYER_DIR}/scan-secrets << 'EOF'
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
EOF
chmod +x ${LAYER_DIR}/scan-secrets

# 7. Add Git (required by some tools)
echo "🔧 Adding Git..."
# Download portable Git
wget -q "https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/PortableGit-2.44.0-64-bit.7z.exe" -O /tmp/git-portable.7z || {
    # Fallback: compile minimal Git
    echo "Compiling minimal Git..."
    cd /tmp
    wget -q https://github.com/git/git/archive/v2.44.0.tar.gz
    tar -xzf v2.44.0.tar.gz
    cd git-2.44.0
    make configure
    ./configure --prefix=${BUILD_DIR}/opt --without-tcltk --without-python --without-expat
    make -j$(nproc) NO_GETTEXT=1 NO_TCLTK=1
    make install NO_GETTEXT=1 NO_TCLTK=1
    cd -
}

# 8. Package the layer
echo "📦 Creating layer package..."
cd ${BUILD_DIR}
zip -r9 ../../${OUTPUT_ZIP} .
cd ../..

# Calculate size
LAYER_SIZE=$(du -h ${OUTPUT_ZIP} | cut -f1)
echo "✅ Enhanced scanner layer built successfully!"
echo "📏 Layer size: ${LAYER_SIZE}"
echo "📍 Output: ${OUTPUT_ZIP}"

# Verify tools
echo ""
echo "🔍 Verifying tools in layer..."
unzip -l ${OUTPUT_ZIP} | grep -E "(trufflehog|gitleaks|semgrep|scan-secrets)" | head -10

echo ""
echo "🚀 Next steps:"
echo "1. Upload to S3: aws s3 cp ${OUTPUT_ZIP} s3://your-bucket/"
echo "2. Create layer: aws lambda publish-layer-version --layer-name ${LAYER_NAME} --content S3Bucket=your-bucket,S3Key=${OUTPUT_ZIP}"
echo "3. Update your Lambda functions to use the new layer" 
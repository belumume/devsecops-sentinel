#!/bin/bash
# Script to build a Lambda layer with multiple security scanning tools

set -e

# Create layer directory structure
mkdir -p scanner-layer/bin
cd scanner-layer

# Download and install TruffleHog
echo "Installing TruffleHog..."
wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.89.2/trufflehog_3.89.2_linux_amd64.tar.gz
tar -xzf trufflehog_3.89.2_linux_amd64.tar.gz -C bin/
rm trufflehog_3.89.2_linux_amd64.tar.gz

# Download and install GitLeaks
echo "Installing GitLeaks..."
wget https://github.com/gitleaks/gitleaks/releases/download/v8.21.3/gitleaks_8.21.3_linux_x64.tar.gz
tar -xzf gitleaks_8.21.3_linux_x64.tar.gz -C bin/
rm gitleaks_8.21.3_linux_x64.tar.gz

# Download and install Semgrep (Python-based, needs different approach)
echo "Installing Semgrep..."
# Semgrep requires Python, so it would need to be in a Python layer
# or installed via pip in the Lambda function

# Download git (required for repository operations)
echo "Installing git..."
# Git is more complex - would need to compile or use Amazon Linux 2 container

# Create the layer zip
cd ..
zip -r scanner-layer.zip scanner-layer/

echo "Layer created: scanner-layer.zip"
echo "Upload this to AWS Lambda as a layer" 
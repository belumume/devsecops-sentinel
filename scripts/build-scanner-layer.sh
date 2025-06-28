#!/bin/bash

# This script builds a Lambda layer containing git, trufflehog, safety, and npm for the DevSecOps Sentinel project.
# It should be run from the root of the project directory.

set -eo pipefail

# Ensure Docker is running
if ! docker info > /dev/null 2>&1; then
  echo "Docker does not seem to be running, please start it and try again." >&2
  exit 1
fi

LAYER_DIR="./scanner-layer"

echo "Creating temporary directory for layer contents..."
rm -rf "${LAYER_DIR}"
mkdir -p "${LAYER_DIR}/bin"
mkdir -p "${LAYER_DIR}/python/lib/python3.9/site-packages"

# --- Build with Amazon Linux 2023 Docker container ---
echo "Building layer using Amazon Linux 2023 container..."

docker run --rm -v "$(pwd)/${LAYER_DIR}:/layer" public.ecr.aws/amazonlinux/amazonlinux:2023 bash -c "
set -ex

yum update -y
# CORRECTED: Added 'tar' to the install list
yum install -y git zip python3-pip nodejs tar

# Install trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/bin

# Install Python dependencies for Python 3.9 (Lambda runtime)
pip3 install safety -t /layer/python/lib/python3.9/site-packages

# Copy binaries to the layer's bin directory
cp /usr/bin/git /layer/bin/
cp /usr/bin/trufflehog /layer/bin/
cp /usr/bin/node /layer/bin/
cp /usr/bin/npm /layer/bin/

# Also create a safety executable script since pip installs it as a module
cat > /layer/bin/safety << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '/opt/python/lib/python3.9/site-packages')
from safety.cli import cli
if __name__ == '__main__':
    cli()
EOF
chmod +x /layer/bin/safety

# Zip the layer contents
cd /layer
zip -r9 /layer/scanner-layer.zip ./*
"

# Move the zip file to the root
mv "${LAYER_DIR}/scanner-layer.zip" ./scanner-layer.zip

# Clean up
rm -rf "${LAYER_DIR}"

echo ""
echo "✅ Lambda layer created successfully: scanner-layer.zip"
echo "You can now upload this to AWS."

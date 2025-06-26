# This script builds a Lambda layer containing git, trufflehog, safety, and npm for the DevSecOps Sentinel project.
# It requires Docker Desktop with the WSL 2 backend to be running.
# It should be run from the root of the project directory using PowerShell.

# Ensure Docker is running
if (-not (docker info 2>$null)) {
    Write-Error "Docker does not seem to be running, please start it and try again."
    exit 1
}

$LayerDir = ".\scanner-layer"

Write-Host "Creating temporary directory for layer contents..."
if (Test-Path $LayerDir) {
    Remove-Item -Recurse -Force $LayerDir
}
New-Item -ItemType Directory -Path "$LayerDir\bin" | Out-Null
New-Item -ItemType Directory -Path "$LayerDir\python\lib\python3.11\site-packages" | Out-Null

# --- Build with Amazon Linux 2023 Docker container ---
Write-Host "Building layer using Amazon Linux 2023 container..."

# CORRECTED: Added 'tar' to the yum install command
$DockerCommand = "`
set -ex;`
`
yum update -y;`
`
yum install -y git zip python3-pip nodejs tar;`
`
# Install trufflehog;`
`
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/bin;`
`
# Install Python dependencies;`
`
pip3 install safety -t /layer/python/lib/python3.11/site-packages;`
`
# Copy binaries to the layer's bin directory;`
`
cp /usr/bin/git /layer/bin/;`
`
cp /usr/bin/trufflehog /layer/bin/;`
`
cp /usr/bin/node /layer/bin/;`
`
cp /usr/bin/npm /layer/bin/;`
`
# Zip the layer contents;`
`
cd /layer;`
`
zip -r9 /layer/scanner-layer.zip ./*;`
"

docker run --rm -v "${PWD}\${LayerDir}:/layer" public.ecr.aws/amazonlinux/amazonlinux:2023 bash -c $DockerCommand

# Move the zip file to the root
Move-Item -Path "$LayerDir\scanner-layer.zip" -Destination ".\scanner-layer.zip" -Force

# Clean up
Remove-Item -Recurse -Force $LayerDir

Write-Host ""
Write-Host "✅ Lambda layer created successfully: scanner-layer.zip"
Write-Host "You can now upload this to AWS."

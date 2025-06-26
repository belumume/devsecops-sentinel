# Build minimal Lambda layer for hackathon demo - API-based scanning approach
# This is optimized for quick deployment and reliable operation

Write-Host "Building Minimal DevSecOps Sentinel Scanner Layer..." -ForegroundColor Green

# Create layer directory structure
$LAYER_DIR = "minimal-scanner-layer"
Remove-Item -Recurse -Force $LAYER_DIR -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$LAYER_DIR\python"

# Install only essential dependencies for API-based scanning
Write-Host "Installing minimal Python dependencies..." -ForegroundColor Yellow
pip install --target "$LAYER_DIR\python" requests boto3

# Create layer zip
Write-Host "Creating minimal layer zip..." -ForegroundColor Yellow
Compress-Archive -Path "$LAYER_DIR\*" -DestinationPath "minimal-scanner-layer.zip" -Force

# Show size
$size = (Get-Item "minimal-scanner-layer.zip").Length / 1MB
Write-Host "Minimal layer size: $($size.ToString("F2")) MB" -ForegroundColor Green

Write-Host "Ready to deploy with:" -ForegroundColor Cyan
Write-Host "aws lambda publish-layer-version --layer-name DevSecOpsSentinel-Scanner --description 'Minimal scanner layer' --zip-file fileb://minimal-scanner-layer.zip --compatible-runtimes python3.11" -ForegroundColor Yellow 
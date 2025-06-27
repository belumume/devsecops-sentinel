# Build Scanner Layer using WSL2
# This script runs the Linux build script inside WSL to create the full scanner layer

Write-Host "🚀 Building DevSecOps Sentinel Scanner Layer using WSL2..." -ForegroundColor Green

# Check if WSL is available
try {
    wsl --status | Out-Null
} catch {
    Write-Host "❌ WSL2 is not installed or not available." -ForegroundColor Red
    Write-Host "Please install WSL2 first: https://learn.microsoft.com/en-us/windows/wsl/install" -ForegroundColor Yellow
    exit 1
}

# Get the current directory in WSL format
$currentDir = Get-Location
$wslPath = "/mnt/" + $currentDir.Path.ToLower().Replace(":\", "/").Replace("\", "/")

Write-Host "📁 Project path in WSL: $wslPath" -ForegroundColor Yellow

# Run the build script in WSL
Write-Host "`n🔨 Running build script in WSL..." -ForegroundColor Blue
$buildCommand = @"
cd '$wslPath' && \
chmod +x scripts/build-scanner-layer.sh && \
./scripts/build-scanner-layer.sh
"@

# Execute in WSL
wsl bash -c $buildCommand

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Scanner layer built successfully!" -ForegroundColor Green
    
    # Check if the zip file was created
    if (Test-Path "scanner-layer.zip") {
        $size = (Get-Item "scanner-layer.zip").Length / 1MB
        Write-Host "📦 Layer size: $($size.ToString('F2')) MB" -ForegroundColor Cyan
        
        Write-Host "`n📤 Next step: Deploy the layer to AWS" -ForegroundColor Yellow
        Write-Host "Run this command to publish the layer:" -ForegroundColor White
        Write-Host "aws lambda publish-layer-version --layer-name DevSecOpsSentinel-Scanner --description 'Full scanner tools layer' --zip-file fileb://scanner-layer.zip --compatible-runtimes python3.11 --region us-east-1" -ForegroundColor Green
    } else {
        Write-Host "⚠️ scanner-layer.zip not found. Build may have failed." -ForegroundColor Red
    }
} else {
    Write-Host "❌ Build failed. Check the error messages above." -ForegroundColor Red
    exit 1
} 
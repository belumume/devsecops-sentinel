# DevSecOps Sentinel Deployment with Full Scanner Layer
# This script ensures the scanner tools are properly deployed

param(
    [string]$Region = "us-east-1"
)

Write-Host "🚀 DevSecOps Sentinel Deployment with Scanner Tools" -ForegroundColor Green
Write-Host "Region: $Region" -ForegroundColor Yellow

# Step 1: Check if full scanner layer exists
if (Test-Path "scanner-layer.zip") {
    Write-Host "`n📦 Using full scanner layer with tools..." -ForegroundColor Green
    $LayerFile = "scanner-layer.zip"
} else {
    Write-Host "`n📦 Full scanner layer not found, building minimal layer..." -ForegroundColor Yellow
    & "$PSScriptRoot\build-minimal-layer.ps1"
    $LayerFile = "minimal-scanner-layer.zip"
}

# Step 2: Deploy the scanner layer
Write-Host "`n📤 Deploying Lambda layer..." -ForegroundColor Blue
$LayerOutput = aws lambda publish-layer-version `
    --layer-name DevSecOpsSentinel-Scanner `
    --description 'Scanner layer for DevSecOps Sentinel with tools' `
    --zip-file fileb://$LayerFile `
    --compatible-runtimes python3.11 `
    --region $Region `
    --output json

$LayerData = $LayerOutput | ConvertFrom-Json
$LayerArn = $LayerData.LayerVersionArn
Write-Host "✅ Layer deployed: $LayerArn" -ForegroundColor Green

# Step 3: Build SAM application
Write-Host "`n🔨 Building SAM application..." -ForegroundColor Blue
sam build

# Step 4: Deploy with layer ARN
Write-Host "`n🚀 Deploying SAM application with scanner layer..." -ForegroundColor Blue
sam deploy --parameter-overrides "ScannerLayerArn=$LayerArn"

Write-Host "`n✅ Deployment complete!" -ForegroundColor Green
if ($LayerFile -eq "scanner-layer.zip") {
    Write-Host "`n🎉 Full scanner tools deployed successfully!" -ForegroundColor Green
    Write-Host "Your Lambda functions now have access to:" -ForegroundColor Cyan
    Write-Host "  - TruffleHog (secret detection)" -ForegroundColor Cyan
    Write-Host "  - npm audit (Node.js vulnerability scanning)" -ForegroundColor Cyan
    Write-Host "  - safety (Python vulnerability scanning)" -ForegroundColor Cyan
} else {
    Write-Host "`nNote: Using minimal layer without scanner tools." -ForegroundColor Yellow
    Write-Host "Build scanner-layer.zip on Linux for full functionality." -ForegroundColor Yellow
}

# Get the webhook URL
Write-Host "`n🔗 Getting webhook URL..." -ForegroundColor Blue
$WebhookUrl = aws cloudformation describe-stacks `
    --stack-name devsecops-sentinel `
    --query 'Stacks[0].Outputs[?OutputKey==`WebhookApiUrl`].OutputValue' `
    --output text `
    --region $Region

Write-Host "Webhook URL: $WebhookUrl" -ForegroundColor Cyan 
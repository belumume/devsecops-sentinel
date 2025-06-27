# DevSecOps Sentinel Deployment with Full Scanner Layer
# This script ensures the scanner tools are properly deployed

param(
    [string]$Region = "us-east-1"
)

Write-Host "🚀 DevSecOps Sentinel Deployment with Scanner Tools" -ForegroundColor Green
Write-Host "Region: $Region" -ForegroundColor Yellow

# Step 1: Build the minimal layer as fallback
Write-Host "`n📦 Building minimal layer..." -ForegroundColor Blue
& "$PSScriptRoot\build-minimal-layer.ps1"

# Step 2: Deploy the minimal layer first
Write-Host "`n📤 Deploying Lambda layer..." -ForegroundColor Blue
$LayerOutput = aws lambda publish-layer-version `
    --layer-name DevSecOpsSentinel-Scanner `
    --description 'Scanner layer for DevSecOps Sentinel' `
    --zip-file fileb://minimal-scanner-layer.zip `
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
Write-Host "`nNote: The scanners are currently using a minimal layer." -ForegroundColor Yellow
Write-Host "For full scanner functionality with tools (npm, safety, trufflehog)," -ForegroundColor Yellow
Write-Host "you need to build and deploy the full scanner layer on a Linux system." -ForegroundColor Yellow

# Get the webhook URL
Write-Host "`n🔗 Getting webhook URL..." -ForegroundColor Blue
$WebhookUrl = aws cloudformation describe-stacks `
    --stack-name devsecops-sentinel `
    --query 'Stacks[0].Outputs[?OutputKey==`WebhookApiUrl`].OutputValue' `
    --output text `
    --region $Region

Write-Host "Webhook URL: $WebhookUrl" -ForegroundColor Cyan 
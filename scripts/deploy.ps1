# DevSecOps Sentinel Deployment Script
# This script deploys the complete DevSecOps Sentinel application to AWS

param(
    [string]$Region = "us-east-1",
    [switch]$SkipLayer,
    [switch]$Help
)

if ($Help) {
    Write-Host "DevSecOps Sentinel Deployment Script"
    Write-Host ""
    Write-Host "Usage: .\scripts\deploy.ps1 [-Region <region>] [-SkipLayer]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Region     AWS region to deploy to (default: us-east-1)"
    Write-Host "  -SkipLayer  Skip Lambda layer deployment (use if layer already exists)"
    Write-Host "  -Help       Show this help message"
    Write-Host ""
    Write-Host "Prerequisites:"
    Write-Host "  1. AWS CLI configured with appropriate permissions"
    Write-Host "  2. SAM CLI installed"
    Write-Host "  3. GitHub token stored in AWS Secrets Manager as 'DevSecOpsSentinel/GitHubToken'"
    Write-Host "  4. Webhook secret stored in AWS Secrets Manager as 'DevSecOpsSentinel/WebhookSecret'"
    exit 0
}

Write-Host "🚀 DevSecOps Sentinel Deployment Starting..." -ForegroundColor Green
Write-Host "Region: $Region" -ForegroundColor Yellow

# Check prerequisites
Write-Host "📋 Checking prerequisites..." -ForegroundColor Blue

# Check AWS CLI
try {
    aws --version | Out-Null
    Write-Host "✅ AWS CLI found" -ForegroundColor Green
} catch {
    Write-Host "❌ AWS CLI not found. Please install AWS CLI." -ForegroundColor Red
    exit 1
}

# Check SAM CLI
try {
    sam --version | Out-Null
    Write-Host "✅ SAM CLI found" -ForegroundColor Green
} catch {
    Write-Host "❌ SAM CLI not found. Please install SAM CLI." -ForegroundColor Red
    exit 1
}

# Check if scanner layer zip exists
if (-not (Test-Path "scanner-layer.zip")) {
    Write-Host "❌ scanner-layer.zip not found. Please run build-scanner-layer.ps1 first." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Scanner layer zip found" -ForegroundColor Green

$LayerArn = ""

# Deploy Lambda Layer (unless skipped)
if (-not $SkipLayer) {
    Write-Host "📦 Deploying Lambda layer..." -ForegroundColor Blue
    
    try {
        $LayerOutput = aws lambda publish-layer-version `
            --layer-name DevSecOpsSentinel-Scanner `
            --description 'Scanner tools for DevSecOps Sentinel' `
            --zip-file fileb://scanner-layer.zip `
            --compatible-runtimes python3.11 `
            --region $Region `
            --output json
        
        $LayerData = $LayerOutput | ConvertFrom-Json
        $LayerArn = $LayerData.LayerArn
        Write-Host "✅ Lambda layer deployed: $LayerArn" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to deploy Lambda layer: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "⏭️ Skipping Lambda layer deployment" -ForegroundColor Yellow
    
    # Try to get existing layer ARN
    try {
        $LayerOutput = aws lambda list-layer-versions `
            --layer-name DevSecOpsSentinel-Scanner `
            --region $Region `
            --output json
        
        $LayerData = $LayerOutput | ConvertFrom-Json
        if ($LayerData.LayerVersions.Count -gt 0) {
            $LayerArn = $LayerData.LayerVersions[0].LayerArn
            Write-Host "✅ Using existing layer: $LayerArn" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️ Could not find existing layer. Proceeding without layer..." -ForegroundColor Yellow
    }
}

# Build SAM application
Write-Host "🔨 Building SAM application..." -ForegroundColor Blue
try {
    sam build
    Write-Host "✅ SAM build completed" -ForegroundColor Green
} catch {
    Write-Host "❌ SAM build failed: $_" -ForegroundColor Red
    exit 1
}

# Deploy SAM application
Write-Host "🚀 Deploying SAM application..." -ForegroundColor Blue

$DeployParams = @(
    "sam", "deploy"
)

if ($LayerArn) {
    $DeployParams += "--parameter-overrides"
    $DeployParams += "ScannerLayerArn=$LayerArn"
}

try {
    & $DeployParams[0] $DeployParams[1..($DeployParams.Length-1)]
    Write-Host "✅ SAM deployment completed" -ForegroundColor Green
} catch {
    Write-Host "❌ SAM deployment failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🎉 DevSecOps Sentinel deployed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Get the API Gateway URL from the CloudFormation outputs"
Write-Host "2. Configure GitHub webhook to point to the API Gateway URL"
Write-Host "3. Create a test pull request to verify the system works"
Write-Host ""
Write-Host "To get the webhook URL, run:" -ForegroundColor Cyan
Write-Host "aws cloudformation describe-stacks --stack-name devsecops-sentinel --query 'Stacks[0].Outputs[?OutputKey==``WebhookApiUrl``].OutputValue' --output text --region $Region"

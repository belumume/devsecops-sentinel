# Monitor DevSecOps Sentinel Scanner Execution
# This script monitors Step Functions and Lambda logs for scanner activity

param(
    [int]$CheckIntervalSeconds = 30,
    [int]$MaxChecks = 20
)

Write-Host "🔍 Monitoring DevSecOps Sentinel Scanner Execution..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
Write-Host ""

# Get the state machine ARN
$stateMachineArn = aws stepfunctions list-state-machines --query "stateMachines[?contains(name, 'Analysis')].stateMachineArn" --output text

if (-not $stateMachineArn) {
    Write-Host "❌ Could not find Analysis State Machine" -ForegroundColor Red
    exit 1
}

Write-Host "📊 Monitoring State Machine: $stateMachineArn" -ForegroundColor Cyan

# Get initial execution to track
$lastExecution = aws stepfunctions list-executions --state-machine-arn $stateMachineArn --max-results 1 --query 'executions[0].startDate' --output text

$checkCount = 0
while ($checkCount -lt $MaxChecks) {
    $checkCount++
    Write-Host "`n🔄 Check $checkCount of $MaxChecks at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Yellow
    
    # Check for new executions
    $latestExecution = aws stepfunctions list-executions --state-machine-arn $stateMachineArn --max-results 1 --query 'executions[0]' --output json | ConvertFrom-Json
    
    if ($latestExecution.startDate -ne $lastExecution) {
        Write-Host "`n🎉 NEW EXECUTION DETECTED!" -ForegroundColor Green
        Write-Host "Execution Name: $($latestExecution.name)" -ForegroundColor Cyan
        Write-Host "Status: $($latestExecution.status)" -ForegroundColor Cyan
        Write-Host "Started: $($latestExecution.startDate)" -ForegroundColor Cyan
        
        # Wait for execution to complete
        Write-Host "`n⏳ Waiting for execution to complete..." -ForegroundColor Yellow
        $executionArn = $latestExecution.executionArn
        
        do {
            Start-Sleep -Seconds 5
            $status = aws stepfunctions describe-execution --execution-arn $executionArn --query 'status' --output text
            Write-Host "." -NoNewline
        } while ($status -eq "RUNNING")
        
        Write-Host "`n✅ Execution completed with status: $status" -ForegroundColor Green
        
        # Get execution details
        $executionDetails = aws stepfunctions describe-execution --execution-arn $executionArn --output json | ConvertFrom-Json
        
        # Extract PR info from execution name (format: pr-owner-repo-number-hash)
        if ($latestExecution.name -match 'pr-([^-]+)-([^-]+)-(\d+)-') {
            $owner = $Matches[1]
            $repo = $Matches[2]
            $prNumber = $Matches[3]
            
            Write-Host "`n📋 Pull Request Details:" -ForegroundColor Cyan
            Write-Host "Repository: $owner/$repo" -ForegroundColor White
            Write-Host "PR Number: #$prNumber" -ForegroundColor White
            
            # Check secret scanner logs
            Write-Host "`n🔍 Checking Secret Scanner Results..." -ForegroundColor Yellow
            
            # Get the Lambda function name
            $functionName = aws lambda list-functions --query "Functions[?contains(FunctionName, 'SecretScanner')].FunctionName" --output text
            
            if ($functionName) {
                # Get recent logs
                $logGroup = "/aws/lambda/$functionName"
                $endTime = [DateTimeOffset]::Now.ToUnixTimeMilliseconds()
                $startTime = $endTime - (10 * 60 * 1000)  # Last 10 minutes
                
                try {
                    $logs = aws logs filter-log-events `
                        --log-group-name $logGroup `
                        --start-time $startTime `
                        --end-time $endTime `
                        --filter-pattern "found.*secrets OR TruffleHog OR semantic" `
                        --query 'events[*].message' `
                        --output json | ConvertFrom-Json
                    
                    foreach ($log in $logs) {
                        if ($log -match "found (\d+) secrets") {
                            $secretCount = $Matches[1]
                            Write-Host "🔐 Secrets Found: $secretCount" -ForegroundColor $(if ([int]$secretCount -gt 0) { "Red" } else { "Green" })
                        }
                        if ($log -match "TruffleHog found (\d+)") {
                            Write-Host "🐷 TruffleHog: $($Matches[1]) secrets" -ForegroundColor Cyan
                        }
                        if ($log -match "semantic.*found (\d+)") {
                            Write-Host "🧠 Semantic Analysis: $($Matches[1]) secrets" -ForegroundColor Cyan
                        }
                        if ($log -match "ENABLE_FALLBACK_DETECTION.*=.*(\w+)") {
                            Write-Host "⚙️  Fallback Detection: $($Matches[1])" -ForegroundColor Cyan
                        }
                    }
                } catch {
                    Write-Host "Could not retrieve detailed logs" -ForegroundColor Yellow
                }
            }
            
            # Show GitHub PR link
            Write-Host "`n🔗 GitHub PR: https://github.com/$owner/$repo/pull/$prNumber" -ForegroundColor Blue
        }
        
        $lastExecution = $latestExecution.startDate
        
        Write-Host "`n✅ Enhanced scanner verification complete!" -ForegroundColor Green
        Write-Host "Continue monitoring? (Y/N): " -NoNewline
        $continue = Read-Host
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            break
        }
    } else {
        Write-Host "No new executions detected" -ForegroundColor Gray
    }
    
    if ($checkCount -lt $MaxChecks) {
        Write-Host "Next check in $CheckIntervalSeconds seconds..." -ForegroundColor Gray
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
}

Write-Host "`n👋 Monitoring complete!" -ForegroundColor Green 
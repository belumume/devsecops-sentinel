# Run all unit tests individually to avoid path conflicts
Write-Host "Running DevSecOps Sentinel Unit Tests..." -ForegroundColor Green

$testFiles = @(
    "tests/unit/test_webhook_handler.py",
    "tests/unit/test_secret_scanner.py", 
    "tests/unit/test_vulnerability_scanner.py",
    "tests/unit/test_ai_reviewer.py",
    "tests/unit/test_aggregator.py"
)

$totalTests = 0
$passedTests = 0
$failedTests = 0

foreach ($testFile in $testFiles) {
    Write-Host "`nRunning $testFile..." -ForegroundColor Yellow
    
    # Run the test file
    python -m pytest $testFile -v
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ $testFile passed" -ForegroundColor Green
        $passedTests++
    } else {
        Write-Host "✗ $testFile failed" -ForegroundColor Red
        $failedTests++
    }
    $totalTests++
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Summary:" -ForegroundColor Cyan
Write-Host "Total test files: $totalTests" -ForegroundColor White
Write-Host "Passed: $passedTests" -ForegroundColor Green
Write-Host "Failed: $failedTests" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Cyan

if ($failedTests -gt 0) {
    exit 1
} 
# Enhanced Secret Scanner Documentation

## Overview

The Enhanced Secret Scanner is a comprehensive, multi-layered solution for detecting secrets in GitHub pull requests. It addresses the limitation where single tools (like TruffleHog) may miss test secrets or have blind spots by implementing a defense-in-depth approach.

## Problem Statement

The original secret scanner relied primarily on TruffleHog, which was found to:
- Miss test secrets like `AKIAIOSFODNN7EXAMPLE` and `sk_test_*`
- Have detection gaps for certain secret patterns
- Potentially ignore known test/example secrets to reduce false positives

## Solution Architecture

### Multi-Tool Detection Engine

```
┌─────────────────────────────────────────────┐
│          Secret Scanner Lambda              │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────────────────────────┐   │
│  │    Multi-Tool Detection Engine      │   │
│  ├─────────────────────────────────────┤   │
│  │                                     │   │
│  │  • TruffleHog (ML-based)          │   │
│  │  • GitLeaks (Pattern-based)       │   │
│  │  • Semgrep (Semantic analysis)    │   │
│  │  • Custom Patterns                │   │
│  │  • AWS Macie (Optional)           │   │
│  │                                     │   │
│  └─────────────────────────────────────┘   │
│                    │                        │
│                    ▼                        │
│  ┌─────────────────────────────────────┐   │
│  │     Intelligent Fusion Engine       │   │
│  ├─────────────────────────────────────┤   │
│  │                                     │   │
│  │  • Deduplication                   │   │
│  │  • Confidence Scoring              │   │
│  │  • Multi-tool Verification         │   │
│  │                                     │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Key Features

### 1. Multi-Layer Detection

The scanner runs multiple detection layers in parallel:

1. **ML-Based Detection** (TruffleHog)
   - Machine learning-based secret detection
   - High accuracy for real secrets
   - May miss test/example secrets

2. **Pattern-Based Detection** (GitLeaks, Semgrep)
   - Comprehensive regex patterns
   - Custom rules for test secrets
   - Semantic code analysis

3. **Entropy Analysis**
   - Detects high-entropy strings
   - Configurable thresholds
   - Context-aware filtering

4. **Semantic Analysis**
   - Dynamic pattern generation
   - Context-aware detection
   - Variable name analysis

5. **Custom Detection**
   - Comment scanning
   - Configuration file analysis
   - URL credential detection

### 2. Enhanced Tool Configuration

#### TruffleHog Configuration
```bash
--only-verified=false     # Include unverified secrets
--allow-verification-overlap  # Multiple detector checks
--no-verification        # Catch test secrets
--include-detectors=all  # All available detectors
```

#### GitLeaks Custom Rules
```toml
[[rules]]
description = "Test Secrets (Include)"
regex = '''(AKIA[0-9A-Z]{16}|sk_test_[a-zA-Z0-9]{24,}|ghp_[a-zA-Z0-9]{36,})'''
tags = ["test", "secret"]
```

### 3. AWS Native Integration (Optional)

When enabled (`ENABLE_AWS_INTEGRATION=true`), the scanner integrates with:

- **AWS Macie**: For sensitive data discovery
- **AWS Security Hub**: For centralized findings
- **S3**: For temporary storage during scanning

### 4. Intelligent Fusion

The fusion engine:
- Groups similar findings from different tools
- Upgrades confidence when multiple tools detect the same secret
- Applies verification algorithms with weighted factors:
  - Entropy score (15%)
  - ML detection (20%)
  - Pattern match (15%)
  - Tool reputation (25%)
  - Multi-tool detection (15%)
  - Context analysis (10%)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_FALLBACK_DETECTION` | `always` | When to run semantic analysis (`always`, `auto`, `never`) |
| `ENABLE_AWS_INTEGRATION` | `false` | Enable AWS Macie/Security Hub integration |
| `SCAN_MODE` | `comprehensive` | Scanning mode (`comprehensive`, `fast`, `balanced`) |

### Lambda Configuration

```yaml
MemorySize: 1024  # Increased for multiple tools
Timeout: 300      # Extended for comprehensive scanning
```

## Building the Enhanced Layer

1. **Create the enhanced layer**:
   ```bash
   cd scripts
   ./build-enhanced-layer.sh
   ```

2. **Upload to S3**:
   ```bash
   aws s3 cp enhanced-scanner-layer.zip s3://your-bucket/
   ```

3. **Create Lambda layer**:
   ```bash
   aws lambda publish-layer-version \
     --layer-name enhanced-scanner-layer \
     --content S3Bucket=your-bucket,S3Key=enhanced-scanner-layer.zip
   ```

## Deployment

1. **Update SAM template** to reference the enhanced layer
2. **Deploy with SAM**:
   ```bash
   sam build --use-container
   sam deploy --guided
   ```

## Performance Considerations

- **Parallel Execution**: All tools run concurrently
- **Smart Caching**: Results cached by tool
- **Early Exit**: Optional fast mode for quick scans
- **Resource Optimization**: 1GB memory for optimal performance

## Monitoring and Troubleshooting

### CloudWatch Metrics
- Scan duration by tool
- Finding counts by type
- Fusion effectiveness
- False positive rates

### Common Issues

1. **Tool timeout**: Increase Lambda timeout
2. **Memory errors**: Increase Lambda memory
3. **Missing tools**: Check layer configuration
4. **Low detection**: Verify fallback detection is enabled

## Security Considerations

- All secrets are masked in logs
- Findings stored encrypted in DynamoDB
- IAM policies follow least privilege
- No secrets persisted to disk

## Future Enhancements

1. **Additional Tools**
   - Nosey Parker (AI-powered)
   - SecretScanner
   - detect-secrets

2. **Advanced Features**
   - Historical secret tracking
   - Cross-repository correlation
   - Custom rule builder UI
   - ML model fine-tuning

3. **Integrations**
   - Slack notifications
   - JIRA ticket creation
   - Custom webhooks

## Testing

Run the test suite:
```bash
pytest tests/unit/test_secret_scanner.py -v
```

Test with known secrets:
```bash
# Create test file with various secret types
echo 'aws_key = "AKIAIOSFODNN7EXAMPLE"' > test_secrets.py
echo 'stripe_key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"' >> test_secrets.py

# Run scanner
python -m src.lambdas.secret_scanner.app test_secrets.py
```

## Conclusion

The Enhanced Secret Scanner provides comprehensive, resilient secret detection through:
- Multiple detection engines running in parallel
- Intelligent fusion of results
- Custom rules for test secrets
- Optional cloud-native integration
- Extensive configuration options

This multi-layered approach ensures maximum coverage while maintaining high accuracy and performance. 
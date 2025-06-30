# Secret Scanner Implementation Strategy

## Current State (As of June 29, 2025)

### What's Working:
- ✅ Multi-layer detection code is implemented
- ✅ TruffleHog is available in Lambda layer
- ✅ Entropy analysis runs (but limited without context)
- ✅ Basic pattern matching works

### Limitations:
- ❌ Only 1 of 5 planned tools available (TruffleHog)
- ❌ TruffleHog not detecting test/example secrets
- ❌ No GitLeaks, Semgrep, detect-secrets, or custom scanner
- ❌ Limited effectiveness of non-tool-based layers

## Implementation Decision Matrix

| Approach | Pros | Cons | Recommendation |
|----------|------|------|----------------|
| **1. TruffleHog Only** | - Already deployed<br>- Simple maintenance | - Single point of failure<br>- Missing obvious secrets<br>- No redundancy | ❌ Not Recommended |
| **2. Full 5-Tool Layer** | - Maximum coverage<br>- True defense-in-depth<br>- Catches different secret types | - Large layer size (>250MB)<br>- Complex dependencies<br>- Longer cold starts | ✅ Ideal for Production |
| **3. Hybrid Approach** | - Balanced performance<br>- Good coverage<br>- Reasonable size | - Some tools missing<br>- Moderate complexity | ✅ Recommended Now |

## Recommended Implementation Plan

### Phase 1: Immediate Fixes (Today)
1. **Deploy TruffleHog fix** with `--no-verification` flag ✅
2. **Enable intelligent fallbacks** when TruffleHog misses secrets
3. **Add custom detection** for common test patterns

### Phase 2: Enhanced Layer (This Week)
Build a new Lambda layer with core tools:
```bash
# Essential tools only (keeps layer under 100MB)
- TruffleHog (30MB) - ML-based detection
- GitLeaks (15MB) - Fast pattern matching  
- Custom patterns - Lightweight regex engine
```

### Phase 3: Full Implementation (Next Sprint)
Add remaining tools via separate layer or container:
```bash
# Advanced tools (separate layer)
- Semgrep (Python-based, 150MB+)
- detect-secrets (Python package)
- Custom ML models
```

## Technical Implementation

### Option A: Build Enhanced Layer Now
```bash
# From Windows with Docker Desktop
cd layer-builder
docker build -f Dockerfile.scanner-layer -t scanner-layer .
docker run --rm -v ${PWD}:/output scanner-layer

# Or use AWS Cloud9/CloudShell
```

### Option B: Use AWS Layer Service
```python
# Use pre-built layers from AWS or community
LAYERS = {
            'trufflehog': 'arn:aws:lambda:us-east-1:ACCOUNT_ID:layer:trufflehog:1',
        'gitleaks': 'arn:aws:lambda:us-east-1:ACCOUNT_ID:layer:gitleaks:1',
    # Community layers often available
}
```

### Option C: Optimize Current Implementation
```python
# Make pattern-based detection smarter
def _run_pattern_detection(self, repo_path: str) -> List[SecretFinding]:
    """Enhanced pattern detection without external tools."""
    patterns = self._load_patterns_from_s3()  # Dynamic pattern updates
    findings = []
    
    # Use multiprocessing for faster scanning
    with ProcessPoolExecutor() as executor:
        results = executor.map(self._scan_file, files)
    
    return findings
```

## Architecture Decisions

### Why Multiple Tools Matter:
1. **TruffleHog** - Great for verified secrets, misses test/unverified ones
2. **GitLeaks** - Fast regex-based, catches different patterns
3. **Semgrep** - Semantic analysis, understands code context
4. **detect-secrets** - Entropy + patterns, good for high-entropy strings
5. **Custom** - Your specific business logic and patterns

### Performance Considerations:
- Current scan time: ~14 seconds (acceptable)
- With 5 tools: ~20-25 seconds (still acceptable)
- Parallel execution keeps time reasonable
- Lambda 512MB memory is sufficient

## Immediate Action Items

1. **Deploy TruffleHog fix** (--no-verification flag)
2. **Test with sentinel-testbed** PR
3. **Build minimal enhanced layer** (TruffleHog + GitLeaks)
4. **Document detected vs missed secrets**
5. **Plan for Semgrep integration** (most complex tool)

## Success Metrics

- ✅ Detect 100% of test secrets in sentinel-testbed
- ✅ < 1% false positive rate
- ✅ < 30 second scan time
- ✅ At least 3 independent detection methods
- ✅ Clear audit trail of what each tool found

## Conclusion

The current single-tool approach is a **vulnerability**. We need at least 2-3 tools for production readiness. The hybrid approach balances immediate needs with long-term robustness. 
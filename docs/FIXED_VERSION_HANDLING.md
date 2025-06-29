# Fixed Version Handling in Vulnerability Scanner

## Overview

The vulnerability scanner now intelligently handles different types of fixed version information returned by the OSV (Open Source Vulnerabilities) API.

## Problem

The OSV API sometimes returns Git commit SHAs instead of semantic version numbers. This happens when:

1. **Commit-based fixes**: The vulnerability was fixed in a specific commit but not yet released as a tagged version
2. **Missing version mapping**: The vulnerability database doesn't have the version number mapping for that commit
3. **No fix available**: Some packages might not have a fixed version available

## Solution

We've implemented a `process_fixed_version()` function that:

1. **Detects commit SHAs** (40-character hex strings)
2. **Provides ecosystem-specific guidance** for finding the latest version
3. **Handles missing fixed versions** gracefully

## Examples

### Before:
```
🔴 Pillow 5.0.0 → a79b65c47c7dc6fe623aadf09aa6192fc54548f3
🔴 bootstrap 3.3.7 → unknown
```

### After:
```
🔴 Pillow 5.0.0 → check PyPI for latest
🔴 bootstrap 3.3.7 → check for updates
```

## How It Works

1. **Vulnerability Scanner** processes the OSV API response
2. **process_fixed_version()** converts commit SHAs to user-friendly messages
3. **Aggregator** intelligently sorts and displays the results

## Technical Details

The function checks for:
- 40-character hex strings (full commit SHAs)
- 7-12 character hex strings (short commit SHAs)
- Valid semantic versions (contains dots, dashes, or starts with digit)

For ecosystem-specific guidance:
- PyPI packages → "check PyPI for latest"
- npm packages → "check npm for latest"
- Others → "update to latest"

## Benefits

1. **User-friendly**: No more confusing commit SHAs in PR comments
2. **Actionable**: Clear guidance on where to find updates
3. **Accurate**: Preserves actual version numbers when available
4. **Dynamic**: Works with any package ecosystem 
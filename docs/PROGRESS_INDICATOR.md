# Progress Indicator Feature

## Overview

DevSecOps Sentinel now provides immediate feedback when a PR is opened, showing users that their code is being analyzed.

## How It Works

### 1. Initial Comment (Immediate)
When a PR is opened/reopened/synchronized, the webhook handler immediately posts a progress comment:

```markdown
## 🔍 DevSecOps Sentinel Analysis In Progress...

[Loading Animation]

**Your PR is being analyzed for:**
- 🔴 **Hardcoded Secrets** - Scanning for API keys, passwords, and tokens
- 🟡 **Vulnerable Dependencies** - Checking for known CVEs in packages
- 💡 **Code Quality** - AI-powered review for best practices

⏱️ **Estimated time:** 30-60 seconds

---
*This comment will be updated with the analysis results shortly...*
```

### 2. Comment Update (After Analysis)
Once all scanners complete (~30-60 seconds), the same comment is updated with the full analysis results.

## Benefits

1. **Immediate Feedback** - Users know analysis is running
2. **Better UX** - No confusion about missing analysis
3. **Single Comment** - Clean PR timeline with one evolving comment
4. **Retention** - Users stay engaged while waiting for results

## Implementation Details

### Webhook Handler
- Posts initial progress comment when PR webhook is received
- Captures comment ID and passes it through Step Functions

### Aggregator
- Checks for `progress_comment_id` in repo details
- Updates existing comment if ID exists
- Creates new comment if no ID (fallback)

### Error Handling
- If initial comment posting fails, analysis continues normally
- Falls back to creating a new comment for results

## Configuration

No additional configuration required. The feature works automatically with existing GitHub token permissions.

## Future Enhancements

1. **Real-time Updates** - Update comment as each scanner completes
2. **Progress Bar** - Show percentage completion
3. **ETA Adjustment** - Update estimated time based on PR size
4. **Custom Messages** - Configurable progress messages per organization 
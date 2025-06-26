"""Unit tests for the AI reviewer Lambda function."""
import json
import pytest
from unittest.mock import patch, MagicMock, Mock
import os
import importlib.util
import sys

# Dynamically import the Lambda function module
lambda_path = os.path.join(os.path.dirname(__file__), '../../src/lambdas/ai_reviewer/app.py')
spec = importlib.util.spec_from_file_location("ai_reviewer_app", lambda_path)
app = importlib.util.module_from_spec(spec)
sys.modules["ai_reviewer_app"] = app
spec.loader.exec_module(app)

# Import the functions we need
lambda_handler = app.lambda_handler
fetch_pr_diff = app.fetch_pr_diff
fetch_pr_details = app.fetch_pr_details
analyze_with_bedrock = app.analyze_with_bedrock

class TestAIReviewer:
    """Test cases for the AI reviewer function."""
    
    @pytest.fixture
    def valid_event(self):
        """Create a valid event for testing."""
        return {
            "repo_details": {
                "repository_full_name": "test-org/test-repo",
                "pr_number": 42,
                "commit_sha": "abc123def456"
            }
        }
    
    @pytest.fixture
    def mock_pr_diff(self):
        """Sample PR diff content."""
        return """diff --git a/test.py b/test.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/test.py
@@ -0,0 +1,10 @@
+def vulnerable_function(user_input):
+    # BAD: SQL injection vulnerability
+    query = f"SELECT * FROM users WHERE id = {user_input}"
+    return query
+
+def weak_crypto():
+    import md5  # BAD: Using deprecated MD5
+    return md5.new("password").hexdigest()
"""
    
    @pytest.fixture
    def mock_pr_details(self):
        """Sample PR details."""
        return {
            "title": "Add new authentication feature",
            "description": "This PR adds a new authentication system",
            "changed_files": 3,
            "additions": 150,
            "deletions": 20
        }
    
    @pytest.fixture
    def mock_bedrock_response(self):
        """Sample Bedrock AI response."""
        return [
            {
                "category": "Security",
                "priority": "high",
                "file": "test.py",
                "line": 3,
                "description": "SQL injection vulnerability detected",
                "recommendation": "Use parameterized queries or an ORM"
            },
            {
                "category": "Security",
                "priority": "medium",
                "file": "test.py",
                "line": 7,
                "description": "Using deprecated MD5 for hashing",
                "recommendation": "Use bcrypt or argon2 for password hashing"
            }
        ]
    
    @patch.object(app, 'get_github_token')
    @patch.object(app, 'fetch_pr_diff')
    @patch.object(app, 'fetch_pr_details')
    @patch.object(app, 'analyze_with_bedrock')
    def test_successful_analysis(self, mock_analyze, mock_details, mock_diff, 
                                mock_token, valid_event, mock_pr_diff, 
                                mock_pr_details, mock_bedrock_response):
        """Test successful AI analysis with findings."""
        # Setup mocks
        mock_token.return_value = "ghp_test_token"
        mock_diff.return_value = mock_pr_diff
        mock_details.return_value = mock_pr_details
        mock_analyze.return_value = mock_bedrock_response
        
        # Call handler
        response = lambda_handler(valid_event, {})
        
        # Assertions
        assert response['statusCode'] == 200
        assert response['scanner_type'] == 'ai_review'
        assert len(response['findings']) == 2
        assert response['summary']['total_findings'] == 2
        assert response['summary']['high_priority'] == 1
        assert response['summary']['medium_priority'] == 1
        assert response['summary']['low_priority'] == 0
        
        # Verify mocks called correctly
        mock_diff.assert_called_once_with("test-org/test-repo", 42, "ghp_test_token")
        mock_details.assert_called_once_with("test-org/test-repo", 42, "ghp_test_token")
        mock_analyze.assert_called_once()
    
    @patch.object(app, 'get_github_token')
    @patch.object(app, 'fetch_pr_diff')
    def test_no_diff_content(self, mock_diff, mock_token, valid_event):
        """Test handling when no diff content is available."""
        mock_token.return_value = "ghp_test_token"
        mock_diff.return_value = None
        
        response = lambda_handler(valid_event, {})
        
        assert response['statusCode'] == 200
        assert len(response['findings']) == 0
        assert response['summary']['total_findings'] == 0
    
    def test_missing_required_fields(self):
        """Test handling of missing required fields."""
        event = {"repo_details": {}}
        response = lambda_handler(event, {})
        
        assert response['statusCode'] == 500
        assert 'error' in response
        assert response['findings'] == []
    
    def test_fetch_pr_diff_success(self):
        """Test successful PR diff fetching."""
        with patch.object(app, 'create_session_with_retries') as mock_create_session:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "diff content"
            mock_response.raise_for_status = MagicMock()
            
            # Mock session
            mock_session = MagicMock()
            mock_session.get.return_value = mock_response
            mock_create_session.return_value = mock_session
            
            diff = fetch_pr_diff("test/repo", 42, "ghp_token")
            
            assert diff == "diff content"
            mock_session.get.assert_called_once()
    
    def test_fetch_pr_diff_failure(self):
        """Test PR diff fetching failure."""
        with patch.object(app, 'create_session_with_retries') as mock_create_session:
            # Mock session to raise exception
            mock_session = MagicMock()
            mock_session.get.side_effect = app.requests.exceptions.RequestException("API Error")
            mock_create_session.return_value = mock_session
            
            diff = fetch_pr_diff("test/repo", 42, "ghp_token")
            
            assert diff is None
    
    def test_analyze_with_bedrock_success(self, mock_pr_diff, mock_pr_details):
        """Test successful Bedrock analysis."""
        mock_response = {
            "body": MagicMock()
        }
        mock_response["body"].read.return_value = json.dumps({
            "content": [{
                "text": json.dumps([
                    {
                        "category": "Security",
                        "priority": "high",
                        "file": "test.py",
                        "line": 10,
                        "description": "Security issue found",
                        "recommendation": "Fix the issue"
                    }
                ])
            }]
        }).encode()
        
        with patch.object(app.bedrock_runtime, 'invoke_model', return_value=mock_response):
            findings = analyze_with_bedrock(mock_pr_diff, mock_pr_details, "test/repo", 42)
            
            assert len(findings) == 1
            assert findings[0]['type'] == 'ai_suggestion'
            assert findings[0]['category'] == 'Security'
            assert findings[0]['priority'] == 'high'
    
    def test_analyze_with_bedrock_json_parse_error(self, mock_pr_diff, mock_pr_details):
        """Test Bedrock analysis with JSON parsing error."""
        mock_response = {
            "body": MagicMock()
        }
        mock_response["body"].read.return_value = json.dumps({
            "content": [{
                "text": "Invalid JSON response"
            }]
        }).encode()
        
        with patch.object(app.bedrock_runtime, 'invoke_model', return_value=mock_response):
            findings = analyze_with_bedrock(mock_pr_diff, mock_pr_details, "test/repo", 42)
            
            assert len(findings) == 1
            assert findings[0]['category'] == 'Maintainability'
            assert 'parsing failed' in findings[0]['description']
    
    def test_analyze_with_bedrock_api_error(self, mock_pr_diff, mock_pr_details):
        """Test Bedrock API error handling."""
        with patch.object(app.bedrock_runtime, 'invoke_model', side_effect=Exception("Bedrock Error")):
            findings = analyze_with_bedrock(mock_pr_diff, mock_pr_details, "test/repo", 42)
            
            assert len(findings) == 1
            assert findings[0]['category'] == 'Error'
            assert 'Bedrock Error' in findings[0]['recommendation']
    
    def test_truncate_large_diff(self, mock_pr_details):
        """Test that large diffs are truncated."""
        # Create a diff larger than 30000 characters
        large_diff = "x" * 35000
        
        mock_response = {
            "body": MagicMock()
        }
        mock_response["body"].read.return_value = json.dumps({
            "content": [{"text": "[]"}]
        }).encode()
        
        with patch.object(app.bedrock_runtime, 'invoke_model', return_value=mock_response) as mock_invoke:
            analyze_with_bedrock(large_diff, mock_pr_details, "test/repo", 42)
            
            # Verify the prompt was truncated
            call_args = mock_invoke.call_args[1]['body']
            prompt_data = json.loads(call_args)
            prompt_text = prompt_data['messages'][0]['content']
            assert "diff truncated due to size" in prompt_text
    
    @patch.object(app, 'get_github_token')
    def test_error_in_main_handler(self, mock_token, valid_event):
        """Test error handling in the main handler."""
        mock_token.side_effect = Exception("Token error")
        
        response = lambda_handler(valid_event, {})
        
        assert response['statusCode'] == 500
        assert 'error' in response
        assert 'Token error' in response['error'] 
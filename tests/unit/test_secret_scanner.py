"""Unit tests for the secret scanner Lambda function."""
import json
import pytest
from unittest.mock import patch, MagicMock, Mock, mock_open
import os
import tempfile
import zipfile
import importlib.util
import sys

# Dynamically import the Lambda function module
lambda_path = os.path.join(os.path.dirname(__file__), '../../src/lambdas/secret_scanner/app.py')
spec = importlib.util.spec_from_file_location("secret_scanner_app", lambda_path)
app = importlib.util.module_from_spec(spec)
sys.modules["secret_scanner_app"] = app
spec.loader.exec_module(app)

# Import the functions we need
lambda_handler = app.lambda_handler
run_trufflehog_scan = app.run_trufflehog_scan

class TestSecretScanner:
    """Test cases for the secret scanner function."""
    
    @pytest.fixture
    def valid_event(self):
        """Create a valid event for testing."""
        return {
            "repo_details": {
                "repository_full_name": "test-org/test-repo",
                "commit_sha": "abc123def456",
                "pull_request_id": "12345",
                "pr_number": 42
            }
        }
    
    @patch.object(app, 'get_github_token')
    @patch.object(app, 'create_session_with_retries')
    @patch.object(app, 'run_trufflehog_scan')
    @patch('zipfile.ZipFile')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.listdir')
    def test_successful_scan_with_findings(self, mock_listdir, mock_file, mock_zipfile, 
                                         mock_scan, mock_session, mock_token, valid_event):
        """Test successful scan that finds secrets."""
        # Mock GitHub token
        mock_token.return_value = "ghp_test_token"
        
        # Mock session with retries
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_content = MagicMock(return_value=[b"fake zip content"])
        mock_response.raise_for_status = MagicMock()
        
        mock_session_obj = MagicMock()
        mock_session_obj.get.return_value = mock_response
        mock_session.return_value = mock_session_obj
        
        # Mock zipfile operations
        mock_zip_instance = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip_instance
        
        # Mock os.listdir to return a fake extracted directory
        mock_listdir.return_value = ['test-repo-abc123']
        
        # Mock trufflehog findings
        mock_scan.return_value = [
            {
                "type": "AWS API Key",
                "file": "config.py",
                "line": 42,
                "raw": "AKIA1234567890ABCDEF"
            },
            {
                "type": "GitHub Token",
                "file": ".env",
                "line": 10,
                "raw": "ghp_1234567890abcdef"
            }
        ]
        
        # Call handler
        response = lambda_handler(valid_event, {})
        
        # Assertions
        assert response['statusCode'] == 200
        assert response['scanner_type'] == 'secrets'
        assert len(response['findings']) == 2
        assert response['summary']['total_findings'] == 2
        mock_session_obj.get.assert_called_once()
        mock_scan.assert_called_once()
    
    @patch.object(app, 'get_github_token')
    @patch.object(app, 'create_session_with_retries')
    @patch.object(app, 'run_trufflehog_scan')
    @patch('zipfile.ZipFile')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.listdir')
    def test_successful_scan_no_findings(self, mock_listdir, mock_file, mock_zipfile,
                                       mock_scan, mock_session, mock_token, valid_event):
        """Test successful scan with no secrets found."""
        mock_token.return_value = "ghp_test_token"
        
        # Mock session with retries
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_content = MagicMock(return_value=[b"fake zip content"])
        mock_response.raise_for_status = MagicMock()
        
        mock_session_obj = MagicMock()
        mock_session_obj.get.return_value = mock_response
        mock_session.return_value = mock_session_obj
        
        # Mock zipfile operations
        mock_zip_instance = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip_instance
        
        # Mock os.listdir to return a fake extracted directory
        mock_listdir.return_value = ['test-repo-abc123']
        
        mock_scan.return_value = []
        
        response = lambda_handler(valid_event, {})
        
        assert response['statusCode'] == 200
        assert len(response['findings']) == 0
        assert response['summary']['total_findings'] == 0
    
    def test_missing_repository_details(self):
        """Test handling of missing repository details."""
        response = lambda_handler({}, {})
        
        assert response['statusCode'] == 500
        assert 'error' in response
        assert response['findings'] == []
    
    @patch.object(app, 'get_github_token')
    @patch.object(app, 'create_session_with_retries')
    def test_github_api_failure(self, mock_session, mock_token, valid_event):
        """Test handling of GitHub API failures."""
        mock_token.return_value = "ghp_test_token"
        
        # Mock session to raise exception
        mock_session_obj = MagicMock()
        mock_session_obj.get.side_effect = Exception("API Error")
        mock_session.return_value = mock_session_obj
        
        response = lambda_handler(valid_event, {})
        
        assert response['statusCode'] == 500
        assert 'error' in response
        assert 'API Error' in response['error']
    
    def test_run_trufflehog_scan_success(self):
        """Test successful trufflehog scan execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file
            test_file = os.path.join(temp_dir, "test.py")
            with open(test_file, 'w') as f:
                f.write("API_KEY = 'test_key'")
            
            # Mock subprocess.run
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = json.dumps({
                "DetectorName": "AWS API Key",
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "test.py",
                            "line": 1
                        }
                    }
                },
                "Raw": "test_key"
            })
            
            with patch('secret_scanner_app.find_tool', return_value='trufflehog'):
                with patch('secret_scanner_app.subprocess.run', return_value=mock_result):
                    findings = run_trufflehog_scan(temp_dir)
                    
                    assert len(findings) == 1
                    assert findings[0]['type'] == "AWS API Key"
                    assert findings[0]['file'] == "test.py"
                    assert findings[0]['line'] == 1
                    assert findings[0]['raw'] == "test_key"
    
    def test_run_trufflehog_scan_failure(self):
        """Test trufflehog scan failure handling."""
        with tempfile.TemporaryDirectory() as temp_dir:
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stderr = "Trufflehog error"
            
            with patch('secret_scanner_app.find_tool', return_value='trufflehog'):
                with patch('secret_scanner_app.subprocess.run', return_value=mock_result):
                    findings = run_trufflehog_scan(temp_dir)
                    
                    # Now it should return an error finding instead of empty list
                    assert len(findings) == 1
                    assert findings[0]['type'] == 'tool_error'
                    assert 'Trufflehog error' in findings[0]['raw']
    
    @patch.object(app, 'get_github_token')
    def test_invalid_github_token(self, mock_token, valid_event):
        """Test handling of invalid GitHub token."""
        mock_token.side_effect = Exception("Invalid token")
        
        response = lambda_handler(valid_event, {})
        
        assert response['statusCode'] == 500
        assert 'error' in response
        assert 'Invalid token' in response['error'] 
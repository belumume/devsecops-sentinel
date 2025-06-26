"""Unit tests for the webhook handler Lambda function."""
import json
import pytest
import hmac
import hashlib
from unittest.mock import patch, MagicMock
import os
import sys

# Add the Lambda function directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../src/lambdas/webhook_handler'))
from app import lambda_handler, success_response, error_response


class TestWebhookHandler:
    """Test cases for the webhook handler function."""
    
    @pytest.fixture
    def valid_webhook_event(self):
        """Create a valid webhook event for testing."""
        body = json.dumps({
            "action": "opened",
            "pull_request": {
                "id": 12345,
                "number": 42,
                "head": {
                    "sha": "abc123def456"
                }
            },
            "repository": {
                "full_name": "test-org/test-repo"
            }
        })
        
        secret = "test-webhook-secret"
        signature = "sha256=" + hmac.new(
            secret.encode('utf-8'),
            body.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return {
            "headers": {
                "x-hub-signature-256": signature,
                "x-github-event": "pull_request"
            },
            "body": body
        }
    
    @patch.dict(os.environ, {
        'GITHUB_WEBHOOK_SECRET_NAME': 'test-secret',
        'STATE_MACHINE_ARN': 'arn:aws:states:us-east-1:123456789012:stateMachine:test',
        'SECRET_SCANNER_FUNCTION_ARN': 'arn:aws:lambda:us-east-1:123456789012:function:secret-scanner',
        'VULNERABILITY_SCANNER_FUNCTION_ARN': 'arn:aws:lambda:us-east-1:123456789012:function:vuln-scanner',
        'AI_REVIEWER_FUNCTION_ARN': 'arn:aws:lambda:us-east-1:123456789012:function:ai-reviewer'
    })
    @patch('app.sfn_client')
    @patch('app.secrets_manager')
    def test_valid_webhook_triggers_step_function(self, mock_secrets, mock_sfn, valid_webhook_event):
        """Test that a valid webhook triggers Step Functions execution."""
        # Mock secrets manager response
        mock_secrets.get_secret_value.return_value = {
            'SecretString': 'test-webhook-secret'
        }
        
        # Mock Step Functions response
        mock_sfn.start_execution.return_value = {
            'executionArn': 'arn:aws:states:us-east-1:123456789012:execution:test:12345'
        }
        
        # Call the handler
        response = lambda_handler(valid_webhook_event, {})
        
        # Assertions
        assert response['statusCode'] == 200
        assert 'Analysis started' in json.loads(response['body'])['message']
        mock_sfn.start_execution.assert_called_once()
        
    @patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET_NAME': 'test-secret'})
    @patch('app.secrets_manager')
    def test_invalid_signature_returns_401(self, mock_secrets, valid_webhook_event):
        """Test that invalid signature returns 401 Unauthorized."""
        # Mock secrets manager with different secret
        mock_secrets.get_secret_value.return_value = {
            'SecretString': 'different-secret'
        }
        
        response = lambda_handler(valid_webhook_event, {})
        
        assert response['statusCode'] == 401
        assert json.loads(response['body'])['error'] == 'Unauthorized'
        
    @patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET_NAME': 'test-secret'})
    @patch('app.secrets_manager')
    def test_missing_signature_header_returns_401(self, mock_secrets):
        """Test that missing signature header returns 401."""
        # Mock secrets manager (though it shouldn't be called)
        mock_secrets.get_secret_value.return_value = {
            'SecretString': 'test-webhook-secret'
        }
        
        event = {
            "headers": {},
            "body": "{}"
        }
        
        response = lambda_handler(event, {})
        
        assert response['statusCode'] == 401
        
    @patch.dict(os.environ, {'GITHUB_WEBHOOK_SECRET_NAME': 'test-secret'})
    @patch('app.secrets_manager')
    def test_ping_event_returns_success(self, mock_secrets):
        """Test that ping events are handled correctly."""
        mock_secrets.get_secret_value.return_value = {
            'SecretString': 'test-webhook-secret'
        }
        
        body = "ping body"
        secret = "test-webhook-secret"
        signature = "sha256=" + hmac.new(
            secret.encode('utf-8'),
            body.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        event = {
            "headers": {
                "x-hub-signature-256": signature,
                "x-github-event": "ping"
            },
            "body": body
        }
        
        response = lambda_handler(event, {})
        
        assert response['statusCode'] == 200
        assert 'Ping event successful' in json.loads(response['body'])['message']
        
    def test_success_response_format(self):
        """Test the success response helper function."""
        response = success_response("Test message")
        
        assert response['statusCode'] == 200
        assert json.loads(response['body'])['message'] == "Test message"
        
    def test_error_response_format(self):
        """Test the error response helper function."""
        response = error_response("Test error", 500)
        
        assert response['statusCode'] == 500
        assert json.loads(response['body'])['error'] == "Test error" 
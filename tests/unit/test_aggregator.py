"""Unit tests for the aggregator Lambda function."""
import json
import pytest
from unittest.mock import patch, MagicMock, Mock
import os
import importlib.util
import sys

# Dynamically import the Lambda function module
lambda_path = os.path.join(os.path.dirname(__file__), '../../src/lambdas/aggregator/app.py')
spec = importlib.util.spec_from_file_location("aggregator_app", lambda_path)
app = importlib.util.module_from_spec(spec)
sys.modules["aggregator_app"] = app
spec.loader.exec_module(app)

# Import the functions we need
lambda_handler = app.lambda_handler
aggregate_scan_results = app.aggregate_scan_results
format_github_comment = app.format_github_comment
post_github_comment = app.post_github_comment
log_scan_summary = app.log_scan_summary

class TestAggregator:
    """Test cases for the aggregator function."""
    
    @pytest.fixture
    def valid_event(self):
        """Create a valid event with scan results."""
        return {
            "repo_details": {
                "repository_full_name": "test-org/test-repo",
                "pull_request_id": "12345",
                "pr_number": 42,
                "commit_sha": "abc123def456"
            },
            "scan_results": [
                {
                    "Payload": json.dumps({
                        "statusCode": 200,
                        "scanner_type": "secrets",
                        "findings": [
                            {
                                "type": "AWS API Key",
                                "file": "config.py",
                                "line": 10
                            }
                        ]
                    })
                },
                {
                    "Payload": {
                        "statusCode": 200,
                        "scanner_type": "vulnerabilities",
                        "findings": [
                            {
                                "package": "Django",
                                "severity": "HIGH",
                                "vulnerability": "CVE-2019-12345"
                            }
                        ]
                    }
                },
                {
                    "Payload": {
                        "statusCode": 200,
                        "scanner_type": "ai_review",
                        "findings": [
                            {
                                "category": "Security",
                                "priority": "high",
                                "description": "SQL injection risk"
                            }
                        ]
                    }
                }
            ]
        }
    
    @pytest.fixture
    def lambda_context(self):
        """Mock Lambda context."""
        context = MagicMock()
        context.aws_request_id = "test-request-id"
        return context
    
    @patch.dict(os.environ, {'SCANS_TABLE_NAME': 'TestScansTable'})
    @patch.object(app, 'get_github_token')
    @patch.object(app, 'post_github_comment')
    @patch.object(app, 'log_scan_summary')
    def test_successful_aggregation(self, mock_log, mock_post, mock_token, 
                                   valid_event, lambda_context):
        """Test successful aggregation with all scanners reporting findings."""
        # Setup mocks
        mock_token.return_value = "ghp_test_token"
        mock_post.return_value = {'success': True}
        
        # Call handler
        response = lambda_handler(valid_event, lambda_context)
        
        # Assertions
        assert response['statusCode'] == 200
        assert response['aggregation_complete'] is True
        assert response['findings_summary']['secrets_found'] == 1
        assert response['findings_summary']['vulnerabilities_found'] == 1
        assert response['findings_summary']['ai_suggestions'] == 1
        assert response['github_comment_posted'] is True
        
        # Verify functions called
        mock_post.assert_called_once()
        mock_log.assert_called_once()
    
    def test_aggregate_scan_results_with_errors(self):
        """Test aggregation when some scanners return errors."""
        scan_results = [
            {
                "Payload": {
                    "statusCode": 500,
                    "scanner_type": "secrets",
                    "error": "Scanner failed"
                }
            },
            {
                "Payload": {
                    "statusCode": 200,
                    "scanner_type": "vulnerabilities",
                    "findings": [{"package": "test"}]
                }
            }
        ]
        
        aggregated = aggregate_scan_results(scan_results)
        
        assert len(aggregated['secrets']) == 0
        assert len(aggregated['vulnerabilities']) == 1
        assert len(aggregated['errors']) == 1
        assert aggregated['errors'][0]['scanner'] == 'secrets'
    
    def test_aggregate_scan_results_json_string_payload(self):
        """Test handling of JSON string payloads."""
        scan_results = [
            {
                "Payload": json.dumps({
                    "statusCode": 200,
                    "scanner_type": "secrets",
                    "findings": [{"type": "API Key"}]
                })
            }
        ]
        
        aggregated = aggregate_scan_results(scan_results)
        
        assert len(aggregated['secrets']) == 1
        assert aggregated['secrets'][0]['type'] == 'API Key'
    
    def test_format_github_comment_with_all_findings(self):
        """Test GitHub comment formatting with findings from all scanners."""
        findings = {
            'secrets': [
                {'type': 'API Key', 'file': 'config.py', 'line': 10},
                {'type': 'Database Password', 'file': '.env', 'line': 5}
            ],
            'vulnerabilities': [
                {
                    'package': 'Django',
                    'installed_version': '2.0.1',
                    'fixed_version': '2.2.0',
                    'severity': 'HIGH',
                    'vulnerability': 'CVE-2019-12345',
                    'description': 'SQL injection'
                }
            ],
            'ai_suggestions': [
                {
                    'category': 'Security',
                    'priority': 'high',
                    'file': 'auth.py',
                    'line': 42,
                    'description': 'Weak password hashing',
                    'recommendation': 'Use bcrypt instead'
                }
            ],
            'errors': []
        }
        
        repo_details = {
            'commit_sha': 'abc123def456789'
        }
        
        comment = format_github_comment(findings, repo_details)
        
        # Verify comment structure
        assert '🔴 Secret Scanner' in comment
        assert '**Action Required**' in comment
        assert '2 secrets found' in comment
        assert 'API Key' in comment
        assert 'config.py' in comment
        assert '🟡 Vulnerability Scanner' in comment
        assert 'Django' in comment
        assert '💡 AI Code Review' in comment
        assert 'Security' in comment
        assert 'bcrypt' in comment
        assert 'abc123d' in comment  # Shortened commit SHA
    
    def test_format_github_comment_no_findings(self):
        """Test GitHub comment formatting when no issues are found."""
        findings = {
            'secrets': [],
            'vulnerabilities': [],
            'ai_suggestions': [],
            'errors': []
        }
        
        repo_details = {'commit_sha': 'abc123'}
        
        comment = format_github_comment(findings, repo_details)
        
        assert '✅ Secret Scanner' in comment
        assert 'Clean' in comment
        assert '0 secrets found' in comment
    
    def test_post_github_comment_success(self):
        """Test successful GitHub comment posting."""
        with patch.object(app, 'get_github_token') as mock_token:
            with patch.object(app, 'create_session_with_retries') as mock_create_session:
                mock_token.return_value = "ghp_test_token"
                
                mock_response = MagicMock()
                mock_response.status_code = 201
                mock_response.json.return_value = {'id': 12345}
                mock_response.raise_for_status = MagicMock()
                
                # Mock session
                mock_session = MagicMock()
                mock_session.post.return_value = mock_response
                mock_create_session.return_value = mock_session
                
                repo_details = {
                    'repository_full_name': 'test/repo',
                    'pr_number': 42
                }
                
                result = post_github_comment(repo_details, "Test comment")
                
                assert result['success'] is True
                assert 'response' in result
                mock_session.post.assert_called_once()
    
    def test_post_github_comment_failure(self):
        """Test GitHub comment posting failure."""
        with patch.object(app, 'get_github_token') as mock_token:
            with patch.object(app, 'create_session_with_retries') as mock_create_session:
                mock_token.return_value = "ghp_test_token"
                
                # Mock session to raise exception
                mock_session = MagicMock()
                mock_session.post.side_effect = Exception("API Error")
                mock_create_session.return_value = mock_session
                
                repo_details = {
                    'repository_full_name': 'test/repo',
                    'pr_number': 42
                }
                
                result = post_github_comment(repo_details, "Test comment")
                
                assert result['success'] is False
                assert 'error' in result
                assert 'API Error' in result['error']
    
    @patch.object(app, 'dynamodb')
    def test_log_scan_summary(self, mock_dynamodb, lambda_context):
        """Test DynamoDB logging of scan summary."""
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        
        repo_details = {
            'pull_request_id': '12345',
            'repository_full_name': 'test/repo',
            'pr_number': 42,
            'commit_sha': 'abc123'
        }
        
        findings = {
            'secrets': [1, 2],
            'vulnerabilities': [1],
            'ai_suggestions': [1, 2, 3],
            'errors': []
        }
        
        log_scan_summary(repo_details, findings, lambda_context)
        
        # Verify DynamoDB put_item called
        mock_table.put_item.assert_called_once()
        call_args = mock_table.put_item.call_args[1]['Item']
        assert call_args['pull_request_id'] == '12345'
        assert call_args['secrets_found'] == 2
        assert call_args['vulnerabilities_found'] == 1
        assert call_args['ai_suggestions'] == 3
    
    @patch.object(app, 'aggregate_scan_results')
    def test_error_handling_in_handler(self, mock_aggregate, lambda_context):
        """Test error handling in the main handler."""
        mock_aggregate.side_effect = Exception("Processing error")
        
        event = {"scan_results": [], "repo_details": {}}
        response = lambda_handler(event, lambda_context)
        
        assert response['statusCode'] == 500
        assert 'error' in response
        assert 'Processing error' in response['error']
        assert response['aggregation_complete'] is False 
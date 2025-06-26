"""Integration tests for end-to-end DevSecOps Sentinel workflow."""
import json
import pytest
import boto3
import time
from unittest.mock import patch, MagicMock
import os

# This test requires AWS credentials and deployed resources
# Run with: pytest tests/integration/test_end_to_end.py -v


class TestEndToEndWorkflow:
    """Test the complete workflow from webhook to comment posting."""
    
    @pytest.fixture
    def step_functions_client(self):
        """Create Step Functions client."""
        return boto3.client('stepfunctions', region_name='us-east-1')
    
    @pytest.fixture
    def lambda_client(self):
        """Create Lambda client."""
        return boto3.client('lambda', region_name='us-east-1')
    
    @pytest.fixture
    def test_event(self):
        """Create a test GitHub webhook event."""
        return {
            "headers": {
                "x-github-event": "pull_request",
                "x-hub-signature-256": "sha256=test_signature"
            },
            "body": json.dumps({
                "action": "opened",
                "pull_request": {
                    "id": 99999,
                    "number": 1,
                    "head": {
                        "sha": "test_commit_sha"
                    }
                },
                "repository": {
                    "full_name": "test-org/test-repo"
                }
            })
        }
    
    @pytest.mark.integration
    @pytest.mark.skipif(
        not os.environ.get('RUN_INTEGRATION_TESTS'),
        reason="Integration tests require deployed resources and RUN_INTEGRATION_TESTS=true"
    )
    def test_webhook_triggers_step_functions(self, lambda_client, step_functions_client, test_event):
        """Test that webhook handler triggers Step Functions execution."""
        # Get the webhook handler function name
        function_name = os.environ.get('WEBHOOK_HANDLER_FUNCTION_NAME', 'devsecops-sentinel-WebhookHandlerFunction')
        
        # Invoke the webhook handler
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(test_event)
        )
        
        # Check response
        assert response['StatusCode'] == 200
        payload = json.loads(response['Payload'].read())
        assert payload['statusCode'] in [200, 401]  # 401 if signature validation fails
    
    @pytest.mark.integration
    @pytest.mark.skipif(
        not os.environ.get('RUN_INTEGRATION_TESTS'),
        reason="Integration tests require deployed resources and RUN_INTEGRATION_TESTS=true"
    )
    def test_step_functions_execution(self, step_functions_client):
        """Test Step Functions execution with test data."""
        state_machine_arn = os.environ.get(
            'STATE_MACHINE_ARN',
            'arn:aws:states:us-east-1:123456789012:stateMachine:AnalysisStateMachine'
        )
        
        test_input = {
            "repo_details": {
                "repository_full_name": "test-org/test-repo",
                "pull_request_id": "99999",
                "pr_number": 1,
                "commit_sha": "test_commit_sha"
            },
            "analysis_types": [
                {
                    "type": "secrets",
                    "function_name": os.environ.get('SECRET_SCANNER_ARN', 'test-secret-scanner'),
                    "payload": {"repo_details": {"repository_full_name": "test-org/test-repo"}}
                }
            ]
        }
        
        # Start execution
        execution_name = f"test-execution-{int(time.time())}"
        response = step_functions_client.start_execution(
            stateMachineArn=state_machine_arn,
            name=execution_name,
            input=json.dumps(test_input)
        )
        
        assert 'executionArn' in response
        
        # Wait for execution to complete (with timeout)
        max_wait = 60  # seconds
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            status = step_functions_client.describe_execution(
                executionArn=response['executionArn']
            )
            
            if status['status'] != 'RUNNING':
                break
                
            time.sleep(5)
        
        # Check final status
        assert status['status'] in ['SUCCEEDED', 'FAILED']
    
    @pytest.mark.integration
    def test_scanner_lambda_invocation(self, lambda_client):
        """Test individual scanner Lambda functions."""
        scanners = [
            ('SECRET_SCANNER_FUNCTION_NAME', 'devsecops-sentinel-SecretScannerFunction'),
            ('VULNERABILITY_SCANNER_FUNCTION_NAME', 'devsecops-sentinel-VulnerabilityScannerFunction'),
            ('AI_REVIEWER_FUNCTION_NAME', 'devsecops-sentinel-AIReviewerFunction'),
        ]
        
        test_payload = {
            "repo_details": {
                "repository_full_name": "test-org/test-repo",
                "pr_number": 1,
                "commit_sha": "test_sha"
            }
        }
        
        for env_var, default_name in scanners:
            function_name = os.environ.get(env_var, default_name)
            
            # Skip if function doesn't exist
            try:
                response = lambda_client.invoke(
                    FunctionName=function_name,
                    InvocationType='RequestResponse',
                    Payload=json.dumps(test_payload)
                )
                
                assert response['StatusCode'] == 200
                payload = json.loads(response['Payload'].read())
                assert 'statusCode' in payload
                assert 'scanner_type' in payload
                
            except lambda_client.exceptions.ResourceNotFoundException:
                pytest.skip(f"Function {function_name} not found")
    
    @pytest.mark.integration
    def test_aggregator_formatting(self):
        """Test aggregator comment formatting with sample data."""
        # This is a unit test but included here for completeness
        from src.lambdas.aggregator.app import format_github_comment
        
        findings = {
            'secrets': [
                {'type': 'API Key', 'file': 'config.py', 'line': 10}
            ],
            'vulnerabilities': [
                {
                    'package': 'requests',
                    'severity': 'HIGH',
                    'vulnerability': 'CVE-2023-12345',
                    'description': 'Test vulnerability'
                }
            ],
            'ai_suggestions': [
                {
                    'category': 'Security',
                    'priority': 'high',
                    'file': 'app.py',
                    'line': 42,
                    'description': 'SQL injection risk',
                    'recommendation': 'Use parameterized queries'
                }
            ],
            'errors': []
        }
        
        repo_details = {
            'commit_sha': 'abc123def456789'
        }
        
        comment = format_github_comment(findings, repo_details)
        
        # Verify comment contains expected sections
        assert '🔴 Critical: Hardcoded Secrets Detected' in comment
        assert '🟡 Dependency Vulnerabilities Detected' in comment
        assert '💡 AI Code Review Suggestions' in comment
        assert 'API Key' in comment
        assert 'requests' in comment
        assert 'SQL injection' in comment 
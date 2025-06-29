"""
AWS Native Services Integration for Secret Detection
Integrates with AWS Macie, Security Hub, and other services
"""

import json
import logging
import os
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class AWSSecurityIntegration:
    """Integrates with AWS native security services for enhanced detection."""
    
    def __init__(self):
        self.region = os.environ.get('AWS_REGION', 'us-east-1')
        self.account_id = boto3.client('sts').get_caller_identity()['Account']
        
        # Initialize AWS clients
        self.macie_client = boto3.client('macie2', region_name=self.region)
        self.securityhub_client = boto3.client('securityhub', region_name=self.region)
        self.s3_client = boto3.client('s3', region_name=self.region)
        
    def scan_with_macie(self, s3_bucket: str, s3_key: str) -> List[Dict[str, Any]]:
        """Use AWS Macie to scan S3 objects for sensitive data."""
        findings = []
        
        try:
            # Check if Macie is enabled
            account_status = self.macie_client.get_macie_session()
            if account_status['status'] != 'ENABLED':
                logger.warning("AWS Macie is not enabled for this account")
                return findings
                
            # Create a classification job
            response = self.macie_client.create_classification_job(
                name=f"DevSecOps-Sentinel-Scan-{s3_key}",
                description="Automated secret scanning via DevSecOps Sentinel",
                s3JobDefinition={
                    'bucketDefinitions': [{
                        'accountId': self.account_id,
                        'buckets': [s3_bucket]
                    }],
                    'scoping': {
                        'includes': {
                            'and': [{
                                'simpleScopeTerm': {
                                    'key': 'OBJECT_KEY',
                                    'values': [s3_key],
                                    'comparator': 'EQ'
                                }
                            }]
                        }
                    }
                },
                customDataIdentifierIds=self._get_custom_identifiers(),
                jobType='ONE_TIME'
            )
            
            job_id = response['jobId']
            logger.info(f"Created Macie classification job: {job_id}")
            
            # Note: Macie jobs are asynchronous, so we'd need to poll or use EventBridge
            # For now, return job metadata
            findings.append({
                'service': 'macie',
                'job_id': job_id,
                'status': 'initiated',
                'message': 'Macie scan initiated, results will be available in Security Hub'
            })
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                logger.warning("No permissions to use AWS Macie")
            else:
                logger.error(f"Macie error: {e}")
        except Exception as e:
            logger.error(f"Failed to scan with Macie: {e}")
            
        return findings
    
    def _get_custom_identifiers(self) -> List[str]:
        """Get custom data identifiers for enhanced detection."""
        identifiers = []
        
        try:
            # List custom data identifiers
            response = self.macie_client.list_custom_data_identifiers()
            
            for item in response.get('items', []):
                if 'secret' in item['name'].lower() or 'key' in item['name'].lower():
                    identifiers.append(item['id'])
                    
        except Exception as e:
            logger.warning(f"Could not retrieve custom identifiers: {e}")
            
        return identifiers
    
    def check_security_hub_findings(self, resource_arn: str) -> List[Dict[str, Any]]:
        """Check Security Hub for existing findings on a resource."""
        findings = []
        
        try:
            # Get findings for the specific resource
            response = self.securityhub_client.get_findings(
                Filters={
                    'ResourceArn': [{
                        'Value': resource_arn,
                        'Comparison': 'EQUALS'
                    }],
                    'RecordState': [{
                        'Value': 'ACTIVE',
                        'Comparison': 'EQUALS'
                    }],
                    'WorkflowStatus': [{
                        'Value': 'NEW',
                        'Comparison': 'EQUALS'
                    }]
                },
                MaxResults=100
            )
            
            for finding in response.get('Findings', []):
                if self._is_secret_related(finding):
                    findings.append({
                        'service': 'security_hub',
                        'finding_id': finding['Id'],
                        'title': finding['Title'],
                        'description': finding['Description'],
                        'severity': finding['Severity']['Label'],
                        'resource': finding['Resources'][0]['Id'],
                        'created_at': finding['CreatedAt']
                    })
                    
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDeniedException':
                logger.error(f"Security Hub error: {e}")
        except Exception as e:
            logger.error(f"Failed to check Security Hub: {e}")
            
        return findings
    
    def _is_secret_related(self, finding: Dict[str, Any]) -> bool:
        """Check if a Security Hub finding is related to secrets."""
        secret_keywords = [
            'secret', 'credential', 'password', 'key', 'token',
            'api', 'access', 'private', 'sensitive'
        ]
        
        # Check title and description
        text_to_check = f"{finding.get('Title', '')} {finding.get('Description', '')}".lower()
        
        return any(keyword in text_to_check for keyword in secret_keywords)
    
    def report_to_security_hub(self, findings: List[Dict[str, Any]], repo_name: str) -> bool:
        """Report findings to AWS Security Hub."""
        try:
            # Ensure Security Hub is enabled
            try:
                self.securityhub_client.enable_security_hub()
            except ClientError:
                pass  # Already enabled
            
            # Convert findings to Security Hub format
            security_hub_findings = []
            
            for finding in findings:
                security_hub_findings.append({
                    'SchemaVersion': '2018-10-08',
                    'Id': f"devsecops-sentinel/{finding.get('id', 'unknown')}",
                    'ProductArn': f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default",
                    'GeneratorId': 'devsecops-sentinel-secret-scanner',
                    'AwsAccountId': self.account_id,
                    'Types': ['Sensitive Data Identifications/PII'],
                    'CreatedAt': finding.get('timestamp', ''),
                    'UpdatedAt': finding.get('timestamp', ''),
                    'Severity': {
                        'Label': self._map_severity(finding.get('confidence', 'LOW'))
                    },
                    'Title': f"Secret detected in {finding.get('file_path', 'unknown')}",
                    'Description': f"Detected {finding.get('secret_type', 'unknown')} secret in repository {repo_name}",
                    'Resources': [{
                        'Type': 'Other',
                        'Id': f"github/{repo_name}/{finding.get('file_path', '')}",
                        'Details': {
                            'Other': {
                                'SecretType': finding.get('secret_type', 'unknown'),
                                'Tool': finding.get('tool', 'unknown'),
                                'LineNumber': str(finding.get('line_number', 0))
                            }
                        }
                    }],
                    'RecordState': 'ACTIVE',
                    'WorkflowState': 'NEW'
                })
            
            if security_hub_findings:
                # Batch import findings
                response = self.securityhub_client.batch_import_findings(
                    Findings=security_hub_findings
                )
                
                logger.info(f"Reported {response['SuccessCount']} findings to Security Hub")
                return response['FailedCount'] == 0
                
        except Exception as e:
            logger.error(f"Failed to report to Security Hub: {e}")
            
        return False
    
    def _map_severity(self, confidence: str) -> str:
        """Map confidence level to Security Hub severity."""
        mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW'
        }
        return mapping.get(confidence.upper(), 'INFORMATIONAL')
    
    def create_s3_bucket_for_scanning(self) -> Optional[str]:
        """Create a temporary S3 bucket for Macie scanning."""
        bucket_name = f"devsecops-sentinel-scan-{self.account_id}-{self.region}"
        
        try:
            # Check if bucket exists
            try:
                self.s3_client.head_bucket(Bucket=bucket_name)
                return bucket_name
            except ClientError:
                # Create bucket
                if self.region == 'us-east-1':
                    self.s3_client.create_bucket(Bucket=bucket_name)
                else:
                    self.s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': self.region}
                    )
                
                # Enable encryption
                self.s3_client.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }]
                    }
                )
                
                logger.info(f"Created S3 bucket for scanning: {bucket_name}")
                return bucket_name
                
        except Exception as e:
            logger.error(f"Failed to create S3 bucket: {e}")
            
        return None 
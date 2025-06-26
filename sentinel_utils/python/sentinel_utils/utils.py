import logging
import os
import boto3
import json

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

def get_github_token():
    """Retrieves the GitHub token from AWS Secrets Manager."""
    secret_name = os.environ.get("GITHUB_TOKEN_SECRET_NAME")
    if not secret_name:
        raise ValueError("GITHUB_TOKEN_SECRET_NAME environment variable not set.")

    secrets_manager = boto3.client("secretsmanager")

    try:
        response = secrets_manager.get_secret_value(SecretId=secret_name)
        secret_string = response['SecretString']

        # Parse the JSON secret to extract the GITHUB_TOKEN value
        try:
            secret_data = json.loads(secret_string)
            github_token = secret_data.get('GITHUB_TOKEN')
            if not github_token:
                raise ValueError("GITHUB_TOKEN key not found in secret JSON")
            return github_token
        except json.JSONDecodeError:
            # If it's not JSON, assume it's a plain string token (backward compatibility)
            logger.warning("Secret is not JSON format, treating as plain token string")
            return secret_string

    except Exception as e:
        logger.error(f"Failed to retrieve GitHub token from Secrets Manager: {e}")
        raise

import os
import json
import boto3
import hmac
import hashlib

# Initialize AWS clients
sfn_client = boto3.client("stepfunctions")
secrets_manager = boto3.client("secretsmanager")

def lambda_handler(event, context):
    """
    Handles and validates incoming GitHub webhooks.
    This function now performs signature validation before starting the Step Function.
    """
    print("--- Webhook Handler Invoked ---")

    # --- 1. Signature Validation ---
    try:
        secret_name = os.environ.get("GITHUB_WEBHOOK_SECRET_NAME")
        secret_response = secrets_manager.get_secret_value(SecretId=secret_name)
        webhook_secret = secret_response["SecretString"]

        headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
        github_signature = headers.get("x-hub-signature-256")
        
        if not github_signature:
            print("ERROR: Request is missing X-Hub-Signature-256 header.")
            return error_response("Unauthorized", 401)
        
        request_body = event.get("body", "")
        if request_body is None:
            request_body = ""

        hash_object = hmac.new(webhook_secret.encode('utf-8'), msg=request_body.encode('utf-8'), digestmod=hashlib.sha256)
        expected_signature = "sha256=" + hash_object.hexdigest()
        
        if not hmac.compare_digest(expected_signature, github_signature):
            print("ERROR: Computed signature does not match GitHub signature.")
            return error_response("Unauthorized", 401)

        print("SUCCESS: Signature validated successfully.")

    except Exception as e:
        print(f"ERROR: An exception occurred during signature validation: {e}")
        return error_response("Internal Server Error", 500)

    # --- 2. Process the Validated Request ---
    try:
        # Handle ping event for initial setup
        if headers.get("x-github-event") == "ping":
            return success_response("Ping event successful.")

        body = json.loads(request_body)
        
        if body.get("action") not in ["opened", "reopened", "synchronize"]:
            return success_response(f"Ignoring action: {body.get('action', 'N/A')}")

        pull_request = body.get("pull_request", {})
        repository = body.get("repository", {})

        pr_details = {
            "pull_request_id": str(pull_request.get("id")),
            "repository_full_name": repository.get("full_name"),
            "commit_sha": pull_request.get("head", {}).get("sha"),
            "pr_number": pull_request.get("number")
        }

        # Get all scanner function ARNs
        secret_scanner_arn = os.environ.get("SECRET_SCANNER_FUNCTION_ARN")
        vulnerability_scanner_arn = os.environ.get("VULNERABILITY_SCANNER_FUNCTION_ARN")
        ai_reviewer_arn = os.environ.get("AI_REVIEWER_FUNCTION_ARN")
        
        # Create the Step Functions input with all three scanners
        sfn_input = {
            "repo_details": pr_details,
            "analysis_types": [
                {
                    "type": "secrets",
                    "function_name": secret_scanner_arn,
                    "payload": {"repo_details": pr_details}
                },
                {
                    "type": "vulnerabilities",
                    "function_name": vulnerability_scanner_arn,
                    "payload": {"repo_details": pr_details}
                },
                {
                    "type": "ai_review",
                    "function_name": ai_reviewer_arn,
                    "payload": {"repo_details": pr_details}
                }
            ]
        }
        
        state_machine_arn = os.environ.get("STATE_MACHINE_ARN")
        execution_name = f"pr-{pr_details['repository_full_name'].replace('/', '-')}-{pr_details['pr_number']}-{pr_details['commit_sha'][:7]}"
        
        response = sfn_client.start_execution(
            stateMachineArn=state_machine_arn,
            input=json.dumps(sfn_input),
            name=execution_name
        )
        
        print(f"SUCCESS: Started Step Function execution: {response['executionArn']}")
        return success_response(f"Analysis started for PR #{pr_details['pr_number']}")

    except Exception as e:
        print(f"ERROR: An unexpected error occurred during processing: {e}")
        return error_response("Failed to process request.", 500)

def success_response(message):
    return {"statusCode": 200, "body": json.dumps({"message": message})}

def error_response(message, status_code=400):
    return {"statusCode": status_code, "body": json.dumps({"error": message})}
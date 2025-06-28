import json
import os

def lambda_handler(event, context):
    results = {
        "opt_contents": [],
        "bin_contents": [],
        "python_contents": []
    }
    
    if os.path.exists('/opt'):
        results["opt_contents"] = os.listdir('/opt')
        
        if os.path.exists('/opt/bin'):
            results["bin_contents"] = os.listdir('/opt/bin')
            
        if os.path.exists('/opt/python'):
            results["python_contents"] = os.listdir('/opt/python')
    
    return {
        'statusCode': 200,
        'body': json.dumps(results, indent=2)
    }

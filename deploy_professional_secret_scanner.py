#!/usr/bin/env python3
"""
Professional Multi-Tool Secret Scanner Deployment Script
Enterprise-grade deployment with multiple security tools
"""

import os
import subprocess
import sys
import tempfile
import zipfile
import requests
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Professional tool configurations
SECURITY_TOOLS = {
    "trufflehog": {
        "version": "3.63.2",
        "url": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_linux_amd64.tar.gz",
        "binary": "trufflehog"
    },
    "gitleaks": {
        "version": "8.18.0",
        "url": "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_linux_x64.tar.gz",
        "binary": "gitleaks"
    },
    "semgrep": {
        "version": "1.45.0",
        "url": "https://github.com/returntocorp/semgrep/releases/download/v{version}/semgrep-v{version}-ubuntu-20.04-x86_64.tgz",
        "binary": "semgrep"
    }
}

def download_and_extract_tool(tool_name: str, config: dict, extract_dir: str) -> bool:
    """Download and extract a security tool."""
    try:
        url = config["url"].format(version=config["version"])
        logger.info(f"Downloading {tool_name} v{config['version']} from {url}")
        
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Create temporary file for download
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp_file:
            for chunk in response.iter_content(chunk_size=8192):
                tmp_file.write(chunk)
            tmp_path = tmp_file.name
        
        # Extract the tool
        tool_extract_dir = os.path.join(extract_dir, tool_name)
        os.makedirs(tool_extract_dir, exist_ok=True)
        
        subprocess.run(['tar', '-xzf', tmp_path, '-C', tool_extract_dir], check=True)
        
        # Find the binary and move it to the bin directory
        bin_dir = os.path.join(extract_dir, 'bin')
        os.makedirs(bin_dir, exist_ok=True)
        
        # Look for the binary in the extracted directory
        for root, dirs, files in os.walk(tool_extract_dir):
            if config["binary"] in files:
                binary_path = os.path.join(root, config["binary"])
                target_path = os.path.join(bin_dir, config["binary"])
                subprocess.run(['cp', binary_path, target_path], check=True)
                subprocess.run(['chmod', '+x', target_path], check=True)
                logger.info(f"✅ {tool_name} binary installed at {target_path}")
                break
        else:
            logger.error(f"❌ Could not find {config['binary']} binary for {tool_name}")
            return False
        
        # Cleanup
        os.unlink(tmp_path)
        subprocess.run(['rm', '-rf', tool_extract_dir], check=True)
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to download {tool_name}: {e}")
        return False

def create_professional_layer():
    """Create a professional Lambda layer with multiple security tools."""
    logger.info("🎯 Creating professional multi-tool Lambda layer...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        layer_dir = os.path.join(temp_dir, 'layer')
        os.makedirs(layer_dir, exist_ok=True)
        
        # Download all security tools
        success_count = 0
        for tool_name, config in SECURITY_TOOLS.items():
            if download_and_extract_tool(tool_name, config, layer_dir):
                success_count += 1
        
        logger.info(f"Successfully downloaded {success_count}/{len(SECURITY_TOOLS)} tools")
        
        # Create the layer zip
        layer_zip_path = os.path.join(temp_dir, 'professional-scanner-layer.zip')
        with zipfile.ZipFile(layer_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(layer_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, layer_dir)
                    zipf.write(file_path, arcname)
        
        # Check layer size
        layer_size = os.path.getsize(layer_zip_path)
        logger.info(f"Professional layer size: {layer_size / (1024*1024):.1f} MB")
        
        if layer_size > 50 * 1024 * 1024:  # 50MB limit for direct upload
            logger.info("Layer too large for direct upload, using S3...")
            return upload_layer_via_s3(layer_zip_path)
        else:
            return upload_layer_direct(layer_zip_path)

def upload_layer_direct(layer_zip_path: str) -> str:
    """Upload layer directly to Lambda."""
    logger.info("Uploading layer directly to Lambda...")
    
    cmd = [
        'aws', 'lambda', 'publish-layer-version',
        '--layer-name', 'professional-scanner-tools',
        '--description', 'Professional multi-tool security scanner layer (TruffleHog, GitLeaks, Semgrep)',
        '--zip-file', f'fileb://{layer_zip_path}',
        '--compatible-runtimes', 'python3.9', 'python3.10', 'python3.11',
        '--region', 'us-east-1'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    layer_info = eval(result.stdout)  # Parse AWS CLI JSON output
    layer_arn = layer_info['LayerVersionArn']
    
    logger.info(f"✅ Professional layer published: {layer_arn}")
    return layer_arn

def upload_layer_via_s3(layer_zip_path: str) -> str:
    """Upload large layer via S3."""
    logger.info("Uploading large layer via S3...")
    
    # Upload to S3 first
    s3_bucket = "devsecops-sentinel-layers"  # You may need to create this bucket
    s3_key = "professional-scanner-layer.zip"
    
    subprocess.run([
        'aws', 's3', 'cp', layer_zip_path, f's3://{s3_bucket}/{s3_key}',
        '--region', 'us-east-1'
    ], check=True)
    
    # Publish layer from S3
    cmd = [
        'aws', 'lambda', 'publish-layer-version',
        '--layer-name', 'professional-scanner-tools',
        '--description', 'Professional multi-tool security scanner layer (TruffleHog, GitLeaks, Semgrep)',
        '--content', f'S3Bucket={s3_bucket},S3Key={s3_key}',
        '--compatible-runtimes', 'python3.9', 'python3.10', 'python3.11',
        '--region', 'us-east-1'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    layer_info = eval(result.stdout)
    layer_arn = layer_info['LayerVersionArn']
    
    logger.info(f"✅ Professional layer published via S3: {layer_arn}")
    return layer_arn

def deploy_professional_scanner():
    """Deploy the professional multi-tool secret scanner."""
    logger.info("🚀 Deploying Professional Multi-Tool Secret Scanner...")
    
    try:
        # Create and upload the professional layer
        layer_arn = create_professional_layer()
        
        # Package the Lambda function
        logger.info("Packaging Lambda function...")
        
        # Create deployment package
        with tempfile.TemporaryDirectory() as temp_dir:
            # Copy Lambda code
            lambda_dir = os.path.join(temp_dir, 'lambda')
            os.makedirs(lambda_dir, exist_ok=True)
            
            subprocess.run([
                'cp', '-r', 'src/lambdas/secret_scanner/', lambda_dir
            ], check=True)
            
            # Create zip
            zip_path = os.path.join(temp_dir, 'professional-secret-scanner.zip')
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(lambda_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, lambda_dir)
                        zipf.write(file_path, arcname)
            
            # Update Lambda function
            logger.info("Updating Lambda function...")
            subprocess.run([
                'aws', 'lambda', 'update-function-code',
                '--function-name', 'devsecops-sentinel-SecretScannerFunction-w0XQI2GV65HU',
                '--zip-file', f'fileb://{zip_path}',
                '--region', 'us-east-1'
            ], check=True)
            
            # Update function configuration to use the new layer
            logger.info("Updating function configuration...")
            subprocess.run([
                'aws', 'lambda', 'update-function-configuration',
                '--function-name', 'devsecops-sentinel-SecretScannerFunction-w0XQI2GV65HU',
                '--layers', layer_arn,
                '--timeout', '300',  # 5 minutes for comprehensive scanning
                '--memory-size', '1024',  # More memory for multiple tools
                '--region', 'us-east-1'
            ], check=True)
        
        logger.info("🎯 Professional Multi-Tool Secret Scanner deployed successfully!")
        logger.info("Features:")
        logger.info("  ✅ TruffleHog (high-precision ML detection)")
        logger.info("  ✅ GitLeaks (comprehensive pattern matching)")
        logger.info("  ✅ Semgrep (semantic analysis)")
        logger.info("  ✅ Intelligent deduplication")
        logger.info("  ✅ Confidence scoring")
        logger.info("  ✅ Enterprise-grade orchestration")
        
    except Exception as e:
        logger.error(f"❌ Deployment failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    deploy_professional_scanner()

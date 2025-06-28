#!/usr/bin/env python3
"""
Build a comprehensive Lambda layer that includes both binaries and Python packages
"""

import os
import subprocess
import shutil
import tempfile
import zipfile
from pathlib import Path

def download_existing_layer(layer_arn, download_path):
    """Download an existing layer to extract its contents"""
    print(f"Downloading layer: {layer_arn}")
    
    # Get the layer download URL
    result = subprocess.run([
        'aws', 'lambda', 'get-layer-version', 
        '--layer-name', 'DevSecOps-Scanner-Layer',
        '--version-number', '1',
        '--region', 'us-east-1',
        '--query', 'Content.Location',
        '--output', 'text'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"Failed to get layer URL: {result.stderr}")
    
    download_url = result.stdout.strip()
    print(f"Download URL: {download_url}")
    
    # Download the layer zip file
    import urllib.request
    urllib.request.urlretrieve(download_url, download_path)
    print(f"Downloaded layer to: {download_path}")

def extract_layer(zip_path, extract_path):
    """Extract a layer zip file"""
    print(f"Extracting {zip_path} to {extract_path}")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

def build_comprehensive_layer():
    """Build a comprehensive layer with both binaries and Python packages"""
    
    # Create temporary directories
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Paths for different components
        binary_layer_zip = temp_path / "binary_layer.zip"
        binary_extract = temp_path / "binary_extract"
        python_layer_zip = temp_path / "python_layer.zip"
        python_extract = temp_path / "python_extract"
        comprehensive_layer = temp_path / "comprehensive_layer"
        
        # Create directories
        binary_extract.mkdir()
        python_extract.mkdir()
        comprehensive_layer.mkdir()
        
        print("=== Downloading existing binary layer ===")
        download_existing_layer("DevSecOps-Scanner-Layer:1", binary_layer_zip)
        
        print("=== Extracting binary layer ===")
        extract_layer(binary_layer_zip, binary_extract)
        
        print("=== Downloading our Python packages layer ===")
        # Download our Python packages layer
        result = subprocess.run([
            'aws', 'lambda', 'get-layer-version',
            '--layer-name', 'DevSecOpsSentinel-Scanner',
            '--version-number', '12',
            '--region', 'us-east-1',
            '--query', 'Content.Location',
            '--output', 'text'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Failed to get Python layer URL: {result.stderr}")
        
        python_url = result.stdout.strip()
        import urllib.request
        urllib.request.urlretrieve(python_url, python_layer_zip)
        
        print("=== Extracting Python packages layer ===")
        extract_layer(python_layer_zip, python_extract)
        
        print("=== Combining layers ===")
        
        # Copy binary layer contents
        if (binary_extract / "bin").exists():
            shutil.copytree(binary_extract / "bin", comprehensive_layer / "bin")
            print("Copied bin/ directory from binary layer")
        
        if (binary_extract / "opt").exists():
            shutil.copytree(binary_extract / "opt", comprehensive_layer / "opt")
            print("Copied opt/ directory from binary layer")
        
        # Copy Python packages
        if (python_extract / "python").exists():
            if (comprehensive_layer / "python").exists():
                # Merge Python directories
                shutil.copytree(python_extract / "python", comprehensive_layer / "python", dirs_exist_ok=True)
            else:
                shutil.copytree(python_extract / "python", comprehensive_layer / "python")
            print("Copied python/ directory from Python packages layer")
        
        print("=== Creating comprehensive layer zip ===")
        
        # Create the final zip file
        output_zip = Path.cwd() / "comprehensive-scanner-layer.zip"
        
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(comprehensive_layer):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(comprehensive_layer)
                    zipf.write(file_path, arcname)
        
        print(f"=== Comprehensive layer created: {output_zip} ===")
        
        # Get file size
        size_mb = output_zip.stat().st_size / (1024 * 1024)
        print(f"Layer size: {size_mb:.2f} MB")
        
        if size_mb > 250:
            print("⚠️  WARNING: Layer size exceeds 250MB limit!")
        else:
            print("✅ Layer size is within limits")
        
        return output_zip

if __name__ == "__main__":
    try:
        layer_path = build_comprehensive_layer()
        print(f"\n🎉 Success! Comprehensive layer built: {layer_path}")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

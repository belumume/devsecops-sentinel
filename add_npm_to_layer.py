#!/usr/bin/env python3
"""
Add npm to our existing Python packages layer
"""

import os
import subprocess
import tempfile
import zipfile
import urllib.request
import tarfile
import shutil
from pathlib import Path

def add_npm_to_existing_layer():
    """Add npm to our existing Python packages layer"""
    
    print("🚀 Adding npm to existing Python packages layer")
    
    # Download our existing layer
    print("⬇️  Downloading existing Python packages layer...")
    
    result = subprocess.run([
        'aws', 'lambda', 'get-layer-version',
        '--layer-name', 'DevSecOpsSentinel-Scanner',
        '--version-number', '12',
        '--region', 'us-east-1',
        '--query', 'Content.Location',
        '--output', 'text'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Failed to get layer URL: {result.stderr}")
        return None
    
    layer_url = result.stdout.strip()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Download existing layer
        existing_layer_zip = temp_path / "existing_layer.zip"
        urllib.request.urlretrieve(layer_url, existing_layer_zip)
        print("✅ Downloaded existing layer")
        
        # Extract existing layer
        extract_dir = temp_path / "extracted"
        extract_dir.mkdir()
        
        with zipfile.ZipFile(existing_layer_zip, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        print("✅ Extracted existing layer")
        
        # Download and add npm
        print("📦 Downloading Node.js and npm...")
        
        node_url = "https://nodejs.org/dist/v18.20.5/node-v18.20.5-linux-x64.tar.xz"
        node_archive = temp_path / "node.tar.xz"
        
        urllib.request.urlretrieve(node_url, node_archive)
        print("✅ Downloaded Node.js")
        
        # Extract Node.js
        node_extract = temp_path / "node_extract"
        node_extract.mkdir()
        
        with tarfile.open(node_archive, 'r:xz') as tar:
            tar.extractall(node_extract)
        
        # Find Node.js directory
        node_dirs = [d for d in node_extract.iterdir() if d.is_dir() and d.name.startswith('node-')]
        if not node_dirs:
            print("❌ Node.js directory not found")
            return None
        
        node_dir = node_dirs[0]
        
        # Create bin directory in layer
        bin_dir = extract_dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        
        # Copy node and npm
        node_bin = node_dir / "bin" / "node"
        npm_bin = node_dir / "bin" / "npm"
        
        if node_bin.exists() and npm_bin.exists():
            shutil.copy2(node_bin, bin_dir / "node")
            shutil.copy2(npm_bin, bin_dir / "npm")
            
            # Make executable
            os.chmod(bin_dir / "node", 0o755)
            os.chmod(bin_dir / "npm", 0o755)
            
            # Copy npm lib
            npm_lib_src = node_dir / "lib" / "node_modules" / "npm"
            if npm_lib_src.exists():
                lib_dir = extract_dir / "lib" / "node_modules"
                lib_dir.mkdir(parents=True, exist_ok=True)
                shutil.copytree(npm_lib_src, lib_dir / "npm", dirs_exist_ok=True)
            
            print("✅ Added Node.js and npm to layer")
        else:
            print("❌ Node.js or npm binaries not found")
            return None
        
        # Create new layer zip
        output_zip = Path("enhanced-scanner-layer.zip")
        if output_zip.exists():
            output_zip.unlink()
        
        print("📦 Creating enhanced layer zip...")
        
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(extract_dir)
                    zipf.write(file_path, arcname)
        
        # Check size
        size_mb = output_zip.stat().st_size / (1024 * 1024)
        print(f"📊 Enhanced layer size: {size_mb:.2f} MB")
        
        if size_mb > 50:
            print("⚠️  WARNING: Layer size exceeds 50MB zipped limit!")
            return None
        
        print(f"✅ Enhanced layer created: {output_zip}")
        return output_zip

if __name__ == "__main__":
    try:
        layer_path = add_npm_to_existing_layer()
        if layer_path:
            print(f"\n🎉 Success! Enhanced layer built: {layer_path}")
        else:
            print("\n❌ Failed to build enhanced layer")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

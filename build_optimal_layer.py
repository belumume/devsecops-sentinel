#!/usr/bin/env python3
"""
Build optimal comprehensive Lambda layer
"""

import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

def build_optimal_layer():
    """Build a single comprehensive layer with all tools"""
    
    print("🚀 Building Optimal Comprehensive Scanner Layer")
    
    # Create layer structure
    layer_dir = Path("comprehensive_layer")
    if layer_dir.exists():
        import shutil
        shutil.rmtree(layer_dir)
    
    layer_dir.mkdir()
    
    # Create directory structure
    bin_dir = layer_dir / "bin"
    python_dir = layer_dir / "python"
    opt_bin_dir = layer_dir / "opt" / "bin"
    
    bin_dir.mkdir()
    python_dir.mkdir()
    opt_bin_dir.mkdir(parents=True)
    
    print("📁 Created layer directory structure")
    
    # Step 1: Install Python packages
    print("🐍 Installing Python packages...")
    
    python_packages = [
        "safety",
        "bandit",
        "semgrep",
        "pip-audit",
        "requests",
        "pyyaml",
        "click",
        "rich",
        "packaging",
        "tenacity"
    ]
    
    # Install to python directory (simplified approach)
    cmd = [
        "pip", "install", "--target", str(python_dir),
        "--upgrade"
    ] + python_packages
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Failed to install Python packages: {result.stderr}")
        return None
    
    print("✅ Python packages installed")
    
    # Step 2: Download and install binary tools
    print("🔧 Installing binary tools...")
    
    # Install Node.js and npm (using NodeSource binary)
    print("📦 Installing Node.js and npm...")
    
    # Download Node.js binary for Linux x64
    node_url = "https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.xz"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        node_archive = temp_path / "node.tar.xz"
        
        # Download Node.js
        import urllib.request
        print(f"⬇️  Downloading Node.js from {node_url}")
        urllib.request.urlretrieve(node_url, node_archive)
        
        # Extract Node.js
        import tarfile
        with tarfile.open(node_archive, 'r:xz') as tar:
            tar.extractall(temp_path)
        
        # Find extracted directory
        node_dirs = [d for d in temp_path.iterdir() if d.is_dir() and d.name.startswith('node-')]
        if not node_dirs:
            print("❌ Failed to find extracted Node.js directory")
            return None
        
        node_dir = node_dirs[0]
        
        # Copy node and npm binaries
        node_bin = node_dir / "bin" / "node"
        npm_bin = node_dir / "bin" / "npm"
        
        if node_bin.exists():
            import shutil
            shutil.copy2(node_bin, opt_bin_dir / "node")
            shutil.copy2(npm_bin, opt_bin_dir / "npm")
            
            # Copy npm lib directory
            npm_lib = node_dir / "lib" / "node_modules" / "npm"
            if npm_lib.exists():
                shutil.copytree(npm_lib, layer_dir / "lib" / "node_modules" / "npm")
            
            print("✅ Node.js and npm installed")
        else:
            print("❌ Node.js binary not found in archive")
    
    # Install git (copy from system if available, or download)
    print("🔧 Installing git...")
    git_paths = ["/usr/bin/git", "/bin/git"]
    git_found = False
    
    for git_path in git_paths:
        if os.path.exists(git_path):
            import shutil
            shutil.copy2(git_path, opt_bin_dir / "git")
            git_found = True
            print("✅ Git installed from system")
            break
    
    if not git_found:
        print("⚠️  Git not found on system, will need to be provided by existing layer")
    
    # Install trufflehog
    print("🔍 Installing trufflehog...")
    trufflehog_url = "https://github.com/trufflesecurity/trufflehog/releases/download/v3.84.2/trufflehog_3.84.2_linux_amd64.tar.gz"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        trufflehog_archive = temp_path / "trufflehog.tar.gz"
        
        # Download trufflehog
        import urllib.request
        print(f"⬇️  Downloading trufflehog from {trufflehog_url}")
        urllib.request.urlretrieve(trufflehog_url, trufflehog_archive)
        
        # Extract trufflehog
        import tarfile
        with tarfile.open(trufflehog_archive, 'r:gz') as tar:
            tar.extractall(temp_path)
        
        # Copy trufflehog binary
        trufflehog_bin = temp_path / "trufflehog"
        if trufflehog_bin.exists():
            import shutil
            shutil.copy2(trufflehog_bin, opt_bin_dir / "trufflehog")
            # Make executable
            os.chmod(opt_bin_dir / "trufflehog", 0o755)
            print("✅ Trufflehog installed")
        else:
            print("❌ Trufflehog binary not found in archive")
    
    # Install safety binary (create wrapper script)
    print("🛡️  Creating safety wrapper...")
    safety_wrapper = opt_bin_dir / "safety"
    safety_wrapper.write_text(f"""#!/bin/bash
export PYTHONPATH="/opt/python:$PYTHONPATH"
/var/lang/bin/python3 -m safety "$@"
""")
    os.chmod(safety_wrapper, 0o755)
    print("✅ Safety wrapper created")
    
    # Step 3: Create the layer zip
    print("📦 Creating layer zip file...")
    
    output_zip = Path("comprehensive-scanner-layer.zip")
    if output_zip.exists():
        output_zip.unlink()
    
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for root, dirs, files in os.walk(layer_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(layer_dir)
                zipf.write(file_path, arcname)
    
    # Get file size
    size_mb = output_zip.stat().st_size / (1024 * 1024)
    print(f"📊 Layer size: {size_mb:.2f} MB")
    
    if size_mb > 50:
        print("⚠️  WARNING: Layer size exceeds 50MB zipped limit!")
        return None
    
    print(f"✅ Comprehensive layer created: {output_zip}")
    return output_zip

if __name__ == "__main__":
    try:
        layer_path = build_optimal_layer()
        if layer_path:
            print(f"\n🎉 Success! Comprehensive layer built: {layer_path}")
        else:
            print("\n❌ Failed to build layer")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

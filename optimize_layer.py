#!/usr/bin/env python3
"""
Optimize the layer by removing unnecessary files
"""

import os
import shutil
import zipfile
from pathlib import Path

def optimize_layer():
    """Optimize the layer by removing unnecessary files"""
    
    print("🔧 Optimizing comprehensive layer...")
    
    layer_dir = Path("comprehensive_layer")
    if not layer_dir.exists():
        print("❌ Layer directory not found")
        return None
    
    python_dir = layer_dir / "python"
    if not python_dir.exists():
        print("❌ Python directory not found")
        return None
    
    # Remove unnecessary files to reduce size
    files_to_remove = [
        "**/__pycache__",
        "**/*.pyc", 
        "**/*.pyo",
        "**/tests",
        "**/test",
        "**/*.dist-info",
        "**/docs",
        "**/examples",
        "**/benchmarks",
        "**/*.so",  # Remove compiled extensions that won't work in Lambda
        "**/bin",   # Remove binary directories from Python packages
    ]
    
    removed_count = 0
    
    for pattern in files_to_remove:
        for path in python_dir.rglob(pattern):
            try:
                if path.is_file():
                    path.unlink()
                    removed_count += 1
                elif path.is_dir():
                    shutil.rmtree(path)
                    removed_count += 1
            except Exception as e:
                print(f"⚠️ Could not remove {path}: {e}")
    
    print(f"✅ Removed {removed_count} unnecessary files/directories")
    
    # Remove large packages that aren't essential
    large_packages_to_remove = [
        "opentelemetry*",
        "semgrep",  # Too large, we'll use fallback detection
        "nltk",     # Large NLP package not needed
        "protobuf", # Large protobuf package
    ]
    
    for pattern in large_packages_to_remove:
        for path in python_dir.rglob(pattern):
            if path.is_dir():
                try:
                    shutil.rmtree(path)
                    print(f"✅ Removed large package: {path.name}")
                except Exception as e:
                    print(f"⚠️ Could not remove {path}: {e}")
    
    # Create optimized zip
    print("📦 Creating optimized layer zip...")
    
    output_zip = Path("optimized-scanner-layer.zip")
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
    print(f"📊 Optimized layer size: {size_mb:.2f} MB")
    
    # Estimate unzipped size (roughly 3-4x compressed size)
    estimated_unzipped_mb = size_mb * 3.5
    print(f"📊 Estimated unzipped size: {estimated_unzipped_mb:.2f} MB")
    
    if estimated_unzipped_mb > 250:
        print("⚠️ WARNING: Estimated unzipped size may still exceed 250MB limit!")
    else:
        print("✅ Estimated unzipped size should be within limits")
    
    print(f"✅ Optimized layer created: {output_zip}")
    return output_zip

if __name__ == "__main__":
    try:
        layer_path = optimize_layer()
        if layer_path:
            print(f"\n🎉 Success! Optimized layer built: {layer_path}")
        else:
            print("\n❌ Failed to optimize layer")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

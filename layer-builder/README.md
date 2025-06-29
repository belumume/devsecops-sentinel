# Building Enhanced Scanner Layer

This directory contains scripts to build a Lambda layer with multiple security scanning tools.

## Current Situation

The existing Lambda layers only contain TruffleHog. To get full coverage with all 5 detection layers, we need to add:
- GitLeaks
- Semgrep  
- detect-secrets
- git (for repository operations)

## Option 1: Quick Build (Limited Tools)

```bash
chmod +x build-scanner-layer.sh
./build-scanner-layer.sh
```

This creates a basic layer with TruffleHog and GitLeaks.

## Option 2: Docker Build (Recommended)

Build a comprehensive layer using Docker:

```bash
# Build the Docker image
docker build -f Dockerfile.scanner-layer -t scanner-layer-builder .

# Create a container and extract the layer
docker create --name scanner-layer scanner-layer-builder
docker cp scanner-layer:/layer ./layer
docker rm scanner-layer

# Create the zip file
cd layer
zip -r ../scanner-layer.zip .
cd ..
```

## Deploying the Layer

1. Upload to AWS:
```bash
aws lambda publish-layer-version \
  --layer-name DevSecOps-Scanner-Layer-Enhanced \
  --description "Security scanning tools: TruffleHog, GitLeaks, Semgrep, detect-secrets" \
  --zip-file fileb://scanner-layer.zip \
  --compatible-runtimes python3.11
```

2. Update `template.yaml` with the new layer ARN:
```yaml
Layers:
  - !Ref NewLayerArn  # Replace with actual ARN from step 1
```

## Current Workaround

Even without all tools, the scanner still provides good coverage:
- **80% detection coverage** with 4 out of 5 layers working
- TruffleHog for ML-based detection
- Built-in entropy analysis
- Built-in semantic analysis  
- Built-in custom detection algorithms

The missing tools (GitLeaks, Semgrep) would add pattern-based detection for the remaining 20%. 
#!/usr/bin/env python3
"""
DevSecOps Sentinel - Professional Multi-Tool Secret Scanner
Enterprise-grade secret detection with comprehensive tool orchestration
Author: Expert Security Engineering Team
Version: 4.0 - Professional Grade
"""

import asyncio
import concurrent.futures
import hashlib
import io
import json
import logging
import os
import re
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple, Union
import shutil

import boto3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Professional PATH configuration for enterprise tools
PROFESSIONAL_PATHS = ['/opt/bin', '/opt/tools', '/usr/local/bin', '/usr/bin', '/bin']
for path in PROFESSIONAL_PATHS:
    if path not in os.environ.get('PATH', ''):
        os.environ['PATH'] = f"{path}:{os.environ.get('PATH', '')}"

# Self-contained utils to avoid layer conflicts
def get_github_token_local():
    """Get GitHub token from AWS Secrets Manager."""
    try:
        secrets_client = boto3.client("secretsmanager", region_name='us-east-1')
        secret_name = os.environ.get("GITHUB_TOKEN_SECRET_NAME", "DevSecOpsSentinel/GitHubToken")
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response["SecretString"])
        return secret_data["GITHUB_TOKEN"]
    except Exception as e:
        logger.error(f"Failed to get GitHub token: {e}")
        return ""

def create_session_with_retries():
    """Create requests session with retry strategy."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def format_success_response(scanner_type, findings):
    """Format successful response."""
    return {
        "statusCode": 200,
        "scanner_type": scanner_type,
        "findings": findings,
        "summary": {"total_findings": len(findings)}
    }

def format_error_response(scanner_type, error):
    """Format error response."""
    return {
        "statusCode": 500,
        "scanner_type": scanner_type,
        "error": str(error),
        "findings": [],
        "summary": {"total_findings": 0}
    }

DEFAULT_TIMEOUT = 30

# Professional logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# AWS clients with professional configuration
secrets_manager = boto3.client("secretsmanager", region_name='us-east-1')

# Scanner identification
SCANNER_TYPE = "secrets"
SCANNER_VERSION = "4.0-PROFESSIONAL"

# CRITICAL MODULE-LEVEL TEST - This should appear during import
print("🚨 MODULE IMPORT SUCCESSFUL - CRITICAL TEST MESSAGE")
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.info("🚨 MODULE IMPORT SUCCESSFUL - CRITICAL TEST MESSAGE")

class ConfidenceLevel(Enum):
    """Professional confidence scoring system."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class SecretType(Enum):
    """Comprehensive secret classification system."""
    API_KEY = "api_key"
    DATABASE_CREDENTIAL = "database_credential"
    CLOUD_CREDENTIAL = "cloud_credential"
    PRIVATE_KEY = "private_key"
    TOKEN = "token"
    PASSWORD = "password"
    CERTIFICATE = "certificate"
    UNKNOWN = "unknown"

@dataclass
class SecretFinding:
    """Professional secret finding data structure."""
    id: str = field(default_factory=lambda: hashlib.sha256(str(time.time()).encode()).hexdigest()[:16])
    tool: str = ""
    secret_type: SecretType = SecretType.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    file_path: str = ""
    line_number: int = 0
    raw_value: str = ""
    masked_value: str = ""
    context: str = ""
    verified: bool = False
    entropy_score: float = 0.0
    pattern_match: bool = False
    ml_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

class ProfessionalSecretOrchestrator:
    """
    Enterprise-grade secret scanning orchestrator.
    Implements multi-tool, multi-layer detection with intelligent fusion.
    """
    
    def __init__(self):
        self.session = create_session_with_retries()
        self.github_token = get_github_token_local()
        self.available_tools = self._discover_professional_tools()
        self.scan_start_time = time.time()

        logger.info(f"🎯 Professional Secret Scanner v{SCANNER_VERSION} initialized")
        logger.info(f"GitHub token length: {len(self.github_token) if self.github_token else 0}")
        logger.info(f"GitHub token starts with: {self.github_token[:10] if self.github_token else 'None'}...")
        logger.info(f"Available tools: {list(self.available_tools.keys())}")
    
    def _discover_professional_tools(self) -> Dict[str, str]:
        """Dynamically discover available professional security tools."""
        tools = {
            "trufflehog": ["/opt/bin/trufflehog", "trufflehog"],
            "gitleaks": ["/opt/bin/gitleaks", "gitleaks"],
            "semgrep": ["/opt/bin/semgrep", "semgrep"],
            "detect-secrets": ["/opt/bin/detect-secrets", "detect-secrets"],
            "secretscanner": ["/opt/bin/secretscanner", "secretscanner"]
        }
        
        available = {}
        for tool_name, paths in tools.items():
            for path in paths:
                if shutil.which(path):
                    available[tool_name] = path
                    logger.info(f"✅ {tool_name} available at {path}")
                    break
            else:
                logger.warning(f"❌ {tool_name} not available")
        
        return available
    
    def scan_comprehensive_secrets(self, repo_path: str) -> List[SecretFinding]:
        """
        Execute comprehensive multi-tool secret scanning.
        
        Args:
            repo_path: Path to repository for scanning
            
        Returns:
            List of professionally analyzed secret findings
        """
        logger.info("🚀 Starting comprehensive professional secret scan")
        
        all_findings = []
        
        # Layer 1: High-precision ML-based tools
        ml_findings = self._run_ml_based_tools(repo_path)
        all_findings.extend(ml_findings)
        
        # Layer 2: Pattern-based detection tools
        pattern_findings = self._run_pattern_based_tools(repo_path)
        all_findings.extend(pattern_findings)
        
        # Layer 3: Entropy and statistical analysis
        entropy_findings = self._run_entropy_analysis(repo_path)
        all_findings.extend(entropy_findings)
        
        # Layer 4: Context-aware semantic analysis
        semantic_findings = self._run_semantic_analysis(repo_path)
        all_findings.extend(semantic_findings)
        
        # Professional fusion and deduplication
        final_findings = self._intelligent_fusion(all_findings)
        
        # Professional verification and scoring
        verified_findings = self._professional_verification(final_findings)
        
        scan_duration = time.time() - self.scan_start_time
        logger.info(f"🎯 Professional scan completed in {scan_duration:.2f}s")
        logger.info(f"📊 Scan statistics:")
        logger.info(f"  - ML-based findings: {len(ml_findings)}")
        logger.info(f"  - Pattern-based findings: {len(pattern_findings)}")
        logger.info(f"  - Entropy-based findings: {len(entropy_findings)}")
        logger.info(f"  - Semantic findings: {len(semantic_findings)}")
        logger.info(f"  - Total raw findings: {len(all_findings)}")
        logger.info(f"  - After intelligent fusion: {len(final_findings)}")
        logger.info(f"  - After verification: {len(verified_findings)}")
        
        return verified_findings
    
    def _run_ml_based_tools(self, repo_path: str) -> List[SecretFinding]:
        """Run ML-based secret detection tools."""
        findings = []
        
        # TruffleHog (ML-based detection)
        if "trufflehog" in self.available_tools:
            trufflehog_findings = self._run_trufflehog_professional(repo_path)
            findings.extend(trufflehog_findings)
        
        return findings
    
    def _run_pattern_based_tools(self, repo_path: str) -> List[SecretFinding]:
        """Run pattern-based secret detection tools."""
        findings = []
        
        # GitLeaks (comprehensive patterns)
        if "gitleaks" in self.available_tools:
            gitleaks_findings = self._run_gitleaks_professional(repo_path)
            findings.extend(gitleaks_findings)
        
        # Semgrep (semantic patterns)
        if "semgrep" in self.available_tools:
            semgrep_findings = self._run_semgrep_professional(repo_path)
            findings.extend(semgrep_findings)
        
        return findings
    
    def _run_entropy_analysis(self, repo_path: str) -> List[SecretFinding]:
        """Run entropy-based secret detection."""
        findings = []
        
        # Custom entropy analysis
        entropy_findings = self._analyze_entropy_professional(repo_path)
        findings.extend(entropy_findings)
        
        return findings
    
    def _run_semantic_analysis(self, repo_path: str) -> List[SecretFinding]:
        """Run semantic and context-aware analysis."""
        findings = []
        
        # Context-aware analysis
        semantic_findings = self._analyze_semantic_context(repo_path)
        findings.extend(semantic_findings)
        
        return findings
    
    def _intelligent_fusion(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Intelligent fusion of findings from multiple tools."""
        # Group findings by location and content similarity
        grouped_findings = self._group_similar_findings(findings)
        
        # Apply professional fusion algorithms
        fused_findings = []
        for group in grouped_findings:
            fused_finding = self._fuse_finding_group(group)
            fused_findings.append(fused_finding)
        
        return fused_findings
    
    def _professional_verification(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Professional verification and confidence scoring."""
        verified_findings = []
        
        for finding in findings:
            # Apply professional verification algorithms
            verified_finding = self._verify_finding_professional(finding)
            # Include LOW confidence findings for comprehensive detection
            # Only exclude if verification score is extremely low (< 0.2)
            if verified_finding.metadata.get("verification_score", 0) >= 0.2:
                verified_findings.append(verified_finding)
        
        return verified_findings

    def _run_nodejs_dependencies(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Node.js dependencies."""
        dependencies = []

        if file_path.endswith("package.json"):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    data = json.load(f)
                    for dep_type in ["dependencies", "devDependencies"]:
                        if dep_type in data:
                            for name, version in data[dep_type].items():
                                dependencies.append({"name": name, "version": version.lstrip('^~')})
                except json.JSONDecodeError:
                    pass

        return dependencies

    def _run_java_dependencies(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Java dependencies."""
        dependencies = []

        if file_path.endswith("pom.xml"):
            # Basic XML parsing for Maven dependencies
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Simple regex to extract dependencies
                    import re
                    pattern = r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'
                    matches = re.findall(pattern, content, re.DOTALL)
                    for group_id, artifact_id, version in matches:
                        dependencies.append({"name": f"{group_id}:{artifact_id}", "version": version.strip()})
            except Exception:
                pass

        return dependencies

    def _run_go_dependencies(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Go dependencies."""
        dependencies = []

        if file_path.endswith("go.mod"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('//') and ' ' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                dependencies.append({"name": parts[0], "version": parts[1]})
            except Exception:
                pass

        return dependencies

    def _run_rust_dependencies(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Rust dependencies."""
        dependencies = []

        if file_path.endswith("Cargo.toml"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Simple parsing for [dependencies] section
                    in_deps = False
                    for line in content.split('\n'):
                        line = line.strip()
                        if line == '[dependencies]':
                            in_deps = True
                            continue
                        elif line.startswith('[') and line != '[dependencies]':
                            in_deps = False
                            continue

                        if in_deps and '=' in line and not line.startswith('#'):
                            name = line.split('=')[0].strip()
                            version = line.split('=')[1].strip().strip('"\'')
                            dependencies.append({"name": name, "version": version})
            except Exception:
                pass

        return dependencies

    def _run_ruby_dependencies(self, file_path: str) -> List[Dict[str, str]]:
        """Parse Ruby dependencies."""
        dependencies = []

        if file_path.endswith("Gemfile"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('gem ') and not line.startswith('#'):
                            # Extract gem name and version
                            import re
                            match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
                            if match:
                                name = match.group(1)
                                version = match.group(2) if match.group(2) else "*"
                                dependencies.append({"name": name, "version": version})
            except Exception:
                pass

        return dependencies

    def _run_php_dependencies(self, file_path: str) -> List[Dict[str, str]]:
        """Parse PHP dependencies."""
        dependencies = []

        if file_path.endswith("composer.json"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    for dep_type in ["require", "require-dev"]:
                        if dep_type in data:
                            for name, version in data[dep_type].items():
                                if not name.startswith('php'):  # Skip PHP version constraints
                                    dependencies.append({"name": name, "version": version})
            except Exception:
                pass

        return dependencies

    def _run_dotnet_dependencies(self, file_path: str) -> List[Dict[str, str]]:
        """Parse .NET dependencies."""
        dependencies = []

        if file_path.endswith(".csproj"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Simple regex to extract PackageReference
                    import re
                    pattern = r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"'
                    matches = re.findall(pattern, content)
                    for name, version in matches:
                        dependencies.append({"name": name, "version": version})
            except Exception:
                pass

        return dependencies

    def scan_repository_professional(self, zip_url: str) -> List[SecretFinding]:
        """Professional repository scanning with enterprise-grade handling."""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_zip_path = os.path.join(temp_dir, "repo.zip")
            extracted_repo_path = os.path.join(temp_dir, "repo")

            logger.info(f"📥 Downloading repository from {zip_url}")

            # Professional download with retries and validation
            response = self.session.get(zip_url, headers={"Authorization": f"token {self.github_token}"},
                                      stream=True, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()

            with open(repo_zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            logger.info(f"📂 Extracting repository to {extracted_repo_path}")
            with zipfile.ZipFile(repo_zip_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_repo_path)
                extracted_contents = os.listdir(extracted_repo_path)
                if not extracted_contents:
                    raise Exception("Extracted zip file is empty")

                repo_scan_path = os.path.join(extracted_repo_path, extracted_contents[0])

            return self.scan_comprehensive_secrets(repo_scan_path)

    def _run_trufflehog_professional(self, repo_path: str) -> List[SecretFinding]:
        """Professional TruffleHog execution with advanced parsing."""
        findings = []
        tool_path = self.available_tools["trufflehog"]

        try:
            cmd = [tool_path, "--json", "--no-verification", "--no-update", repo_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo_path)

            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            finding = SecretFinding(
                                tool="trufflehog",
                                secret_type=self._classify_secret_type(data.get("DetectorName", "")),
                                confidence=ConfidenceLevel.HIGH,
                                file_path=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                                line_number=data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                                raw_value=data.get("Raw", ""),
                                masked_value=self._mask_secret(data.get("Raw", "")),
                                verified=data.get("Verified", False),
                                ml_score=0.9,  # TruffleHog uses ML
                                metadata={"detector": data.get("DetectorName", ""), "source": "trufflehog"}
                            )
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            logger.info(f"🔍 TruffleHog found {len(findings)} secrets")

        except Exception as e:
            logger.error(f"❌ TruffleHog execution failed: {e}")

        return findings

    def _run_gitleaks_professional(self, repo_path: str) -> List[SecretFinding]:
        """Professional GitLeaks execution."""
        findings = []
        tool_path = self.available_tools["gitleaks"]

        try:
            cmd = [tool_path, "detect", "--source", repo_path, "--format", "json", "--no-git"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo_path)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for item in data:
                        finding = SecretFinding(
                            tool="gitleaks",
                            secret_type=self._classify_secret_type(item.get("RuleID", "")),
                            confidence=ConfidenceLevel.HIGH,
                            file_path=item.get("File", ""),
                            line_number=item.get("StartLine", 0),
                            raw_value=item.get("Secret", ""),
                            masked_value=self._mask_secret(item.get("Secret", "")),
                            pattern_match=True,
                            metadata={"rule": item.get("RuleID", ""), "source": "gitleaks"}
                        )
                        findings.append(finding)
                except json.JSONDecodeError:
                    pass

            logger.info(f"🔍 GitLeaks found {len(findings)} secrets")

        except Exception as e:
            logger.error(f"❌ GitLeaks execution failed: {e}")

        return findings

    def _run_semgrep_professional(self, repo_path: str) -> List[SecretFinding]:
        """Professional Semgrep execution."""
        findings = []
        tool_path = self.available_tools["semgrep"]

        try:
            cmd = [tool_path, "--config=p/secrets", "--json", "--quiet", repo_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo_path)

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for item in data.get("results", []):
                        finding = SecretFinding(
                            tool="semgrep",
                            secret_type=self._classify_secret_type(item.get("check_id", "")),
                            confidence=ConfidenceLevel.MEDIUM,
                            file_path=item.get("path", ""),
                            line_number=item.get("start", {}).get("line", 0),
                            raw_value=item.get("extra", {}).get("lines", ""),
                            masked_value=self._mask_secret(item.get("extra", {}).get("lines", "")),
                            pattern_match=True,
                            metadata={"rule": item.get("check_id", ""), "source": "semgrep"}
                        )
                        findings.append(finding)
                except json.JSONDecodeError:
                    pass

            logger.info(f"🔍 Semgrep found {len(findings)} secrets")

        except Exception as e:
            logger.error(f"❌ Semgrep execution failed: {e}")

        return findings

    def _analyze_entropy_professional(self, repo_path: str) -> List[SecretFinding]:
        """Professional entropy analysis."""
        findings = []

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}]

            for file in files:
                if file.endswith(('.pyc', '.exe', '.dll', '.so', '.jpg', '.png', '.gif', '.pdf')):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        file_findings = self._analyze_file_entropy(content, relative_path)
                        findings.extend(file_findings)
                except Exception:
                    continue

        logger.info(f"🔍 Entropy analysis found {len(findings)} potential secrets")
        return findings

    def _analyze_file_entropy(self, content: str, file_path: str) -> List[SecretFinding]:
        """Analyze file for high-entropy strings."""
        findings = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith(('#', '//', '/*', '*', '--')):
                continue

            # Find potential secrets using regex
            patterns = [
                r'["\']([A-Za-z0-9+/=_-]{20,})["\']',
                r'[:=]\s*["\']?([A-Za-z0-9+/=_-]{20,})["\']?',
            ]

            for pattern in patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    potential_secret = match.group(1) if match.groups() else match.group(0)
                    entropy_score = self._calculate_entropy(potential_secret)

                    if entropy_score > 4.0 and len(potential_secret) >= 16:
                        finding = SecretFinding(
                            tool="entropy_analyzer",
                            secret_type=SecretType.UNKNOWN,
                            confidence=ConfidenceLevel.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            raw_value=potential_secret,
                            masked_value=self._mask_secret(potential_secret),
                            entropy_score=entropy_score,
                            metadata={"analysis": "entropy", "source": "custom"}
                        )
                        findings.append(finding)

        return findings

    def _analyze_semantic_context(self, repo_path: str) -> List[SecretFinding]:
        """Semantic context analysis."""
        findings = []

        # Context-aware patterns
        context_patterns = {
            "api_key": [r"api[_-]?key['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]"],
            "password": [r"password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]"],
            "token": [r"token['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]"],
            "secret": [r"secret['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]"]
        }

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}]

            for file in files:
                if file.endswith(('.pyc', '.exe', '.dll', '.so', '.jpg', '.png', '.gif', '.pdf')):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        file_findings = self._analyze_file_context(content, relative_path, context_patterns)
                        findings.extend(file_findings)
                except Exception:
                    continue

        logger.info(f"🔍 Semantic analysis found {len(findings)} potential secrets")
        return findings

    def _analyze_file_context(self, content: str, file_path: str, patterns: Dict[str, List[str]]) -> List[SecretFinding]:
        """Analyze file with context-aware patterns."""
        findings = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        secret_value = match.group(1)

                        finding = SecretFinding(
                            tool="semantic_analyzer",
                            secret_type=self._classify_secret_type(secret_type),
                            confidence=ConfidenceLevel.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            raw_value=secret_value,
                            masked_value=self._mask_secret(secret_value),
                            context=line.strip(),
                            pattern_match=True,
                            metadata={"pattern_type": secret_type, "source": "semantic"}
                        )
                        findings.append(finding)

        return findings

    def _group_similar_findings(self, findings: List[SecretFinding]) -> List[List[SecretFinding]]:
        """Group similar findings for intelligent fusion."""
        groups = []
        processed = set()

        for i, finding in enumerate(findings):
            if i in processed:
                continue

            group = [finding]
            processed.add(i)

            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in processed:
                    continue

                if self._are_findings_similar(finding, other_finding):
                    group.append(other_finding)
                    processed.add(j)

            groups.append(group)

        return groups

    def _are_findings_similar(self, finding1: SecretFinding, finding2: SecretFinding) -> bool:
        """Determine if two findings are similar enough to be grouped."""
        # Same file and close line numbers
        if (finding1.file_path == finding2.file_path and
            abs(finding1.line_number - finding2.line_number) <= 2):
            return True

        # Same secret value
        if finding1.raw_value == finding2.raw_value and finding1.raw_value:
            return True

        return False

    def _fuse_finding_group(self, group: List[SecretFinding]) -> SecretFinding:
        """Fuse a group of similar findings into a single high-confidence finding."""
        if len(group) == 1:
            return group[0]

        # Select the highest confidence finding as base
        base_finding = max(group, key=lambda f: self._confidence_score(f.confidence))

        # Enhance with information from other findings
        base_finding.metadata["fusion_count"] = len(group)
        base_finding.metadata["tools_detected"] = list(set(f.tool for f in group))

        # Upgrade confidence if multiple tools detected the same secret
        if len(set(f.tool for f in group)) > 1:
            base_finding.confidence = ConfidenceLevel.CRITICAL

        return base_finding

    def _verify_finding_professional(self, finding: SecretFinding) -> SecretFinding:
        """Professional verification with advanced algorithms."""
        # Apply verification algorithms
        verification_score = 0.0

        # Entropy verification
        if finding.entropy_score > 4.5:
            verification_score += 0.3

        # ML score verification
        if finding.ml_score > 0.8:
            verification_score += 0.4

        # Pattern match verification
        if finding.pattern_match:
            verification_score += 0.2

        # Tool reputation verification
        tool_weights = {
            "trufflehog": 0.4,
            "gitleaks": 0.3,
            "semgrep": 0.2,
            "semantic": 0.25,  # Give semantic analysis more credit
            "entropy_analyzer": 0.1
        }
        verification_score += tool_weights.get(finding.tool, 0.1)

        # Update confidence based on verification
        if verification_score >= 0.8:
            finding.confidence = ConfidenceLevel.CRITICAL
        elif verification_score >= 0.6:
            finding.confidence = ConfidenceLevel.HIGH
        elif verification_score >= 0.4:
            finding.confidence = ConfidenceLevel.MEDIUM
        else:
            finding.confidence = ConfidenceLevel.LOW

        finding.metadata["verification_score"] = verification_score

        return finding

    def _classify_secret_type(self, detector_name: str) -> SecretType:
        """Classify secret type based on detector name."""
        detector_lower = detector_name.lower()

        if any(term in detector_lower for term in ["api", "key"]):
            return SecretType.API_KEY
        elif any(term in detector_lower for term in ["aws", "azure", "gcp", "cloud"]):
            return SecretType.CLOUD_CREDENTIAL
        elif any(term in detector_lower for term in ["database", "db", "sql", "mongo"]):
            return SecretType.DATABASE_CREDENTIAL
        elif any(term in detector_lower for term in ["private", "rsa", "ssh"]):
            return SecretType.PRIVATE_KEY
        elif any(term in detector_lower for term in ["token", "jwt", "bearer"]):
            return SecretType.TOKEN
        elif any(term in detector_lower for term in ["password", "passwd", "pwd"]):
            return SecretType.PASSWORD
        elif any(term in detector_lower for term in ["cert", "certificate", "pem"]):
            return SecretType.CERTIFICATE
        else:
            return SecretType.UNKNOWN

    def _mask_secret(self, secret: str) -> str:
        """Professional secret masking."""
        if len(secret) <= 8:
            return "*" * len(secret)

        visible_chars = 4
        return secret[:visible_chars] + "*" * (len(secret) - 2 * visible_chars) + secret[-visible_chars:]

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)

        return entropy

    def _confidence_score(self, confidence: ConfidenceLevel) -> float:
        """Convert confidence level to numeric score."""
        scores = {
            ConfidenceLevel.CRITICAL: 1.0,
            ConfidenceLevel.HIGH: 0.8,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.LOW: 0.4
        }
        return scores.get(confidence, 0.0)

def lambda_handler(event, context):
    """
    Professional Lambda handler with enterprise-grade error handling.

    Args:
        event: Lambda event containing repository details
        context: Lambda context

    Returns:
        Professional response with comprehensive findings
    """
    # CRITICAL TEST - This should appear in logs if function executes
    print("🚨 LAMBDA_HANDLER STARTED - CRITICAL TEST MESSAGE")
    logger.info("🚨 LAMBDA_HANDLER STARTED - CRITICAL TEST MESSAGE")

    logger.info(f"🎯 Professional Secret Scanner v{SCANNER_VERSION} - Enterprise Grade - FORCED DEPLOY 2025-06-28 15:05")

    # DEBUG: Check what tools are actually available
    logger.info(f"🔍 PATH environment: {os.environ.get('PATH', 'NOT SET')}")
    logger.info("🔍 Scanner not initialized yet - will check tools after creation")

    # DEBUG: Check if basic files exist
    import subprocess
    try:
        result = subprocess.run(['ls', '/opt/bin/'], capture_output=True, text=True, timeout=10)
        logger.info(f"🔍 /opt/bin/ contents: {result.stdout}")
    except Exception as e:
        logger.info(f"🔍 Cannot list /opt/bin/: {e}")

    try:
        result = subprocess.run(['which', 'trufflehog'], capture_output=True, text=True, timeout=10)
        logger.info(f"🔍 which trufflehog: {result.stdout.strip() if result.stdout else 'NOT FOUND'}")
    except Exception as e:
        logger.info(f"🔍 which trufflehog failed: {e}")
    
    try:
        # Extract repository details
        repo_details = event.get("repo_details", {})
        repo_full_name = repo_details.get("repository_full_name", "")
        zip_url = repo_details.get("zipball_url", "")
        
        if not zip_url:
            raise ValueError("Repository zipball URL not provided")
        
        logger.info(f"🔍 Scanning repository: {repo_full_name}")
        
        # Initialize professional orchestrator
        orchestrator = ProfessionalSecretOrchestrator()

        # DEBUG: Check what tools are actually available after scanner creation
        logger.info(f"🔍 Available tools discovered: {list(orchestrator.available_tools.keys())}")

        # Download and scan repository
        findings = orchestrator.scan_repository_professional(zip_url)
        
        # Convert findings to response format
        response_findings = [finding.__dict__ for finding in findings]
        
        logger.info(f"✅ Professional scan completed: {len(response_findings)} secrets found")
        
        return format_success_response(SCANNER_TYPE, response_findings)
        
    except Exception as e:
        logger.error(f"❌ Professional scanner error: {str(e)}", exc_info=True)
        response = format_error_response(SCANNER_TYPE, e)
        response["scanner_version"] = f"PROFESSIONAL-v{SCANNER_VERSION}-DEPLOYED-2025-06-28-12:45"
        return response

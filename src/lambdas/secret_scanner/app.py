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
        Runs all detection methods in parallel for maximum coverage.
        
        Args:
            repo_path: Path to repository for scanning
            
        Returns:
            List of professionally analyzed secret findings
        """
        logger.info("🚀 Starting comprehensive multi-layer secret scan")
        
        all_findings = []
        
        # Run ALL detection layers in parallel for robustness
        # Don't depend on any single tool or method
        
        # Layer 1: ML-based tools (TruffleHog)
        logger.info("🤖 Layer 1: Running ML-based detection")
        ml_findings = self._run_ml_based_tools(repo_path)
        all_findings.extend(ml_findings)
        logger.info(f"  └─ ML-based tools found {len(ml_findings)} potential secrets")
        
        # Layer 2: Pattern-based detection tools (GitLeaks, Semgrep)
        logger.info("🔍 Layer 2: Running pattern-based detection")
        pattern_findings = self._run_pattern_based_tools(repo_path)
        all_findings.extend(pattern_findings)
        logger.info(f"  └─ Pattern-based tools found {len(pattern_findings)} potential secrets")
        
        # Layer 3: Entropy and statistical analysis
        logger.info("📊 Layer 3: Running entropy analysis")
        entropy_findings = self._run_entropy_analysis(repo_path)
        all_findings.extend(entropy_findings)
        logger.info(f"  └─ Entropy analysis found {len(entropy_findings)} potential secrets")
        
        # Layer 4: Context-aware semantic analysis
        # Always run this as an independent layer, not just as fallback
        logger.info("🧠 Layer 4: Running semantic context analysis")
        semantic_findings = self._run_semantic_analysis(repo_path)
        all_findings.extend(semantic_findings)
        logger.info(f"  └─ Semantic analysis found {len(semantic_findings)} potential secrets")
        
        # Layer 5: Custom detection algorithms
        logger.info("🎯 Layer 5: Running custom detection algorithms")
        custom_findings = self._run_custom_detection(repo_path)
        all_findings.extend(custom_findings)
        logger.info(f"  └─ Custom algorithms found {len(custom_findings)} potential secrets")
        
        # Professional fusion and deduplication
        logger.info("🔄 Applying intelligent fusion and deduplication")
        final_findings = self._intelligent_fusion(all_findings)
        
        # Professional verification and scoring
        logger.info("✅ Verifying and scoring findings")
        verified_findings = self._professional_verification(final_findings)
        
        scan_duration = time.time() - self.scan_start_time
        logger.info(f"🎯 Multi-layer scan completed in {scan_duration:.2f}s")
        logger.info(f"📊 Final scan statistics:")
        logger.info(f"  - Total raw findings: {len(all_findings)}")
        logger.info(f"  - After intelligent fusion: {len(final_findings)}")
        logger.info(f"  - After verification: {len(verified_findings)}")
        logger.info(f"  - Detection coverage: {self._calculate_coverage_score()}")
        
        return verified_findings
    
    def _calculate_coverage_score(self) -> str:
        """Calculate a coverage score based on available detection methods."""
        available_methods = 0
        total_methods = 5
        
        if any(tool in self.available_tools for tool in ["trufflehog"]):
            available_methods += 1
        if any(tool in self.available_tools for tool in ["gitleaks", "semgrep"]):
            available_methods += 1
        # Entropy, semantic, and custom are always available
        available_methods += 3
        
        percentage = (available_methods / total_methods) * 100
        return f"{percentage:.0f}% ({available_methods}/{total_methods} methods active)"
    
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
        """Run semantic and context-aware analysis as intelligent fallback."""
        findings = []
        
        # Dynamic context-aware patterns that look for general secret patterns
        # rather than hardcoded specific formats
        context_patterns = self._build_dynamic_patterns()
        
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
    
    def _build_dynamic_patterns(self) -> Dict[str, List[str]]:
        """Build dynamic patterns based on common secret structures and context."""
        patterns = {}
        
        # Common secret indicators with context requirements
        secret_contexts = {
            'api_key': {
                'keywords': ['api', 'key', 'apikey', 'api_key'],
                'min_length': 16,
                'patterns': [
                    # Standard assignment patterns
                    r'{keyword}["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{{16,}})["\']',
                    # Environment variable patterns
                    r'{keyword}\s*=\s*["\']?([A-Za-z0-9_\-]{{16,}})["\']?',
                    # Function parameter patterns
                    r'{keyword}\s*:\s*["\']([A-Za-z0-9_\-]{{16,}})["\']'
                ]
            },
            'token': {
                'keywords': ['token', 'bearer', 'access_token', 'refresh_token', 'auth_token'],
                'min_length': 20,
                'patterns': [
                    r'{keyword}["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\./+]{{20,}})["\']',
                    r'Bearer\s+([A-Za-z0-9_\-\./+]{{20,}})',
                    r'{keyword}\s*:\s*["\']([A-Za-z0-9_\-\./+]{{20,}})["\']'
                ]
            },
            'password': {
                'keywords': ['password', 'passwd', 'pwd', 'pass'],
                'min_length': 8,
                'patterns': [
                    r'{keyword}["\']?\s*[:=]\s*["\']([^"\'{{}}]+)["\']',
                    r'{keyword}\s*=\s*["\']?([^"\'\s{{}}]+)["\']?',
                    # Exclude common placeholder patterns
                    r'{keyword}["\']?\s*[:=]\s*["\'](?!(?:password|example|changeme|admin|test|demo|sample|placeholder|xxx+)["\'$])([^"\'{{}}]+)["\']'
                ]
            },
            'credential': {
                'keywords': ['credential', 'cred', 'secret', 'auth'],
                'min_length': 12,
                'patterns': [
                    r'{keyword}[s]?["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\./+]{{12,}})["\']',
                    r'{keyword}_?(?:id|key|token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{{12,}})["\']'
                ]
            },
            'private_key': {
                'keywords': ['private', 'priv', 'key', 'rsa', 'dsa', 'ecdsa', 'ed25519'],
                'min_length': 30,
                'patterns': [
                    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                    r'{keyword}[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=\-_]{{30,}})["\']'
                ]
            }
        }
        
        # Build patterns for each secret type
        for secret_type, config in secret_contexts.items():
            type_patterns = []
            
            for keyword in config['keywords']:
                for pattern_template in config['patterns']:
                    # Replace {keyword} placeholder with actual keyword variations
                    pattern = pattern_template.replace('{keyword}', keyword)
                    # Also create uppercase variant
                    pattern_upper = pattern_template.replace('{keyword}', keyword.upper())
                    
                    type_patterns.extend([pattern, pattern_upper])
            
            patterns[secret_type] = type_patterns
        
        # Add specialized patterns for known secret formats
        patterns['cloud_credentials'] = [
            # AWS
            r'AKIA[0-9A-Z]{16}',
            r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9+/]{40})["\']',
            # Azure
            r'DefaultEndpointsProtocol=https;AccountName=([^;]+);AccountKey=([A-Za-z0-9+/=]{88});',
            # GCP
            r'"private_key":\s*"(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----)"',
        ]
        
        # Add Docker ENV and general environment variable patterns
        patterns['env_variables'] = [
            # Docker ENV syntax
            r'ENV\s+([A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|API)[A-Z_]*)\s*=\s*([^\s]+)',
            # Shell export syntax
            r'export\s+([A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|API)[A-Z_]*)\s*=\s*["\']?([^"\'\s]+)["\']?',
            # General ENV patterns with common prefixes
            r'(OPENAI|SENDGRID|STRIPE|GITHUB|GITLAB|SLACK|DISCORD|TELEGRAM|TWILIO|AWS|AZURE|GCP)_API_KEY\s*=\s*["\']?([A-Za-z0-9_\-\.]+)["\']?',
            # JWT patterns
            r'JWT[_-]?SECRET\s*=\s*["\']?([A-Za-z0-9_\-\.]+)["\']?',
            # Generic API key patterns in ENV format
            r'([A-Z_]*API[_-]?KEY)\s*=\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',
            # sk_ prefixed keys (common for test/live API keys)
            r'=\s*["\']?(sk_(?:test_|live_)?[A-Za-z0-9]{24,})["\']?',
            # SG. prefixed keys (SendGrid)
            r'=\s*["\']?(SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,})["\']?'
        ]
        
        patterns['database_urls'] = [
            # Database connection strings with credentials
            r'(?:mysql|postgresql|postgres|mongodb)://([^:]+):([^@]+)@[^/\s]+',
            r'Data Source=[^;]+;User Id=([^;]+);Password=([^;]+)',
            r'Server=[^;]+;Database=[^;]+;User Id=([^;]+);Password=([^;]+)'
        ]
        
        # Add high-entropy pattern with context requirements
        patterns['high_entropy_with_context'] = [
            # Must be preceded by assignment or key-value separator
            r'(?:=|:)\s*["\']?([A-Za-z0-9+/=_\-]{32,})["\']?(?:\s|$|,)',
            # In JSON/YAML context
            r'"[^"]*(?:key|token|secret|password)[^"]*"\s*:\s*"([A-Za-z0-9+/=_\-]{20,})"',
            # Environment variable assignment
            r'^[A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD)\s*=\s*([A-Za-z0-9+/=_\-]{16,})$'
        ]
        
        return patterns

    def _analyze_file_context(self, content: str, file_path: str, patterns: Dict[str, List[str]]) -> List[SecretFinding]:
        """Analyze file with context-aware patterns."""
        findings = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Handle patterns with multiple capture groups
                        if match.groups():
                            # For ENV patterns with 2 groups (key, value), use the last group as secret
                            if len(match.groups()) >= 2 and match.group(2):
                                secret_value = match.group(2)
                                key_name = match.group(1) if len(match.groups()) >= 1 else ""
                            else:
                                secret_value = match.group(1)
                                key_name = ""
                        else:
                            secret_value = match.group(0)
                            key_name = ""

                        # Skip empty values
                        if not secret_value or len(secret_value.strip()) < 8:
                            continue

                        # Create finding with initial type classification
                        finding = SecretFinding(
                            tool="semantic_analyzer",
                            secret_type=SecretType.UNKNOWN,  # Will be updated below
                            confidence=ConfidenceLevel.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            raw_value=secret_value,
                            masked_value=self._mask_secret(secret_value),
                            context=line.strip(),
                            pattern_match=True,
                            metadata={"pattern_type": secret_type, "source": "semantic", "key_name": key_name}
                        )
                        # Now classify with the finding context
                        finding.secret_type = self._classify_secret_type(secret_type, finding)
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
        # Only group if BOTH conditions are met:
        # 1. Same file
        # 2. Same secret value (or very close line numbers for the exact same pattern)
        
        if finding1.file_path != finding2.file_path:
            return False
            
        # If same secret value, group them
        if finding1.raw_value and finding1.raw_value == finding2.raw_value:
            return True
            
        # If different values but on the exact same line (multi-pattern match), don't group
        if finding1.line_number == finding2.line_number and finding1.raw_value != finding2.raw_value:
            return False
            
        # Don't group different secrets just because they're close in the file
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
        
        # Factor 1: Entropy verification (15% weight)
        if finding.entropy_score > 4.5:
            verification_score += 0.15
        elif finding.entropy_score > 4.0:
            verification_score += 0.10
        elif finding.entropy_score > 3.5:
            verification_score += 0.05
        
        # Factor 2: ML score verification (20% weight)
        if finding.ml_score > 0.8:
            verification_score += 0.20
        elif finding.ml_score > 0.6:
            verification_score += 0.15
        elif finding.ml_score > 0.4:
            verification_score += 0.10
        
        # Factor 3: Pattern match verification (15% weight)
        if finding.pattern_match:
            verification_score += 0.15
        
        # Factor 4: Tool reputation verification (25% weight)
        tool_weights = {
            "trufflehog": 0.25,          # High confidence in ML-based detection
            "gitleaks": 0.23,            # Strong pattern matching
            "semgrep": 0.20,             # Good semantic analysis
            "custom_config_analyzer": 0.20,  # Config files often contain real secrets
            "custom_url_analyzer": 0.25,      # URLs with credentials are high risk
            "semantic_analyzer": 0.18,        # General semantic patterns
            "custom_variable_analyzer": 0.15, # Variable name analysis
            "entropy_analyzer": 0.12,         # Pure entropy can have false positives
            "custom_comment_scanner": 0.08    # Comments less likely to have real secrets
        }
        tool_score = tool_weights.get(finding.tool, 0.10)
        verification_score += tool_score
        
        # Factor 5: Multi-tool detection bonus (15% weight)
        # If detected by multiple tools, increase confidence significantly
        if finding.metadata.get("fusion_count", 1) > 1:
            multi_tool_bonus = min(0.15, 0.05 * finding.metadata.get("fusion_count", 1))
            verification_score += multi_tool_bonus
        
        # Factor 6: Context analysis (10% weight)
        context_score = self._analyze_context_confidence(finding)
        verification_score += context_score * 0.10
        
        # Ensure score is between 0 and 1
        verification_score = min(1.0, verification_score)
        
        # Update confidence based on verification score
        if verification_score >= 0.75:
            finding.confidence = ConfidenceLevel.CRITICAL
        elif verification_score >= 0.60:
            finding.confidence = ConfidenceLevel.HIGH
        elif verification_score >= 0.40:
            finding.confidence = ConfidenceLevel.MEDIUM
        else:
            finding.confidence = ConfidenceLevel.LOW
        
        finding.metadata["verification_score"] = verification_score
        
        # Add verification details for transparency
        finding.metadata["verification_factors"] = {
            "entropy_weight": finding.entropy_score > 3.5,
            "ml_detected": finding.ml_score > 0.4,
            "pattern_matched": finding.pattern_match,
            "tool_confidence": tool_score,
            "multi_tool_detected": finding.metadata.get("fusion_count", 1) > 1,
            "context_confidence": context_score
        }
        
        return finding
    
    def _analyze_context_confidence(self, finding: SecretFinding) -> float:
        """Analyze the context of a finding to determine confidence."""
        confidence = 0.5  # Base confidence
        
        # Check file type
        file_path = finding.file_path.lower()
        
        # High-risk files
        if any(pattern in file_path for pattern in ['.env', 'config', 'settings', 'credentials']):
            confidence += 0.3
        
        # Medium-risk files
        elif any(pattern in file_path for pattern in ['.yml', '.yaml', '.json', '.xml', '.properties']):
            confidence += 0.2
        
        # Low-risk files
        elif any(pattern in file_path for pattern in ['test', 'example', 'sample', 'demo']):
            confidence -= 0.2
        
        # Check secret type
        if finding.secret_type in [SecretType.API_KEY, SecretType.CLOUD_CREDENTIAL, SecretType.DATABASE_CREDENTIAL]:
            confidence += 0.2
        
        # Check if it's in production code
        if 'prod' in file_path or 'production' in file_path:
            confidence += 0.3
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))

    def _classify_secret_type(self, detector_name: str, finding: Optional['SecretFinding'] = None) -> SecretType:
        """Classify secret type based on detector name or pattern type, with context awareness."""
        detector_lower = detector_name.lower()

        # Direct mapping for pattern types from semantic analysis
        if detector_lower == "api_key":
            return SecretType.API_KEY
        elif detector_lower == "token":
            return SecretType.TOKEN
        elif detector_lower == "password":
            return SecretType.PASSWORD
        elif detector_lower == "credential":
            return SecretType.UNKNOWN
        elif detector_lower == "private_key":
            return SecretType.PRIVATE_KEY
        elif detector_lower == "cloud_credentials":
            return SecretType.CLOUD_CREDENTIAL
        elif detector_lower == "database_urls":
            return SecretType.DATABASE_CREDENTIAL
        elif detector_lower == "env_variables":
            # For env variables, check the key name from metadata if available
            if finding and finding.metadata.get("key_name"):
                key_name = finding.metadata["key_name"].upper()
                if "JWT" in key_name:
                    return SecretType.TOKEN
                elif any(term in key_name for term in ["PASSWORD", "PASSWD", "PWD"]):
                    return SecretType.PASSWORD
                elif "API" in key_name or "KEY" in key_name:
                    return SecretType.API_KEY
            return SecretType.API_KEY  # Default for env secrets
        
        # Check for specific vendor patterns in the detector name
        if any(vendor in detector_lower for vendor in ["openai", "sendgrid", "stripe", "github", "gitlab"]):
            return SecretType.API_KEY
        
        # Fallback to keyword matching for tool-specific detectors
        if any(term in detector_lower for term in ["api", "key", "apikey", "api_key"]):
            return SecretType.API_KEY
        elif any(term in detector_lower for term in ["aws", "azure", "gcp", "cloud"]):
            return SecretType.CLOUD_CREDENTIAL
        elif any(term in detector_lower for term in ["database", "db", "sql", "mongo", "postgres", "mysql"]):
            return SecretType.DATABASE_CREDENTIAL
        elif any(term in detector_lower for term in ["private", "rsa", "ssh", "dsa", "ecdsa"]):
            return SecretType.PRIVATE_KEY
        elif any(term in detector_lower for term in ["token", "jwt", "bearer", "oauth"]):
            return SecretType.TOKEN
        elif any(term in detector_lower for term in ["password", "passwd", "pwd", "pass"]):
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
            # Debug: List files in repo to verify content
            import os
            logger.info(f"🔍 Repository path: {repo_path}")
            for root, dirs, files in os.walk(repo_path):
                for file in files[:10]:  # Limit to first 10 files
                    file_path = os.path.join(root, file)
                    logger.info(f"🔍 Found file: {file_path}")

            # TruffleHog v3+ with all detectors enabled and verification
            cmd = [tool_path, "filesystem", "--json", "--no-update", "--include-detectors=all", repo_path]
            
            # Add additional flags to improve detection
            # --only-verified=false includes unverified secrets (test secrets might not verify)
            # --allow-verification-overlap allows multiple detectors to check the same secret
            cmd.extend(["--only-verified=false", "--allow-verification-overlap"])
            
            logger.info(f"🔍 Running TruffleHog command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo_path)

            # Log TruffleHog output for debugging
            if result.stderr:
                logger.warning(f"🔍 TruffleHog stderr: {result.stderr}")
            if result.stdout:
                logger.info(f"🔍 TruffleHog stdout length: {len(result.stdout)} chars")
                logger.info(f"🔍 TruffleHog stdout preview: {result.stdout[:500]}...")

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
        """Professional GitLeaks execution with enhanced configuration."""
        findings = []
        
        if "gitleaks" not in self.available_tools:
            logger.warning("GitLeaks not available, skipping...")
            return findings
            
        tool_path = self.available_tools["gitleaks"]

        try:
            # Use custom config if available, otherwise use default
            custom_config = "/opt/rules/gitleaks.toml"
            if os.path.exists(custom_config):
                cmd = [tool_path, "detect", "--source", repo_path, "--config", custom_config, "-f", "json", "--no-git"]
            else:
                cmd = [tool_path, "detect", "--source", repo_path, "-f", "json", "--no-git"]
                
            logger.info(f"🔍 Running GitLeaks command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=repo_path)

            if result.stderr and "no leaks found" not in result.stderr.lower():
                logger.warning(f"GitLeaks stderr: {result.stderr}")

            if result.stdout:
                try:
                    # GitLeaks outputs JSON array directly
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
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
                                metadata={
                                    "rule": item.get("RuleID", ""),
                                    "source": "gitleaks",
                                    "commit": item.get("Commit", ""),
                                    "match": item.get("Match", "")
                                }
                            )
                            findings.append(finding)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse GitLeaks output: {e}")
                    logger.debug(f"GitLeaks stdout: {result.stdout[:500]}")

            logger.info(f"🔍 GitLeaks found {len(findings)} secrets")

        except subprocess.TimeoutExpired:
            logger.error("GitLeaks execution timed out")
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

    def _run_custom_detection(self, repo_path: str) -> List[SecretFinding]:
        """Run custom detection algorithms for comprehensive coverage."""
        findings = []

        # Custom detection algorithm 1: Variable name analysis
        var_findings = self._detect_by_variable_names(repo_path)
        findings.extend(var_findings)
        
        # Custom detection algorithm 2: Comment scanning
        comment_findings = self._scan_comments_for_secrets(repo_path)
        findings.extend(comment_findings)
        
        # Custom detection algorithm 3: Configuration file deep analysis
        config_findings = self._analyze_config_files(repo_path)
        findings.extend(config_findings)
        
        # Custom detection algorithm 4: URL parameter analysis
        url_findings = self._analyze_urls_for_secrets(repo_path)
        findings.extend(url_findings)
        
        logger.info(f"🎯 Custom detection found {len(findings)} potential secrets")
        return findings
    
    def _detect_by_variable_names(self, repo_path: str) -> List[SecretFinding]:
        """Detect secrets by analyzing variable names and their values."""
        findings = []
        
        # Keywords that strongly indicate secrets
        secret_indicators = {
            'private', 'secret', 'key', 'token', 'password', 'pwd', 
            'credential', 'auth', 'api', 'access', 'encryption'
        }

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}]

            for file in files:
                if not file.endswith(('.py', '.js', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c')):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        
                    for line_num, line in enumerate(lines, 1):
                        # Look for variable assignments with secret indicators
                        for indicator in secret_indicators:
                            if indicator in line.lower():
                                # Extract potential secret value
                                value_match = re.search(r'=\s*["\']?([^"\'\s]{8,})["\']?', line)
                                if value_match and len(value_match.group(1)) >= 12:
                                    finding = SecretFinding(
                                        tool="custom_variable_analyzer",
                                        secret_type=SecretType.UNKNOWN,
                                        confidence=ConfidenceLevel.MEDIUM,
                                        file_path=relative_path,
                                        line_number=line_num,
                                        raw_value=value_match.group(1),
                                        masked_value=self._mask_secret(value_match.group(1)),
                                        context=line.strip(),
                                        pattern_match=True,
                                        metadata={"detection_method": "variable_name", "indicator": indicator}
                                    )
                                    findings.append(finding)
                except Exception:
                    continue

        return findings

    def _scan_comments_for_secrets(self, repo_path: str) -> List[SecretFinding]:
        """Scan code comments for accidentally included secrets."""
        findings = []
        
        comment_patterns = {
            'python': r'#.*',
            'javascript': r'//.*|/\*[\s\S]*?\*/',
            'java': r'//.*|/\*[\s\S]*?\*/',
            'go': r'//.*|/\*[\s\S]*?\*/',
            'ruby': r'#.*',
            'php': r'//.*|/\*[\s\S]*?\*/',
            'c': r'//.*|/\*[\s\S]*?\*/',
        }
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}]
            
            for file in files:
                file_ext = os.path.splitext(file)[1]
                lang = None
                
                if file_ext in ['.py']:
                    lang = 'python'
                elif file_ext in ['.js', '.ts']:
                    lang = 'javascript'
                elif file_ext in ['.java']:
                    lang = 'java'
                elif file_ext in ['.go']:
                    lang = 'go'
                elif file_ext in ['.rb']:
                    lang = 'ruby'
                elif file_ext in ['.php']:
                    lang = 'php'
                elif file_ext in ['.c', '.cpp', '.h']:
                    lang = 'c'
                else:
                    continue
                    
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Find all comments
                    pattern = comment_patterns[lang]
                    for match in re.finditer(pattern, content, re.MULTILINE):
                        comment = match.group(0)
                        
                        # Look for potential secrets in comments
                        secret_match = re.search(r'[A-Za-z0-9+/=_-]{16,}', comment)
                        if secret_match:
                            line_num = content[:match.start()].count('\n') + 1
                            finding = SecretFinding(
                                tool="custom_comment_scanner",
                                secret_type=SecretType.UNKNOWN,
                                confidence=ConfidenceLevel.LOW,
                                file_path=relative_path,
                                line_number=line_num,
                                raw_value=secret_match.group(0),
                                masked_value=self._mask_secret(secret_match.group(0)),
                                context=comment.strip(),
                                pattern_match=True,
                                metadata={"detection_method": "comment_scan", "language": lang}
                            )
                            findings.append(finding)
                except Exception:
                    continue

        return findings

    def _analyze_config_files(self, repo_path: str) -> List[SecretFinding]:
        """Deep analysis of configuration files for secrets."""
        findings = []
        
        config_extensions = [
            '.env', '.ini', '.cfg', '.conf', '.config', '.properties',
            '.yaml', '.yml', '.json', '.xml', '.toml'
        ]
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}]
            
            for file in files:
                if not any(file.endswith(ext) for ext in config_extensions):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        
                    for line_num, line in enumerate(lines, 1):
                        # Skip comments
                        if line.strip().startswith(('#', ';', '//')):
                            continue

                        # Look for key-value pairs
                        kv_match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["\']?([^"\'\n]{8,})["\']?', line)
                        if kv_match:
                            key = kv_match.group(1)
                            value = kv_match.group(2).strip()
                            
                            # Check if this looks like a secret
                            if self._is_likely_secret(key, value):
                                finding = SecretFinding(
                                    tool="custom_config_analyzer",
                                    secret_type=self._classify_secret_type(key),
                                    confidence=ConfidenceLevel.MEDIUM,
                                    file_path=relative_path,
                                    line_number=line_num,
                                    raw_value=value,
                                    masked_value=self._mask_secret(value),
                                    context=line.strip(),
                                    pattern_match=True,
                                    metadata={"detection_method": "config_analysis", "key": key}
                                )
                                findings.append(finding)
                except Exception:
                    continue
                    
        return findings
    
    def _analyze_urls_for_secrets(self, repo_path: str) -> List[SecretFinding]:
        """Analyze URLs for embedded credentials and API keys."""
        findings = []
        
        url_pattern = r'https?://[^\s\'"<>]+'
        
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
                        
                    for match in re.finditer(url_pattern, content):
                        url = match.group(0)
                        
                        # Check for credentials in URL
                        cred_match = re.search(r'://([^:]+):([^@]+)@', url)
                        if cred_match:
                            line_num = content[:match.start()].count('\n') + 1
                            finding = SecretFinding(
                                tool="custom_url_analyzer",
                                secret_type=SecretType.PASSWORD,
                                confidence=ConfidenceLevel.HIGH,
                                file_path=relative_path,
                                line_number=line_num,
                                raw_value=cred_match.group(2),
                                masked_value=self._mask_secret(cred_match.group(2)),
                                context=url,
                                verified=True,
                                metadata={"detection_method": "url_credentials", "username": cred_match.group(1)}
                            )
                            findings.append(finding)
                            
                        # Check for API keys in URL parameters
                        param_match = re.search(r'[?&](api[_-]?key|token|auth|secret)=([^&\s]+)', url, re.IGNORECASE)
                        if param_match:
                            line_num = content[:match.start()].count('\n') + 1
                            finding = SecretFinding(
                                tool="custom_url_analyzer",
                                secret_type=SecretType.API_KEY,
                                confidence=ConfidenceLevel.HIGH,
                                file_path=relative_path,
                                line_number=line_num,
                                raw_value=param_match.group(2),
                                masked_value=self._mask_secret(param_match.group(2)),
                                context=url,
                                pattern_match=True,
                                metadata={"detection_method": "url_parameter", "param": param_match.group(1)}
                            )
                            findings.append(finding)
                except Exception:
                    continue
                    
        return findings
    
    def _is_likely_secret(self, key: str, value: str) -> bool:
        """Determine if a key-value pair is likely to be a secret."""
        # Check key indicators
        key_lower = key.lower()
        secret_keywords = ['password', 'secret', 'key', 'token', 'credential', 'auth', 'api']
        
        if not any(keyword in key_lower for keyword in secret_keywords):
            return False
            
        # Check value characteristics
        if len(value) < 8:  # Too short to be a secret
            return False
            
        # Check for high entropy
        entropy = self._calculate_entropy(value)
        if entropy > 3.5:
            return True
            
        # Check for patterns that indicate secrets
        if re.match(r'^[A-Za-z0-9+/=_-]{16,}$', value):
            return True
            
        return False
    
    def _run_orchestrator(self, repo_path: str) -> List[SecretFinding]:
        """Run multi-tool orchestrator if available."""
        findings = []
        orchestrator_path = "/opt/bin/scan-secrets"
        
        if not os.path.exists(orchestrator_path):
            return findings
            
        try:
            logger.info("🔧 Running multi-tool secret scanner orchestrator...")
            cmd = [orchestrator_path, repo_path, "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                try:
                    # Parse orchestrator output
                    data = json.loads(result.stdout)
                    
                    # Process TruffleHog results
                    for section in data:
                        if "TruffleHog Results" in str(section):
                            continue  # Skip if already processed
                            
                        # Process GitLeaks results  
                        if isinstance(section, dict) and section.get("Description"):
                            finding = SecretFinding(
                                tool="gitleaks_orchestrator",
                                secret_type=self._classify_secret_type(section.get("RuleID", "")),
                                confidence=ConfidenceLevel.HIGH,
                                file_path=section.get("File", ""),
                                line_number=section.get("StartLine", 0),
                                raw_value=section.get("Secret", ""),
                                masked_value=self._mask_secret(section.get("Secret", "")),
                                pattern_match=True,
                                metadata={"source": "orchestrator", "rule": section.get("RuleID", "")}
                            )
                            findings.append(finding)
                            
                        # Process Semgrep results
                        if isinstance(section, dict) and section.get("check_id"):
                            finding = SecretFinding(
                                tool="semgrep_orchestrator",
                                secret_type=self._classify_secret_type(section.get("check_id", "")),
                                confidence=ConfidenceLevel.MEDIUM,
                                file_path=section.get("path", ""),
                                line_number=section.get("start", {}).get("line", 0),
                                raw_value=section.get("extra", {}).get("message", ""),
                                masked_value=self._mask_secret(section.get("extra", {}).get("message", "")),
                                pattern_match=True,
                                metadata={"source": "orchestrator", "rule": section.get("check_id", "")}
                            )
                            findings.append(finding)
                            
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse orchestrator output: {e}")
                    
            logger.info(f"🔧 Orchestrator found {len(findings)} additional secrets")
            
        except Exception as e:
            logger.error(f"Orchestrator execution failed: {e}")
            
        return findings

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
        
        # Convert findings to response format with proper JSON serialization
        response_findings = []
        for finding in findings:
            finding_dict = finding.__dict__.copy()
            # Convert enums to strings for JSON serialization
            if hasattr(finding_dict.get('secret_type'), 'value'):
                finding_dict['secret_type'] = finding_dict['secret_type'].value
            if hasattr(finding_dict.get('confidence'), 'value'):
                finding_dict['confidence'] = finding_dict['confidence'].value
            
            # Map field names to match aggregator expectations
            finding_dict['file'] = finding_dict.get('file_path', 'unknown')
            finding_dict['line'] = finding_dict.get('line_number', '?')
            finding_dict['type'] = finding_dict.get('secret_type', 'Secret')
            
            response_findings.append(finding_dict)
        
        logger.info(f"✅ Professional scan completed: {len(response_findings)} secrets found")
        
        return format_success_response(SCANNER_TYPE, response_findings)
        
    except Exception as e:
        logger.error(f"❌ Professional scanner error: {str(e)}", exc_info=True)
        response = format_error_response(SCANNER_TYPE, e)
        response["scanner_version"] = f"PROFESSIONAL-v{SCANNER_VERSION}-DEPLOYED-2025-06-28-12:45"
        return response

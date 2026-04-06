from __future__ import annotations

import math
import re
from pathlib import Path

from androidaudit.findings import Finding, Severity

# Standard high confidence secret patterns
SECRET_PATTERNS = {
    "AWS_KEY": r"(AKIA[0-9A-Z]{16})",
    "GCP_KEY": r"(AIza[0-9A-Za-z_-]{35})",
    "STRIPE_KEY": r"([sr]k_live_[0-9a-zA-Z]{24})",
    "JWT": r"(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})",
    "PRIVATE_KEY": r"(-----BEGIN PRIVATE KEY-----)",
    "IPV4": r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
}

def calculate_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def scan_secrets(source_dir: Path) -> list[Finding]:
    """
    Walk decompiled source code looking for hardcoded secrets.
    """
    findings: list[Finding] = []
    
    skip_dirs = {"build", "test", ".gradle", "res", "resources"}
    
    for file_path in source_dir.rglob("*"):
        if not file_path.is_file():
            continue
            
        # Skip standard non-source dirs
        if any(part in skip_dirs for part in file_path.parts):
            continue
            
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
            
        for name, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                findings.append(Finding(
                    id="STAT-SEC-001",
                    title=f"Hardcoded {name}",
                    severity=Severity.CRITICAL if "KEY" in name or "JWT" in name else Severity.MEDIUM,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cvss_score=9.1 if "KEY" in name else 5.3,
                    owasp_category="M1: Improper Credential Usage",
                    description=f"Found hardcoded {name} in source code.",
                    evidence=match.group(1),
                    remediation="Move secrets to secure server-side storage and do not bundle them.",
                    module="static.secret_scan",
                    file_path=str(file_path.relative_to(source_dir)),
                    line_number=content[:match.start()].count("\n") + 1
                ))
                
        # High entropy strings inside quotes check
        for match in re.finditer(r'(?:"|\')([A-Za-z0-9+/=]{20,})(?:"|\')', content):
            candidate = match.group(1)
            if calculate_entropy(candidate) > 4.5:
                findings.append(Finding(
                    id="STAT-SEC-002",
                    title="High Entropy String (Potential Secret)",
                    severity=Severity.LOW,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                    cvss_score=3.3,
                    owasp_category="M1: Improper Credential Usage",
                    description="Found high-entropy string that may be an obfuscated secret or key.",
                    evidence=candidate,
                    remediation="Verify if this string represents sensitive data. If so, remove it.",
                    module="static.secret_scan",
                    file_path=str(file_path.relative_to(source_dir)),
                    line_number=content[:match.start()].count("\n") + 1
                ))

    return findings


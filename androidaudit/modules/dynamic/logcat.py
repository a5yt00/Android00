from __future__ import annotations
import re
from typing import Any

from androidaudit.session import ADBSession
from androidaudit.findings import Finding, Severity
from androidaudit.modules.static.secret_scan import SECRET_PATTERNS

def analyze_logcat(session: ADBSession, package: str, timeout_seconds: int = 10) -> tuple[list[Finding], list[str]]:
    """
    Stream and parse logcat filtered to the target package.
    """
    findings: list[Finding] = []
    raw_lines: list[str] = []
    
    url_pattern = re.compile(r"https?://[^\s]+(?:\?[^\s]+)")
    
    iterator = session.logcat(package)
    import time
    start = time.time()
    
    for line in iterator:
        raw_lines.append(line)
        if time.time() - start > timeout_seconds:
            break
            
        # Match secrets
        for name, pattern in SECRET_PATTERNS.items():
            if match := re.search(pattern, line):
                findings.append(Finding(
                    id="DYN-LOG-001",
                    title=f"Secret in Logcat: {name}",
                    severity=Severity.HIGH,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=6.2,
                    owasp_category="M1: Improper Credential Usage",
                    description=f"App logged a {name} to system logcat.",
                    evidence=line.strip(),
                    remediation="Never log sensitive data or access tokens.",
                    module="dynamic.logcat"
                ))
        
        # Look for URLs with params
        if match := url_pattern.search(line):
            findings.append(Finding(
                id="DYN-LOG-002",
                title="URL with parameters in Logcat",
                severity=Severity.LOW,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_score=3.3,
                owasp_category="M6: Inadequate Privacy Controls",
                description="Logged URLs may contain sensitive query parameters.",
                evidence=match.group(0),
                remediation="Ensure no PII or auth tokens are in logged URLs.",
                module="dynamic.logcat"
            ))
            
    return findings, raw_lines

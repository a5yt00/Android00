from __future__ import annotations

import re
from pathlib import Path

from androidaudit.findings import Finding, Severity

def scan_crypto(source_dir: Path) -> list[Finding]:
    """
    Walk decompiled jadx output to detect weak cryptography patterns.
    """
    findings: list[Finding] = []
    
    skip_dirs = {"build", "test", ".gradle", "res"}
    
    for file_path in source_dir.rglob("*.java"):
        if not file_path.is_file():
            continue
            
        if any(part in skip_dirs for part in file_path.parts):
            continue
            
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
            
        lines = content.splitlines()
        has_crypto = "javax.crypto" in content or "java.security" in content
        has_keystore = "KeyStore.getInstance" in content
        
        if has_crypto and not has_keystore:
            findings.append(Finding(
                id="STAT-CRY-001",
                title="Cryptography Used Without KeyStore",
                severity=Severity.MEDIUM,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_score=4.0,
                owasp_category="M10: Insufficient Cryptography",
                description="File uses cryptography classes but does not reference KeyStore. Keys might be hardcoded.",
                evidence="File contains usage of javax.crypto without KeyStore",
                remediation="Use Android KeyStore to securely manage cryptographic keys.",
                module="static.crypto_check",
                file_path=str(file_path.relative_to(source_dir))
            ))

        for i, line in enumerate(lines):
            line_no = i + 1
            
            # Check weak ciphers
            if 'Cipher.getInstance("AES/ECB' in line or 'Cipher.getInstance("DES' in line:
                findings.append(Finding(
                    id="STAT-CRY-002",
                    title="Weak Block Cipher Mode (ECB/DES)",
                    severity=Severity.HIGH,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=7.5,
                    owasp_category="M10: Insufficient Cryptography",
                    description="AES/ECB mode is not semantically secure. DES is broken.",
                    evidence=line.strip(),
                    remediation="Use AES/GCM/NoPadding.",
                    module="static.crypto_check",
                    file_path=str(file_path.relative_to(source_dir)),
                    line_number=line_no
                ))
            
            # Check weak hashes
            if 'MessageDigest.getInstance("MD5")' in line or 'MessageDigest.getInstance("SHA1")' in line or 'MessageDigest.getInstance("SHA-1")' in line:
                findings.append(Finding(
                    id="STAT-CRY-003",
                    title="Weak Hashing Algorithm (MD5/SHA1)",
                    severity=Severity.HIGH,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cvss_score=7.5,
                    owasp_category="M10: Insufficient Cryptography",
                    description="MD5 and SHA-1 are cryptographically broken.",
                    evidence=line.strip(),
                    remediation="Use SHA-256 or bcrypt/Argon2 for passwords.",
                    module="static.crypto_check",
                    file_path=str(file_path.relative_to(source_dir)),
                    line_number=line_no
                ))
            
            # Check SecureRandom seeded
            if 'SecureRandom.setSeed' in line or re.search(r"new SecureRandom\([^)]+\)", line):
                findings.append(Finding(
                    id="STAT-CRY-004",
                    title="Seeded SecureRandom",
                    severity=Severity.HIGH,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cvss_score=5.3,
                    owasp_category="M10: Insufficient Cryptography",
                    description="SecureRandom instance should not be seeded with deterministic or weak seeds.",
                    evidence=line.strip(),
                    remediation="Use SecureRandom() without custom seeding to rely on the OS PRNG.",
                    module="static.crypto_check",
                    file_path=str(file_path.relative_to(source_dir)),
                    line_number=line_no
                ))
            
            # Hardcoded IV or Key - Look for common byte array definitions matching lengths like 16
            if re.search(r"new byte\[\]\s*{[^}]+}", line) and ("iv" in line.lower() or "key" in line.lower()):
                findings.append(Finding(
                    id="STAT-CRY-005",
                    title="Hardcoded IV or Key Byte Array",
                    severity=Severity.CRITICAL,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cvss_score=9.1,
                    owasp_category="M10: Insufficient Cryptography",
                    description="Cryptographic key or Initialization Vector appears to be hardcoded.",
                    evidence=line.strip(),
                    remediation="Generate keys/IVs dynamically use KeyStore.",
                    module="static.crypto_check",
                    file_path=str(file_path.relative_to(source_dir)),
                    line_number=line_no
                ))
                
    # Keep only unique findings for crypto to avoid flooding
    unique_findings = []
    seen = set()
    for f in findings:
        key = (f.id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings

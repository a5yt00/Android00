from __future__ import annotations
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
import re

from androidaudit.findings import Finding, Severity

SENSITIVE_COLS = ["password", "token", "secret", "key", "auth", "credential"]
KEYSTORE_EXTENSIONS = [".pem", ".p12", ".keystore", ".jks"]

def inspect_storage(local_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    
    for file_path in local_dir.rglob("*"):
        if not file_path.is_file():
            continue
            
        ext = file_path.suffix.lower()
        
        # 1. SQLite Databases
        if ext in [".db", ".sqlite", ".sqlite3"]:
            try:
                conn = sqlite3.connect(file_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                for (table_name,) in tables:
                    cursor.execute(f"PRAGMA table_info({table_name});")
                    columns = cursor.fetchall()
                    for col in columns:
                        col_name = col[1].lower()
                        if any(s in col_name for s in SENSITIVE_COLS):
                            findings.append(Finding(
                                id="STOR-SQL-001",
                                title=f"Sensitive Info in SQLite Column ({table_name}.{col_name})",
                                severity=Severity.HIGH,
                                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
                                cvss_score=4.4,
                                owasp_category="M9: Insecure Data Storage",
                                description=f"Found {col_name} in {file_path.name}/{table_name}.",
                                evidence=f"Table: {table_name}, Column: {col_name}",
                                remediation="Encrypt sensitive data using SQLCipher.",
                                module="storage.inspector"
                            ))
                conn.close()
            except sqlite3.Error:
                pass
                
        # 2. SharedPrefs
        elif ext == ".xml" and "shared_prefs" in str(file_path):
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                for child in root:
                    name = child.attrib.get('name', '').lower()
                    val = child.text or ""
                    
                    if any(s in name for s in SENSITIVE_COLS):
                        findings.append(Finding(
                            id="STOR-XML-001",
                            title=f"Sensitive SharedPreference Key ({name})",
                            severity=Severity.HIGH,
                            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=4.4,
                            owasp_category="M9: Insecure Data Storage",
                            description=f"Found key '{name}' in {file_path.name}.",
                            evidence=f"Key: {name}, Value: {val}",
                            remediation="Use EncryptedSharedPreferences.",
                            module="storage.inspector"
                        ))
                    elif len(val) > 30 and re.match(r"^[A-Za-z0-9+/=]+$", val):
                        findings.append(Finding(
                            id="STOR-XML-002",
                            title="Unencrypted Token in SharedPreferences",
                            severity=Severity.MEDIUM,
                            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
                            cvss_score=2.3,
                            owasp_category="M9: Insecure Data Storage",
                            description=f"Value for {name} looks like an unencrypted token.",
                            evidence=f"Value: {val}",
                            remediation="Use EncryptedSharedPreferences.",
                            module="storage.inspector"
                        ))
            except ET.ParseError:
                pass
                
        # 3. Files (Keystore checks)
        elif ext in KEYSTORE_EXTENSIONS:
            findings.append(Finding(
                id="STOR-FILE-001",
                title="Keystore File Present on Device",
                severity=Severity.CRITICAL,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=8.4,
                owasp_category="M9: Insecure Data Storage",
                description=f"App stores {ext} keystore inside its data directory.",
                evidence=f"File: {file_path.name}",
                remediation="Store keys securely inside the Android Hardware Keystore.",
                module="storage.inspector"
            ))

    return findings

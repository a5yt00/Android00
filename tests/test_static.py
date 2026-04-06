import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from androidaudit.modules.static.apk_parser import parse_apk
from androidaudit.modules.static.manifest import audit_manifest
from androidaudit.modules.static.secret_scan import scan_secrets, calculate_entropy
from androidaudit.modules.static.crypto_check import scan_crypto

def test_parse_apk(sample_apk_path: Path) -> None:
    with patch("androidaudit.modules.static.apk_parser.AnalyzeAPK") as mock_analyze:
        mock_a = MagicMock()
        mock_a.get_package.return_value = "com.test.app"
        mock_analyze.return_value = (mock_a, None, None)
        
        info = parse_apk(sample_apk_path)
        assert info["package_name"] == "com.test.app"

def test_audit_manifest(sample_apk_path: Path) -> None:
    with patch("androidaudit.modules.static.manifest.APK") as mock_apk:
        mock_a = MagicMock()
        mock_a.get_package.return_value = "com.test.app"
        mock_a.get_android_manifest_xml.return_value = None
        mock_apk.return_value = mock_a
        
        findings = audit_manifest(sample_apk_path)
        assert isinstance(findings, list)

def test_entropy() -> None:
    assert calculate_entropy("AAAA") == 0.0
    assert calculate_entropy("aB3$kL9#mP0@_xZ!vT") > 3.0

def test_scan_secrets(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    test_file = source_dir / "Test.java"
    test_file.write_text("String awsKey = \"AKIAIOSFODNN7EXAMPLE\";")
    
    findings = scan_secrets(source_dir)
    assert len(findings) >= 1
    assert any("AKIAIOSFODNN7EXAMPLE" in f.evidence for f in findings)

def test_scan_crypto(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    test_file = source_dir / "CryptoTest.java"
    test_file.write_text("""
    import javax.crypto.Cipher;
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    """)
    
    findings = scan_crypto(source_dir)
    assert len(findings) >= 1
    assert any("AES/ECB" in f.evidence for f in findings)

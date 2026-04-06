from __future__ import annotations

from pathlib import Path
from typing import Any

from androguard.core.apk import APK
from lxml import etree

from androidaudit.findings import Finding, Severity

def audit_manifest(apk_path: Path | str) -> list[Finding]:
    """
    Audit AndroidManifest.xml for common security misconfigurations.
    
    Args:
        apk_path: Path to the APK.
        
    Returns:
        A list of Finding objects detailing vulnerabilities found in the manifest.
    """
    findings: list[Finding] = []
    a = APK(str(apk_path))
    
    manifest_xml = a.get_android_manifest_xml()
    if manifest_xml is None:
        return findings

    app_element = manifest_xml.find("application")
    
    if app_element is not None:
        # Check debuggable
        debuggable = app_element.get("{http://schemas.android.com/apk/res/android}debuggable")
        if debuggable == "true":
            findings.append(Finding(
                id="STAT-MAN-001",
                title="Application is Debuggable",
                severity=Severity.HIGH,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=8.4,
                owasp_category="M8: Security Misconfiguration",
                description="android:debuggable is set to true. An attacker could attach a debugger.",
                evidence='android:debuggable="true"',
                remediation="Remove android:debuggable or set it to false for release builds.",
                module="static.manifest"
            ))

        # Check allowBackup
        allow_backup = app_element.get("{http://schemas.android.com/apk/res/android}allowBackup")
        if allow_backup == "true" or allow_backup is None:
            findings.append(Finding(
                id="STAT-MAN-002",
                title="Application Allows Backup",
                severity=Severity.MEDIUM,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=4.4,
                owasp_category="M9: Insecure Data Storage",
                description="android:allowBackup is true. App data can be backed up via adb.",
                evidence=f'android:allowBackup="{allow_backup if allow_backup else "default (true)"}"',
                remediation='Set android:allowBackup="false".',
                module="static.manifest"
            ))

        # Check usesCleartextTraffic
        cleartext = app_element.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
        if cleartext == "true":
            findings.append(Finding(
                id="STAT-MAN-003",
                title="Cleartext Traffic Allowed",
                severity=Severity.HIGH,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cvss_score=9.1,
                owasp_category="M5: Insecure Communication",
                description="The app allows unencrypted HTTP traffic.",
                evidence='android:usesCleartextTraffic="true"',
                remediation='Set android:usesCleartextTraffic="false".',
                module="static.manifest"
            ))

    # Check min sdk version
    min_sdk_str = a.get_min_sdk_version()
    if min_sdk_str and min_sdk_str.isdigit():
        if int(min_sdk_str) < 21:
            findings.append(Finding(
                id="STAT-MAN-004",
                title="Low Minimum SDK Version",
                severity=Severity.INFO,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                cvss_score=0.0,
                owasp_category="M8: Security Misconfiguration",
                description=f"App supports ancient Android versions (minSdkVersion {min_sdk_str}).",
                evidence=f'minSdkVersion="{min_sdk_str}"',
                remediation="Increase minSdkVersion to at least 21 (preferably 24+).",
                module="static.manifest"
            ))

    # Check exported components without permissions
    components = []
    components.extend(manifest_xml.findall(".//activity") or [])
    components.extend(manifest_xml.findall(".//service") or [])
    components.extend(manifest_xml.findall(".//receiver") or [])
    components.extend(manifest_xml.findall(".//provider") or [])

    for comp in components:
        exported = comp.get("{http://schemas.android.com/apk/res/android}exported")
        permission = comp.get("{http://schemas.android.com/apk/res/android}permission")
        name = comp.get("{http://schemas.android.com/apk/res/android}name")

        has_intent_filter = len(comp.findall(".//intent-filter")) > 0
        is_exported = False
        if exported == "true":
            is_exported = True
        elif exported is None and has_intent_filter:
            is_exported = True

        if is_exported and not permission:
            findings.append(Finding(
                id="STAT-MAN-005",
                title=f"Exported Component without Permission: {name}",
                severity=Severity.HIGH,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                cvss_score=8.4,
                owasp_category="M3: Insecure Authentication / Authorization",
                description="Component is exported but not protected by a permission.",
                evidence=etree.tostring(comp).decode("utf-8").split(">")[0] + ">",
                remediation="Add android:permission or set exported = false",
                module="static.manifest"
            ))

    return findings


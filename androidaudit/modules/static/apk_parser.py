from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TypedDict, Any

from androguard.misc import AnalyzeAPK


class APKInfo(TypedDict):
    package_name: str
    version_name: str
    min_sdk: str
    target_sdk: str
    permissions: list[str]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]


def parse_apk(apk_path: Path) -> APKInfo:
    """
    Parse an APK file using androguard.
    
    Args:
        apk_path: Path to the APK file.
        
    Returns:
        Structured dictionary containing APK metadata.
    """
    a, d, dx = AnalyzeAPK(str(apk_path))
    
    return {
        "package_name": a.get_package() or "",
        "version_name": a.get_androidversion_name() or "",
        "min_sdk": a.get_min_sdk_version() or "",
        "target_sdk": a.get_target_sdk_version() or "",
        "permissions": a.get_permissions() or [],
        "activities": a.get_activities() or [],
        "services": a.get_services() or [],
        "receivers": a.get_receivers() or [],
        "providers": a.get_providers() or [],
    }


def extract_dex(apk_path: Path, output_dir: Path) -> None:
    """
    Extract DEX files from APK for downstream checking if needed.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    a, _, _ = AnalyzeAPK(str(apk_path))
    for i, dex_bytes in enumerate(a.get_all_dex()):
        dex_path = output_dir / f"classes{i if i > 0 else ''}.dex"
        dex_path.write_bytes(dex_bytes)


def decompile_apk(apk_path: Path, output_dir: Path) -> None:
    """
    Run jadx to decompile the APK for downstream crypto and secret scanning.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["jadx", "-d", str(output_dir), "--no-res", str(apk_path)], check=True)
    except FileNotFoundError:
        import logging
        logging.warning("jadx not found in PATH. Skipping decompilation.")

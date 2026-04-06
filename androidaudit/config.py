from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass

import toml
from dotenv import load_dotenv

@dataclass
class AndroidAuditConfig:
    adb_serial: str | None
    target_package: str
    frida_server_path: str
    output_dir: Path

def load_config(config_path: Path | None = None) -> AndroidAuditConfig:
    """Loads configuration from .env and config.toml."""
    load_dotenv()
    
    config_data = {}
    if config_path and config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = toml.load(f)
            
    adb_serial = os.environ.get("ADB_SERIAL", config_data.get("adb_serial"))
    target_package = os.environ.get("TARGET_PACKAGE", config_data.get("target_package", ""))
    
    # Defaults
    default_frida = "/data/local/tmp/frida-server"
    frida_server_path = os.environ.get("FRIDA_SERVER_PATH", config_data.get("frida_server_path", default_frida))
    
    output_dir = Path(os.environ.get("OUTPUT_DIR", config_data.get("output_dir", "./reports")))
    
    return AndroidAuditConfig(
        adb_serial=adb_serial,
        target_package=target_package,
        frida_server_path=frida_server_path,
        output_dir=output_dir
    )

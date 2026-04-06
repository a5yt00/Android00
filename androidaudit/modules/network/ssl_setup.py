from __future__ import annotations
import os
from pathlib import Path

from androidaudit.session import ADBSession

class SSLSetup:
    """Manages mitmproxy CA cert installation and proxy routing."""
    def __init__(self, session: ADBSession) -> None:
        self.session = session
        
    def setup_proxy_and_cert(self) -> None:
        """Push mitmproxy CA cert and set device proxy to 127.0.0.1:8080"""
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        if not cert_path.exists():
            import time
            time.sleep(2)
            if not cert_path.exists():
                print(f"WARNING: MITM CA cert not found at {cert_path}. Run mitmproxy once to generate it.")
                return
            
        self.session.push(cert_path, "/sdcard/cert.pem")
        
        # Invoke intent to install cert
        self.session.shell("am start -a android.credentials.INSTALL -t application/x-x509-ca-cert -d file:///sdcard/cert.pem")
        
        # Setup Proxy globally
        self.session.shell("settings put global http_proxy 127.0.0.1:8080")
        
    def cleanup(self) -> None:
        """Remove global proxy setting."""
        self.session.shell("settings put global http_proxy :0")

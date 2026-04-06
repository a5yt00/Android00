from __future__ import annotations
import threading
import queue
import re
import asyncio

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.http import HTTPFlow

from androidaudit.findings import Finding, Severity

PII_PATTERN = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}|\b(?:\d[ -]*?){13,16}\b)")

class AndroidAuditAddon:
    def __init__(self, findings_queue: queue.Queue[Finding]) -> None:
        self.queue = findings_queue
        self.hosts: set[str] = set()
        
    def request(self, flow: HTTPFlow) -> None:
        host = flow.request.host
        self.hosts.add(host)
        
        # Check HTTP (non-TLS)
        if flow.request.scheme == "http":
            self.queue.put(Finding(
                id="NET-001",
                title="Cleartext HTTP Request",
                severity=Severity.HIGH,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cvss_score=9.1,
                owasp_category="M5: Insecure Communication",
                description=f"App communicates with {host} over unencrypted HTTP.",
                evidence=flow.request.url,
                remediation="Enforce HTTPS everywhere and use Network Security Config.",
                module="network.mitm"
            ))
            
        # Check credentials in URL params
        url_lower = flow.request.url.lower()
        if "password=" in url_lower or "token=" in url_lower:
             self.queue.put(Finding(
                id="NET-002",
                title="Credentials in Query Parameters",
                severity=Severity.CRITICAL,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5,
                owasp_category="M1: Improper Credential Usage",
                description="Sensitive tokens/passwords passed in URL parameters.",
                evidence=flow.request.url,
                remediation="Pass credentials securely in POST bodies or Authentication headers.",
                module="network.mitm"
            ))
             
        # Check PII in body
        if flow.request.content:
            try:
                body = flow.request.content.decode("utf-8")
                if PII_PATTERN.search(body):
                    self.queue.put(Finding(
                        id="NET-003",
                        title="Possible PII in Request Body",
                        severity=Severity.HIGH,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cvss_score=7.5,
                        owasp_category="M6: Inadequate Privacy Controls",
                        description="Request body contains suspected PII (Email, Phone, CC).",
                        evidence=flow.request.url,
                        remediation="Ensure PII transmission is necessary and encrypted.",
                        module="network.mitm"
                    ))
            except UnicodeDecodeError:
                pass

def run_mitm(findings_queue: queue.Queue[Finding]) -> None:
    """Run mitmproxy inside an asyncio loop in a separate thread."""
    
    async def _run():
        opts = options.Options(listen_host='127.0.0.1', listen_port=8080)
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(AndroidAuditAddon(findings_queue))
        try:
            await master.run()
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass

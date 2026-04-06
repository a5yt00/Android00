# AndroidAudit: Golden Code Standards

### 1. The Standard Module Pattern
Every module should follow this structure to ensure the Report Engine can parse it.

```python
from androidaudit.session import ADBSession
from androidaudit.findings import Finding, Severity

def scan_something(session: ADBSession, config: dict) -> list[Finding]:
    findings = []
    # Implementation...
    findings.append(Finding(
        id="STATIC-001",
        title="Insecure Configuration",
        severity=Severity.HIGH,
        owasp_category="M8: Security Misconfiguration",
        evidence="Found android:debuggable='true'",
        remediation="Set android:debuggable to 'false' in production."
    ))
    return findings
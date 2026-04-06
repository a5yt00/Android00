# AndroidAudit Code Examples

## Example: Creating a Module
Modules must take `ADBSession` and return a list of `Finding` objects.

```python
from __future__ import annotations
from androidaudit.session import ADBSession
from androidaudit.findings import Finding, Severity

def scan_something(session: ADBSession) -> list[Finding]:
    results = []
    output = session.shell("ls -la /data/data")
    if "some_bad_file" in output:
        results.append(Finding(
            id="STATIC-002",
            title="Bad File Found",
            severity=Severity.HIGH,
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_score=6.2,
            owasp_category="M9: Insecure Data Storage",
            description="Found a bad file indicating weak storage.",
            evidence=output,
            remediation="Remove the file.",
            module="static.some_module"
        ))
    return results
```

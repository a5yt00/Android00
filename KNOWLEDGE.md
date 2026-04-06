# AndroidAudit Knowledge Base

This document contains persistent knowledge related to the project architecture, dependencies, and rules.

## Core Directives
- **Stateless Modules:** Analysis modules are pure logic. They receive an `ADBSession` and configurations, and return `Finding` objects.
- **Single Source of Truth:** `ADBSession` is the ONLY class responsible for interacting with the Android device.
- **Python 3.11+:** Modern syntax required (e.g. `str | None`).
- **No Direct Subprocesses for ADB:** Never shell out directly when `pure-python-adb` properties via `ADBSession` can serve the same goal. When fallback is needed, it must stay inside `ADBSession`.
- **Absolute Type Integrity:** 100% type annotations with `strict = true` in mypy.

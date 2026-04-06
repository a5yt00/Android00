# AndroidAudit — Tech Stack

> A dedicated-device Android pentesting framework built for rooted hardware over USB/ADB.

---

## Language & Runtime

| Component | Choice | Reason |
|---|---|---|
| Language | Python 3.11+ | Frida bindings, androguard, mitmproxy all Python-native |
| Package manager | `pip` + `pyproject.toml` | Modern, PEP 517 compliant |
| Virtual env | `venv` or `uv` | Isolation from system Python |

---

## CLI & Interface

| Component | Library | Notes |
|---|---|---|
| CLI framework | `click` | Subcommands, options, argument parsing |
| Terminal UI | `rich` | Progress bars, tables, colored output, live panels |
| Config files | `python-dotenv` + TOML | `.env` for secrets, `config.toml` for device profiles |

---

## ADB & Device Layer

| Component | Library | Notes |
|---|---|---|
| Primary ADB driver | `pure-python-adb` | Programmatic ADB without subprocess |
| Fallback | `subprocess` + system `adb` | Edge cases: port forwarding, reverse proxy |
| Device detection | `adb devices` poll | Auto-reconnect on disconnect |
| Root verification | `adb shell id` | Confirms Magisk/SuperSU root at session start |
| Port forwarding | `adb forward tcp:<port>` | Frida server tunnel |
| Reverse proxy | `adb reverse tcp:8080 tcp:8080` | MITM traffic routing |

### ADB Session bootstrap sequence

```
1. adb devices              → verify device connected
2. adb shell id             → verify root access
3. adb push frida-server    → push if not present
4. adb shell ./frida-server → start Frida in background
5. adb reverse tcp:8080     → open MITM tunnel
```

---

## Static Analysis

| Component | Library / Tool | Notes |
|---|---|---|
| APK parsing | `androguard` | Manifest, permissions, code graphs, DEX analysis |
| Decompiler | `jadx` (subprocess) | Human-readable Java/Kotlin output |
| Disassembler | `apktool` (subprocess) | Smali-level inspection, resource extraction |
| Secret scanner | Custom regex + `math.log2` entropy | API keys, JWTs, Base64 creds, hardcoded IPs |
| Crypto checker | Custom AST walker on jadx output | Detects ECB mode, MD5 passwords, weak RNG |
| Manifest analyzer | `androguard.core.bytecodes.apk` | Exported components, `debuggable`, backup flags |

### Secret detection patterns

```python
PATTERNS = {
    "AWS key":       r"AKIA[0-9A-Z]{16}",
    "JWT":           r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Google API":    r"AIza[0-9A-Za-z_-]{35}",
    "Private key":   r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "High entropy":  # Shannon entropy > 4.5 on strings > 20 chars
}
```

---

## Dynamic Analysis

| Component | Library / Tool | Notes |
|---|---|---|
| Instrumentation | `frida` (Python bindings) | Runtime method hooking |
| Frida scripts | Custom `.js` in `/scripts/` | Pre-written hook bundles (see below) |
| Logcat capture | `adb logcat` subprocess | Runtime log leak detection |
| Activity monitor | `adb shell dumpsys activity` | Screen stack, intent monitoring |

### Pre-written Frida hook scripts

```
scripts/
├── ssl_pinning_bypass.js       # OkHttp, TrustManager, Conscrypt
├── root_detection_bypass.js    # RootBeer, custom checks, file checks
├── biometric_bypass.js         # BiometricPrompt, FingerprintManager
├── method_tracer.js            # Generic class/method trace + args logger
├── crypto_interceptor.js       # Cipher.getInstance, MessageDigest intercept
└── intent_monitor.js           # startActivity, sendBroadcast capture
```

---

## Network Interception

| Component | Library | Notes |
|---|---|---|
| MITM proxy | `mitmproxy` (programmatic API) | Not subprocess — Python addon hooks |
| CA cert install | `adb push` + `adb shell` | Push cert, set as user/system CA |
| System proxy config | `adb shell settings put global` | HTTP_PROXY, HTTPS_PROXY via ADB |
| Traffic routing | `adb reverse tcp:8080 tcp:8080` | Device → host tunnel (no WiFi needed) |
| Traffic analysis | `mitmproxy` addon + custom scripts | Flag PII leaks, insecure endpoints |

### Why `adb reverse` over WiFi proxy

- Works even when device and host are on different network segments
- No need to touch WiFi settings — pure USB tunnel
- Survives WiFi reconnects during long test sessions

---

## Storage & Filesystem Forensics

| Component | Library / Tool | Notes |
|---|---|---|
| File pulling | `adb pull` via pure-python-adb | `/data/data/<pkg>/`, `/sdcard/` |
| SQLite inspection | `sqlite3` (stdlib) | Dump tables, check encryption |
| SharedPreferences | `xml.etree.ElementTree` (stdlib) | Parse XML prefs, flag sensitive keys |
| Keystore audit | Custom checker | Verify Android Keystore usage vs hardcoded keys |
| File permissions | `adb shell ls -la` | World-readable files, insecure modes |
| Backup extraction | `adb backup` + `java -jar abe.jar` | Android Backup Extractor for `.ab` files |

### Storage paths checked automatically

```
/data/data/<package>/databases/        → SQLite DBs
/data/data/<package>/shared_prefs/     → SharedPreferences XML
/data/data/<package>/files/            → Arbitrary file storage
/data/data/<package>/cache/            → Cached network responses
/sdcard/Android/data/<package>/        → External storage
```

---

## Report Engine

| Component | Library | Notes |
|---|---|---|
| HTML reports | `jinja2` | Templated, self-contained HTML with findings |
| JSON export | `json` (stdlib) | Machine-readable, CI/CD pipeline friendly |
| Markdown export | f-strings / `jinja2` | GitHub Issues / pull request integration |
| CVSS scoring | `cvss` library | CVSS v3.1 base score per finding |
| OWASP mapping | Custom lookup table | Maps each finding to OWASP Mobile Top 10 (2024) |

### Finding data model

```python
@dataclass
class Finding:
    id: str                        # e.g. "STATIC-001"
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    cvss_vector: str               # e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    cvss_score: float
    owasp_category: str            # e.g. "M1: Improper Credential Usage"
    description: str
    evidence: str                  # raw output / code snippet
    remediation: str
    module: str                    # which module found it
```

---

## Project Structure

```
androidaudit/
├── pyproject.toml
├── README.md
├── TECHSTACK.md
├── config.toml                    # device profile, target package
├── androidaudit/
│   ├── __init__.py
│   ├── cli.py                     # Click entry points
│   ├── session.py                 # ADBSession — device lifecycle manager
│   ├── findings.py                # Finding dataclass + severity enum
│   ├── config.py                  # Config loader
│   ├── modules/
│   │   ├── static/
│   │   │   ├── apk_parser.py      # androguard wrapper
│   │   │   ├── secret_scan.py     # regex + entropy scanner
│   │   │   ├── manifest.py        # manifest flag checker
│   │   │   └── crypto_check.py    # weak crypto patterns
│   │   ├── dynamic/
│   │   │   ├── frida_runner.py    # frida-python wrapper
│   │   │   ├── logcat.py          # logcat stream parser
│   │   │   └── scripts/           # .js Frida hook scripts
│   │   ├── network/
│   │   │   ├── mitm.py            # mitmproxy programmatic setup
│   │   │   └── ssl_setup.py       # cert push + proxy config via ADB
│   │   └── storage/
│   │       ├── puller.py          # adb pull + path discovery
│   │       └── inspector.py       # sqlite, xml, keystore analysis
│   └── report/
│       ├── engine.py              # finding aggregator + deduplication
│       ├── cvss.py                # CVSS v3.1 score calculator
│       └── templates/
│           ├── report.html.j2     # full HTML report template
│           └── summary.md.j2      # markdown summary template
└── tests/
    ├── test_static.py
    ├── test_session.py
    └── fixtures/                  # sample APKs for unit tests
```

---

## Dependencies (`pyproject.toml`)

```toml
[project]
name = "androidaudit"
version = "0.1.0"
requires-python = ">=3.11"

dependencies = [
    # CLI
    "click>=8.1",
    "rich>=13.0",
    "python-dotenv>=1.0",

    # ADB
    "pure-python-adb>=0.3",

    # Static analysis
    "androguard>=3.3",

    # Dynamic analysis
    "frida>=16.0",
    "frida-tools>=12.0",

    # Network interception
    "mitmproxy>=10.0",

    # Reporting
    "jinja2>=3.1",
    "cvss>=2.6",

    # Utilities
    "pycryptodome>=3.20",
    "toml>=0.10",
]

[project.scripts]
androidaudit = "androidaudit.cli:main"
```

---

## External Tools (must be on PATH)

| Tool | Purpose | Install |
|---|---|---|
| `adb` | Android Debug Bridge | Android Platform Tools |
| `jadx` | APK decompiler | `brew install jadx` / GitHub release |
| `apktool` | APK disassembler | `brew install apktool` / GitHub release |
| `frida-server` | Device-side Frida binary | Push to device via ADB (auto by tool) |

---

## Device Requirements

| Requirement | Details |
|---|---|
| Android version | 10+ (API 29+) recommended |
| Root | Magisk (preferred) or SuperSU |
| USB debugging | Enabled in Developer Options |
| USB mode | MTP or File Transfer (not Charging only) |
| `frida-server` | Matching version to host `frida` Python package |
| SELinux | Permissive mode recommended for full access |

---

## CLI Usage (planned)

```bash
# Full pentest session against a package
androidaudit run --package com.target.app --output ./report/

# Static analysis only (no device needed)
androidaudit static --apk ./target.apk

# Start MITM proxy and capture traffic
androidaudit network --package com.target.app --duration 60

# Pull and inspect app storage
androidaudit storage --package com.target.app

# List connected devices
androidaudit devices

# Generate report from saved session
androidaudit report --session ./sessions/2025-04-06/ --format html
```

---

## OWASP Mobile Top 10 (2024) Coverage

| ID | Category | Modules |
|---|---|---|
| M1 | Improper Credential Usage | `secret_scan`, `storage` |
| M2 | Inadequate Supply Chain Security | `apk_parser` |
| M3 | Insecure Authentication / Authorization | `frida_runner`, `manifest` |
| M4 | Insufficient Input/Output Validation | `static`, `network` |
| M5 | Insecure Communication | `network`, `mitm` |
| M6 | Inadequate Privacy Controls | `storage`, `logcat` |
| M7 | Insufficient Binary Protections | `apk_parser`, `static` |
| M8 | Security Misconfiguration | `manifest`, `storage` |
| M9 | Insecure Data Storage | `storage`, `inspector` |
| M10 | Insufficient Cryptography | `crypto_check`, `frida_runner` |

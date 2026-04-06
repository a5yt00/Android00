Here's the full blueprint — two diagrams: the system architecture first, then the pentest workflow. Let's start with how all the layers connect.Now the pentest workflow — how a session flows from target selection through to report generation:Here's the full tech stack and blueprint breakdown:

---

## Tech stack

**Language & runtime:** Python 3.11+ is the anchor. The ecosystem (Frida bindings, androguard, mitmproxy, rich) is Python-native and nothing beats it for rapid module development.

**CLI / UX:** `click` for the command structure, `rich` for live tables, progress bars, and colored output. The tool should feel like a proper CLI, not a script dump.

**ADB layer:** `pure-python-adb` as the primary driver, with a subprocess fallback to the real `adb` binary for edge cases. You wrap this in your own `ADBSession` class that manages the connection, auto-reconnects on drop, and handles port forwarding/reversing.

**Static analysis:** `androguard` for deep APK parsing (manifest, permissions, code graphs). `jadx` or `apktool` called as subprocesses for human-readable decompiled output. Custom regex + entropy engine for secret scanning (API keys, JWTs, Base64-encoded credentials, hardcoded IPs).

**Dynamic analysis:** `frida-python` for the host-side Frida API. You ship a set of pre-written JS hook scripts that live in a `/scripts/` folder — one for SSL pinning bypass, one for root detection bypass, one for biometric bypass, one for method tracing. The tool pushes and starts `frida-server` on the device via ADB before running.

**Network interception:** `mitmproxy` in programmatic mode (not subprocess). You use `adb reverse tcp:8080 tcp:8080` to tunnel traffic through your host, then push a WiFi proxy config or use `adb shell settings put global` to set the system proxy. CA cert install goes via `adb push` + shell commands.

**Storage forensics:** Pure ADB — pull `/data/data/<package>/`, `/sdcard/Android/data/<package>/`, then parse with `sqlite3` (stdlib), `xml.etree` for SharedPreferences, and `pycryptodome` for checking crypto implementations.

**Report engine:** `jinja2` for HTML reports. `json` stdlib for machine-readable output. Each finding gets a CVSS v3.1 score, OWASP Mobile Top 10 category tag, and a remediation recommendation. Optional markdown output for GitHub issues.

---

## Project structure

```
androidaudit/
├── cli.py                  # Click entry points
├── session.py              # ADBSession, device lifecycle
├── modules/
│   ├── static/
│   │   ├── apk_parser.py   # androguard wrapper
│   │   ├── secret_scan.py  # regex + entropy
│   │   └── manifest.py     # exported comps, flags
│   ├── dynamic/
│   │   ├── frida_runner.py # frida-python wrapper
│   │   └── scripts/        # .js hook scripts
│   ├── network/
│   │   ├── mitm.py         # mitmproxy programmatic
│   │   └── ssl_setup.py    # cert push + proxy config
│   └── storage/
│       ├── puller.py       # adb pull + path discovery
│       └── inspector.py    # sqlite, xml, keystore
├── report/
│   ├── engine.py           # finding aggregator
│   ├── cvss.py             # score calculator
│   └── templates/          # jinja2 HTML templates
├── config.py               # device profile, target pkg
└── findings.py             # Finding dataclass + severity
```

---

## Key ADB-specific design decisions

Since you have a dedicated device, you get to make some strong assumptions: root is always available, `frida-server` is pre-installed or gets pushed at session start, and USB debugging is always on. This lets you skip the emulator-detection layer and all the "maybe rooted, maybe not" branching.

The `ADBSession` class should do three things on init: verify device connectivity with `adb devices`, check for root with `adb shell id`, and push + start `frida-server` if it isn't already running. Everything else in the tool talks to the device only through that session object — no raw subprocess calls scattered across modules.

For network interception, `adb reverse` is cleaner than WiFi proxy because it works even if the device is on a different network segment. You tunnel port 8080 from device → host, mitmproxy listens on host:8080, and all app traffic routes through it automatically.

---

Want me to start generating actual code? I can begin with the `ADBSession` class and CLI skeleton, which everything else builds on top of.
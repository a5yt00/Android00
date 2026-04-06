# Development Constraints for AndroidAudit

### 1. Architectural Rules
- **No Direct Subprocesses:** Never use `subprocess.run` or `os.system` for ADB commands. ALL device interaction must use the `ADBSession` class.
- **Stateless Modules:** Analysis modules must not store state. They take an `ADBSession` and a config, and return `Finding` objects.
- **Path Handling:** Use `pathlib.Path` exclusively. Do not use `os.path` or string concatenation for file paths.

### 2. Code Quality & Style
- **Type Hinting:** 100% type hint coverage is required for all function signatures.
- **Output:** Never use `print()`. Use the `rich.console.Console` instance provided by the CLI layer for user-facing feedback.
- **Logging:** Use the standard `logging` library for internal debug traces.

### 3. Dependencies & Versions
- **Frida:** Version must be `>=16.0`. Do not downgrade for compatibility with old devices.
- **Python:** Minimum version is `3.11`. Use modern syntax (e.g., `|` for Union types).
- **No New Deps:** Do not add entries to `pyproject.toml` without explicit user approval.

### 4. Security
- **No Hardcoded Secrets:** Never bake test API keys or IP addresses into the source code.
- **Local Only:** No telemetry or external API calls (except if an LLM-module is explicitly enabled by the user).
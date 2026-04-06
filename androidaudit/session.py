from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterator

from ppadb.client import Client as AdbClient

from androidaudit.exceptions import DeviceNotFoundError, RootNotAvailableError


class ADBSession:
    """Manages the connection and interaction with an Android device over ADB."""

    def __init__(self, serial: str | None = None) -> None:
        """
        Initialize the ADBSession.
        
        Args:
            serial: The specific device serial to connect to. If None, connects to the first available device.
        """
        self.serial = serial
        self.client = AdbClient(host="127.0.0.1", port=5037)
        self.device = None

    def connect(self) -> None:
        """
        Connect to the device, verify root, and prepare the environment.
        
        1. Run `adb devices` and select device (auto or by serial).
        2. Verify root with `adb shell id`.
        3. Push frida-server if not present.
        4. Start frida-server in background.
        5. Set up `adb reverse tcp:8080 tcp:8080` for MITM tunnel.
        
        Raises:
            DeviceNotFoundError: If no matching device is found.
            RootNotAvailableError: If the device does not have root access.
        """
        try:
            devices = self.client.devices()
        except Exception:
            # Try to start adb server if not running
            subprocess.run(["adb", "start-server"], check=False)
            try:
                devices = self.client.devices()
            except Exception:
                devices = []

        if not devices:
            raise DeviceNotFoundError("No ADB devices connected.")

        if self.serial:
            for d in devices:
                if d.serial == self.serial:
                    self.device = d
                    break
            if not self.device:
                raise DeviceNotFoundError(f"Device with serial '{self.serial}' not found.")
        else:
            self.device = devices[0]
            self.serial = self.device.serial

        # Verify Root
        id_output = self.shell("id")
        if "uid=0(root)" not in id_output:
            # Retry gaining root just in case
            subprocess.run(["adb", "-s", self.serial, "root"], check=False, capture_output=True)
            id_output = self.shell("id")
            if "uid=0(root)" not in id_output:
                raise RootNotAvailableError("Failed to gain root access on the device.")

        # Push frida-server if not present, and start it
        frida_server_path = "/data/local/tmp/frida-server"
        frida_running = self.shell("ps -A")
        if "frida-server" not in frida_running:
            self.shell(f"chmod +x {frida_server_path}")
            self.shell(f"nohup {frida_server_path} >/dev/null 2>&1 &")

        # Set up reverse tunnel
        self.reverse(8080, 8080)

    def shell(self, command: str) -> str:
        """
        Execute shell command on device, return stdout.
        
        Args:
            command: The command to run.
            
        Returns:
            The standard output of the command.
        """
        if not self.device:
            raise DeviceNotFoundError("Session is not connected to a device.")
        
        # device.shell returns str according to pure-python-adb
        output = self.device.shell(command)
        return str(output) if output else ""

    def push(self, local: Path, remote: str) -> None:
        """
        Push file to device.
        
        Args:
            local: Local file path.
            remote: Remote file path.
        """
        if not self.device:
            raise DeviceNotFoundError("Session is not connected to a device.")
        self.device.push(str(local), remote)

    def pull(self, remote: str, local: Path) -> None:
        """
        Pull file or directory from device.
        
        Args:
            remote: Remote file or directory path.
            local: Local destination path.
        """
        if not self.device or not self.serial:
            raise DeviceNotFoundError("Session is not connected to a device.")
        # Fallback to subprocess for robust directory pulling since ppadb has simple file pull
        subprocess.run(["adb", "-s", self.serial, "pull", remote, str(local)], check=True)

    def forward(self, local_port: int, remote_port: int) -> None:
        """adb forward tcp:<local> tcp:<remote>"""
        if not self.device or not self.serial:
            raise DeviceNotFoundError("Session is not connected to a device.")
        subprocess.run(["adb", "-s", self.serial, "forward", f"tcp:{local_port}", f"tcp:{remote_port}"], check=True)

    def reverse(self, remote_port: int, local_port: int) -> None:
        """adb reverse tcp:<remote> tcp:<local>"""
        if not self.device or not self.serial:
            raise DeviceNotFoundError("Session is not connected to a device.")
        subprocess.run(["adb", "-s", self.serial, "reverse", f"tcp:{remote_port}", f"tcp:{local_port}"], check=True)

    def logcat(self, package: str) -> Iterator[str]:
        """Stream logcat filtered to package, yield lines."""
        if not self.device or not self.serial:
            raise DeviceNotFoundError("Session is not connected to a device.")
        
        pid_output = self.shell(f"pidof {package}")
        if not pid_output.strip():
            return
        
        pid = pid_output.strip()
        process = subprocess.Popen(
            ["adb", "-s", self.serial, "logcat", "--pid", pid],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if process.stdout:
            for line in process.stdout:
                yield line

    def get_apk_path(self, package: str) -> str:
        """Return on-device path of installed APK via pm path."""
        if not self.device:
            raise DeviceNotFoundError("Session is not connected to a device.")
        output = self.shell(f"pm path {package}")
        if not output or "package:" not in output:
            return ""
        return output.split("package:")[1].strip()

    def install_apk(self, apk_path: Path) -> None:
        """adb install with -r -d flags."""
        if not self.device:
            raise DeviceNotFoundError("Session is not connected to a device.")
        self.device.install(str(apk_path), "-r", "-d")

    def disconnect(self) -> None:
        """Clean up port forwards and reverse tunnels."""
        if self.serial:
            subprocess.run(["adb", "-s", self.serial, "forward", "--remove-all"], check=False)
            subprocess.run(["adb", "-s", self.serial, "reverse", "--remove-all"], check=False)

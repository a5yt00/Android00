from __future__ import annotations
from typing import Callable, Any
from pathlib import Path
import time
import queue

import frida

from androidaudit.session import ADBSession
from androidaudit.exceptions import FridaServerError

class FridaRunner:
    def __init__(self, session: ADBSession, package: str) -> None:
        self.session = session
        self.package = package
        self.device: frida.core.Device | None = None
        self.frida_session: frida.core.Session | None = None
        self.scripts: dict[str, frida.core.Script] = {}
        self.message_queue: queue.Queue[dict[str, Any]] = queue.Queue()

    def attach(self) -> None:
        """Attach to the target process. If not running, launch it."""
        try:
            # Try to start frida-server first
            self.session.shell("su -c 'killall frida-server'")
            self.session.shell("su -c '/data/local/tmp/frida-server -D'")
            time.sleep(2)
            
            try:
                self.device = frida.get_usb_device(timeout=3)
            except Exception:
                # Fallback to local remote connection if port forwarded, but usually usb_device works for wireless ADB
                self.device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        except Exception as e:
            raise FridaServerError(f"Could not connect to Frida: {e}")

        try:
            # Try to spawn the app directly ensuring a fresh cold-start and successful hook entry
            pid = self.device.spawn([self.package])
            self.frida_session = self.device.attach(pid)
            self.device.resume(pid)
        except Exception as e:
            # If spawn fails, it might already be actively stuck in fg. Try direct attach
            try:
                self.frida_session = self.device.attach(self.package)
            except frida.ProcessNotFoundError:
                raise FridaServerError(f"Failed to attach or spawn {self.package}. Error: {e}")

    def _on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        self.message_queue.put(message)

    def run_script(self, script_name: str) -> None:
        """Load and run a script from the modules/dynamic/scripts dir."""
        if not self.frida_session:
            raise FridaServerError("Not attached to any process.")
        
        script_path = Path(__file__).parent / "scripts" / f"{script_name}.js"
        if not script_path.exists():
            raise FileNotFoundError(f"Frida script {script_path} not found.")

        source = script_path.read_text(encoding="utf-8")
        script = self.frida_session.create_script(source)
        script.on("message", self._on_message)
        script.load()
        self.scripts[script_name] = script

    def detach(self) -> None:
        """Detach all scripts and session."""
        for name, script in self.scripts.items():
            try:
                script.unload()
            except Exception:
                pass
        if self.frida_session:
            self.frida_session.detach()
            
    def get_messages(self) -> list[dict[str, Any]]:
        msgs = []
        while not self.message_queue.empty():
            msgs.append(self.message_queue.get())
        return msgs

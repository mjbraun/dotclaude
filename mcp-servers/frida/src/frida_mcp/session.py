# ABOUTME: Frida session management for app instrumentation
# ABOUTME: Handles spawning/attaching to apps with SSL bypass injection

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import frida

from .device import get_device


@dataclass
class SessionInfo:
    """Information about an active Frida session."""
    pid: int
    package: str
    device_id: str


# Path to SSL bypass script
_SCRIPT_DIR = Path(__file__).parent.parent.parent / "scripts"
_SSL_BYPASS_SCRIPT = _SCRIPT_DIR / "ssl_bypass.js"


def _get_ssl_bypass_script() -> str:
    """Load the SSL bypass script."""
    if not _SSL_BYPASS_SCRIPT.exists():
        raise FileNotFoundError(f"SSL bypass script not found: {_SSL_BYPASS_SCRIPT}")
    return _SSL_BYPASS_SCRIPT.read_text()


class SessionManager:
    """Manages Frida sessions with SSL bypass."""

    def __init__(self):
        self._sessions: dict[str, tuple[frida.core.Session, frida.core.Script]] = {}

    @property
    def active_sessions(self) -> list[SessionInfo]:
        """List active sessions."""
        result = []
        for package, (session, _) in self._sessions.items():
            try:
                # Check if session is still valid
                pid = session.pid
                result.append(SessionInfo(
                    pid=pid,
                    package=package,
                    device_id=session._impl.device.id if hasattr(session, '_impl') else "unknown",
                ))
            except frida.InvalidOperationError:
                # Session is dead, will be cleaned up later
                pass
        return result

    def spawn(
        self,
        package: str,
        device_id: Optional[str] = None,
        inject_ssl_bypass: bool = True,
    ) -> SessionInfo:
        """
        Spawn an application and optionally inject SSL bypass.

        Args:
            package: Package identifier (e.g., com.skylight.app)
            device_id: Device ID (default: USB device)
            inject_ssl_bypass: Whether to inject SSL bypass script

        Returns:
            SessionInfo for the spawned app
        """
        if package in self._sessions:
            self.detach(package)

        device = get_device(device_id)

        # Spawn the app suspended
        pid = device.spawn([package])

        # Attach to the spawned process
        session = device.attach(pid)

        script = None
        if inject_ssl_bypass:
            script_source = _get_ssl_bypass_script()
            script = session.create_script(script_source)
            script.on("message", self._on_message)
            script.load()

        # Resume the app
        device.resume(pid)

        self._sessions[package] = (session, script)

        return SessionInfo(
            pid=pid,
            package=package,
            device_id=device.id,
        )

    def attach(
        self,
        package: str,
        device_id: Optional[str] = None,
        inject_ssl_bypass: bool = True,
    ) -> SessionInfo:
        """
        Attach to a running application.

        Args:
            package: Package identifier or PID
            device_id: Device ID (default: USB device)
            inject_ssl_bypass: Whether to inject SSL bypass script

        Returns:
            SessionInfo for the attached process
        """
        if package in self._sessions:
            self.detach(package)

        device = get_device(device_id)

        # Attach to running process
        session = device.attach(package)
        pid = session.pid

        script = None
        if inject_ssl_bypass:
            script_source = _get_ssl_bypass_script()
            script = session.create_script(script_source)
            script.on("message", self._on_message)
            script.load()

        self._sessions[package] = (session, script)

        return SessionInfo(
            pid=pid,
            package=package,
            device_id=device.id,
        )

    def detach(self, package: str) -> bool:
        """
        Detach from an application.

        Args:
            package: Package identifier

        Returns:
            True if successfully detached, False if not found
        """
        if package not in self._sessions:
            return False

        session, script = self._sessions.pop(package)

        try:
            if script:
                script.unload()
        except frida.InvalidOperationError:
            pass

        try:
            session.detach()
        except frida.InvalidOperationError:
            pass

        return True

    def detach_all(self) -> int:
        """
        Detach from all sessions.

        Returns:
            Number of sessions detached
        """
        packages = list(self._sessions.keys())
        for package in packages:
            self.detach(package)
        return len(packages)

    def _on_message(self, message, data):
        """Handle messages from Frida scripts (silently - stdout breaks MCP)."""
        # Don't print to stdout - it corrupts the MCP stdio protocol
        # Messages are logged internally but not output
        pass

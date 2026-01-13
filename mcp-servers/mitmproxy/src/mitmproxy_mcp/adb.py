# ABOUTME: Android adb integration for proxy control
# ABOUTME: Provides device listing and global proxy enable/disable via adb

import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class DeviceInfo:
    """Information about a connected Android device."""
    id: str
    status: str
    model: Optional[str] = None
    product: Optional[str] = None


def is_adb_available() -> bool:
    """Check if adb is available on the system."""
    try:
        subprocess.run(
            ["adb", "version"],
            capture_output=True,
            check=False,
        )
        return True
    except FileNotFoundError:
        return False


def list_devices() -> list[DeviceInfo]:
    """
    List connected Android devices.

    Returns:
        List of DeviceInfo objects

    Raises:
        RuntimeError: If adb is not available
    """
    try:
        result = subprocess.run(
            ["adb", "devices", "-l"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("adb not found - ensure Android SDK platform-tools is installed")

    devices = []
    lines = result.stdout.strip().split("\n")

    for line in lines[1:]:  # Skip "List of devices attached" header
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        device_id = parts[0]
        status = parts[1]

        # Parse optional properties like model:Pixel_5a
        model = None
        product = None
        for part in parts[2:]:
            if part.startswith("model:"):
                model = part.split(":", 1)[1]
            elif part.startswith("product:"):
                product = part.split(":", 1)[1]

        devices.append(DeviceInfo(
            id=device_id,
            status=status,
            model=model,
            product=product,
        ))

    return devices


def get_local_ip() -> str:
    """
    Get the local IP address of this machine.

    Returns:
        Local IPv4 address as a string
    """
    try:
        # Create a socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback to localhost
        return "127.0.0.1"


def _run_adb_command(args: list[str], device_id: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run an adb command, optionally targeting a specific device."""
    cmd = ["adb"]
    if device_id:
        cmd.extend(["-s", device_id])
    cmd.extend(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def enable_proxy(
    host: str,
    port: int,
    device_id: Optional[str] = None,
) -> bool:
    """
    Enable global HTTP proxy on an Android device.

    Args:
        host: Proxy server hostname or IP
        port: Proxy server port
        device_id: Specific device ID (optional)

    Returns:
        True if successful, False otherwise
    """
    proxy_value = f"{host}:{port}"
    result = _run_adb_command(
        ["shell", "settings", "put", "global", "http_proxy", proxy_value],
        device_id=device_id,
    )
    return result.returncode == 0


def disable_proxy(device_id: Optional[str] = None) -> bool:
    """
    Disable global HTTP proxy on an Android device.

    Args:
        device_id: Specific device ID (optional)

    Returns:
        True if successful, False otherwise
    """
    result = _run_adb_command(
        ["shell", "settings", "put", "global", "http_proxy", ":0"],
        device_id=device_id,
    )
    return result.returncode == 0


def get_current_proxy(device_id: Optional[str] = None) -> Optional[str]:
    """
    Get the current proxy setting from an Android device.

    Args:
        device_id: Specific device ID (optional)

    Returns:
        Proxy setting string (host:port) or None if not set
    """
    result = _run_adb_command(
        ["shell", "settings", "get", "global", "http_proxy"],
        device_id=device_id,
    )
    if result.returncode != 0:
        return None

    value = result.stdout.strip()
    if not value or value == "null" or value == ":0":
        return None

    return value

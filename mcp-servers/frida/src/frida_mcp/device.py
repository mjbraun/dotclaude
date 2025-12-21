# ABOUTME: Frida device and application management
# ABOUTME: Wraps Frida APIs for device enumeration and app interaction

from dataclasses import dataclass
from typing import Optional

import frida


@dataclass
class DeviceInfo:
    """Information about a connected device."""
    id: str
    name: str
    type: str


@dataclass
class PackageInfo:
    """Information about an installed application."""
    identifier: str
    name: str


def list_devices(include_local: bool = False) -> list[DeviceInfo]:
    """
    List connected devices.

    Args:
        include_local: Include local system device (default False)

    Returns:
        List of DeviceInfo objects
    """
    devices = frida.enumerate_devices()
    result = []

    for device in devices:
        if not include_local and device.type == "local":
            continue
        result.append(DeviceInfo(
            id=device.id,
            name=device.name,
            type=device.type,
        ))

    return result


def get_device(device_id: Optional[str] = None) -> frida.core.Device:
    """
    Get a Frida device handle.

    Args:
        device_id: Specific device ID, or None for USB device

    Returns:
        Frida Device object
    """
    if device_id:
        return frida.get_device(device_id)
    return frida.get_usb_device()


def list_packages(
    device_id: Optional[str] = None,
    query: Optional[str] = None,
) -> list[PackageInfo]:
    """
    List installed applications on a device.

    Args:
        device_id: Device to query (default: USB device)
        query: Filter by package name or app name

    Returns:
        List of PackageInfo objects
    """
    device = get_device(device_id)
    apps = device.enumerate_applications()

    result = []
    for app in apps:
        if query:
            query_lower = query.lower()
            if query_lower not in app.identifier.lower() and query_lower not in app.name.lower():
                continue

        result.append(PackageInfo(
            identifier=app.identifier,
            name=app.name,
        ))

    return sorted(result, key=lambda p: p.name.lower())

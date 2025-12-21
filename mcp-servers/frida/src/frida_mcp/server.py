# ABOUTME: MCP server for Frida-based Android instrumentation
# ABOUTME: Exposes tools for SSL pinning bypass and app debugging

import json
from dataclasses import asdict
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .device import list_devices, list_packages, DeviceInfo, PackageInfo
from .session import SessionManager, SessionInfo

# Global session manager
_session_manager = SessionManager()

# Create the MCP server
mcp = FastMCP("frida")


@mcp.tool()
def frida_list_devices(include_local: bool = False) -> str:
    """
    List connected Android devices.

    Args:
        include_local: Include local system device (default False)

    Returns:
        JSON array of connected devices
    """
    try:
        devices = list_devices(include_local=include_local)
        return json.dumps([asdict(d) for d in devices], indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def frida_list_packages(
    device_id: Optional[str] = None,
    query: Optional[str] = None,
) -> str:
    """
    List installed applications on a device.

    Args:
        device_id: Device to query (default: first USB device)
        query: Filter by package name or app name

    Returns:
        JSON array of installed applications
    """
    try:
        packages = list_packages(device_id=device_id, query=query)
        return json.dumps([asdict(p) for p in packages], indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def frida_spawn(
    package: str,
    device_id: Optional[str] = None,
    ssl_bypass: bool = True,
) -> str:
    """
    Spawn an application with SSL pinning bypass.

    This kills any existing instance of the app and starts it fresh
    with Frida instrumentation injected from the start.

    Args:
        package: Package identifier (e.g., com.skylight.app)
        device_id: Device ID (default: first USB device)
        ssl_bypass: Whether to inject SSL bypass (default True)

    Returns:
        JSON with session info
    """
    try:
        session = _session_manager.spawn(
            package=package,
            device_id=device_id,
            inject_ssl_bypass=ssl_bypass,
        )
        return json.dumps({
            "status": "spawned",
            "session": asdict(session),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def frida_attach(
    package: str,
    device_id: Optional[str] = None,
    ssl_bypass: bool = True,
) -> str:
    """
    Attach to a running application with SSL pinning bypass.

    Use this if the app is already running. For best results with
    SSL bypass, use spawn instead (injects before app initializes).

    Args:
        package: Package identifier (e.g., com.skylight.app)
        device_id: Device ID (default: first USB device)
        ssl_bypass: Whether to inject SSL bypass (default True)

    Returns:
        JSON with session info
    """
    try:
        session = _session_manager.attach(
            package=package,
            device_id=device_id,
            inject_ssl_bypass=ssl_bypass,
        )
        return json.dumps({
            "status": "attached",
            "session": asdict(session),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def frida_detach(package: str) -> str:
    """
    Detach from an application.

    The app will continue running but without Frida instrumentation.

    Args:
        package: Package identifier

    Returns:
        Status message
    """
    if _session_manager.detach(package):
        return json.dumps({"status": "detached", "package": package})
    else:
        return json.dumps({"error": f"No active session for {package}"})


@mcp.tool()
def frida_detach_all() -> str:
    """
    Detach from all applications.

    Returns:
        Number of sessions detached
    """
    count = _session_manager.detach_all()
    return json.dumps({"status": "detached_all", "count": count})


@mcp.tool()
def frida_list_sessions() -> str:
    """
    List active Frida sessions.

    Returns:
        JSON array of active sessions
    """
    sessions = _session_manager.active_sessions
    return json.dumps([asdict(s) for s in sessions], indent=2)


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()

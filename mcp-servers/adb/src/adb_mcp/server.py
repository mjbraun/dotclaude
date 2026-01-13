# ABOUTME: MCP server for Android Debug Bridge (adb) interaction
# ABOUTME: Supports USB and wireless/remote connections via enable_tcpip + connect

import json
import re
import subprocess
from typing import Optional

from mcp.server.fastmcp import FastMCP


def _run_adb(args: list[str], device_id: Optional[str] = None, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run an adb command, optionally targeting a specific device."""
    cmd = ["adb"]
    if device_id:
        cmd.extend(["-s", device_id])
    cmd.extend(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _get_first_device() -> Optional[str]:
    """Get the ID of the first connected device."""
    result = _run_adb(["devices"])
    lines = result.stdout.strip().split("\n")[1:]  # Skip header
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    return None


# Create the MCP server
mcp = FastMCP("adb")


@mcp.tool()
def list_devices() -> str:
    """
    List connected Android devices.

    Returns:
        JSON array of connected devices with IDs, status, and model info
    """
    try:
        result = _run_adb(["devices", "-l"])
    except FileNotFoundError:
        return json.dumps({"error": "adb not found - install Android SDK platform-tools"})

    devices = []
    lines = result.stdout.strip().split("\n")

    for line in lines[1:]:  # Skip header
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        device = {
            "id": parts[0],
            "status": parts[1],
        }

        # Parse optional properties
        for part in parts[2:]:
            if ":" in part:
                key, val = part.split(":", 1)
                device[key] = val

        devices.append(device)

    return json.dumps(devices, indent=2)


@mcp.tool()
def get_device_info(device_id: Optional[str] = None) -> str:
    """
    Get detailed information about an Android device.

    Args:
        device_id: Specific device ID (uses first device if not specified)

    Returns:
        JSON object with device properties (model, Android version, etc.)
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    props = [
        ("model", "ro.product.model"),
        ("manufacturer", "ro.product.manufacturer"),
        ("android_version", "ro.build.version.release"),
        ("sdk_version", "ro.build.version.sdk"),
        ("build_id", "ro.build.id"),
        ("device", "ro.product.device"),
        ("brand", "ro.product.brand"),
        ("fingerprint", "ro.build.fingerprint"),
    ]

    info = {"device_id": device_id}

    for name, prop in props:
        result = _run_adb(["shell", "getprop", prop], device_id=device_id)
        if result.returncode == 0:
            info[name] = result.stdout.strip()

    return json.dumps(info, indent=2)


@mcp.tool()
def get_network_info(device_id: Optional[str] = None) -> str:
    """
    Get network information from an Android device.

    Returns IP address, WiFi SSID, gateway, and other network details.

    Args:
        device_id: Specific device ID (uses first device if not specified)

    Returns:
        JSON object with network information
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    info = {"device_id": device_id}

    # Get IP address from wlan0
    result = _run_adb(["shell", "ip", "addr", "show", "wlan0"], device_id=device_id)
    if result.returncode == 0:
        # Parse inet line
        for line in result.stdout.split("\n"):
            if "inet " in line:
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
                if match:
                    info["ip_address"] = match.group(1)
                    ip_only = match.group(1).split("/")[0]
                    info["ip"] = ip_only

    # Get WiFi SSID
    result = _run_adb(["shell", "dumpsys", "wifi"], device_id=device_id)
    if result.returncode == 0:
        # Look for current SSID
        for line in result.stdout.split("\n"):
            if "mWifiInfo" in line and "SSID:" in line:
                match = re.search(r'SSID: "?([^",]+)"?', line)
                if match:
                    info["ssid"] = match.group(1).strip('"')
                break

    # Get default gateway
    result = _run_adb(["shell", "ip", "route"], device_id=device_id)
    if result.returncode == 0:
        for line in result.stdout.split("\n"):
            if "default via" in line:
                match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    info["gateway"] = match.group(1)
                break

    # Get DNS servers
    result = _run_adb(["shell", "getprop", "net.dns1"], device_id=device_id)
    if result.returncode == 0 and result.stdout.strip():
        info["dns1"] = result.stdout.strip()

    result = _run_adb(["shell", "getprop", "net.dns2"], device_id=device_id)
    if result.returncode == 0 and result.stdout.strip():
        info["dns2"] = result.stdout.strip()

    return json.dumps(info, indent=2)


@mcp.tool()
def shell(
    command: str,
    device_id: Optional[str] = None,
    timeout: int = 30,
) -> str:
    """
    Run a shell command on an Android device.

    Args:
        command: The shell command to run
        device_id: Specific device ID (uses first device if not specified)
        timeout: Command timeout in seconds (default 30)

    Returns:
        JSON object with stdout, stderr, and return code
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    try:
        result = _run_adb(["shell", command], device_id=device_id, timeout=timeout)
        return json.dumps({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Command timed out after {timeout}s"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def logcat(
    filter_spec: Optional[str] = None,
    device_id: Optional[str] = None,
    lines: int = 100,
    tag: Optional[str] = None,
) -> str:
    """
    Get logcat output from an Android device.

    Args:
        filter_spec: Logcat filter spec (e.g., "*:W" for warnings and above)
        device_id: Specific device ID (uses first device if not specified)
        lines: Number of lines to return (default 100)
        tag: Filter by specific tag

    Returns:
        Logcat output as text
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    cmd = ["logcat", "-d", "-t", str(lines)]

    if tag:
        cmd.extend(["-s", tag])
    elif filter_spec:
        cmd.append(filter_spec)

    result = _run_adb(cmd, device_id=device_id)
    return result.stdout


@mcp.tool()
def list_packages(
    device_id: Optional[str] = None,
    filter_text: Optional[str] = None,
    third_party_only: bool = False,
) -> str:
    """
    List installed packages on an Android device.

    Args:
        device_id: Specific device ID (uses first device if not specified)
        filter_text: Filter packages containing this text
        third_party_only: Only show third-party (non-system) apps

    Returns:
        JSON array of package names
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    cmd = ["shell", "pm", "list", "packages"]
    if third_party_only:
        cmd.append("-3")

    result = _run_adb(cmd, device_id=device_id)
    if result.returncode != 0:
        return json.dumps({"error": result.stderr})

    packages = []
    for line in result.stdout.strip().split("\n"):
        if line.startswith("package:"):
            pkg = line[8:]
            if filter_text is None or filter_text.lower() in pkg.lower():
                packages.append(pkg)

    return json.dumps(sorted(packages), indent=2)


@mcp.tool()
def connect(host: str, port: int = 5555) -> str:
    """
    Connect to an Android device over the network.

    First enable network ADB on the device while USB connected:
      adb tcpip 5555

    Then disconnect USB and use this tool to connect wirelessly.

    Args:
        host: IP address of the Android device
        port: ADB port (default 5555)

    Returns:
        JSON with connection status
    """
    target = f"{host}:{port}"
    result = _run_adb(["connect", target])

    if "connected" in result.stdout.lower():
        return json.dumps({
            "status": "connected",
            "device_id": target,
            "message": result.stdout.strip()
        })
    else:
        return json.dumps({
            "status": "failed",
            "message": result.stdout.strip() or result.stderr.strip()
        })


@mcp.tool()
def disconnect(host: Optional[str] = None, port: int = 5555, all_devices: bool = False) -> str:
    """
    Disconnect from a network-connected Android device.

    Args:
        host: IP address of the device (or None with all_devices=True)
        port: ADB port (default 5555)
        all_devices: Disconnect from all network devices

    Returns:
        JSON with disconnect status
    """
    if all_devices:
        result = _run_adb(["disconnect"])
    elif host:
        target = f"{host}:{port}"
        result = _run_adb(["disconnect", target])
    else:
        return json.dumps({"error": "Specify host or all_devices=True"})

    return json.dumps({
        "status": "disconnected",
        "message": result.stdout.strip() or "disconnected"
    })


@mcp.tool()
def enable_tcpip(port: int = 5555, device_id: Optional[str] = None) -> str:
    """
    Enable network ADB on a USB-connected device.

    After running this, you can disconnect USB and connect wirelessly.

    Args:
        port: Port for network ADB (default 5555)
        device_id: USB device ID (uses first device if not specified)

    Returns:
        JSON with status and next steps
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    # First get the device's IP address
    ip_result = _run_adb(["shell", "ip", "addr", "show", "wlan0"], device_id=device_id)
    device_ip = None
    if ip_result.returncode == 0:
        for line in ip_result.stdout.split("\n"):
            if "inet " in line:
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", line)
                if match:
                    device_ip = match.group(1)
                    break

    # Enable tcpip mode
    result = _run_adb(["tcpip", str(port)], device_id=device_id)

    if "restarting" in result.stdout.lower() or result.returncode == 0:
        response = {
            "status": "enabled",
            "port": port,
            "message": "Network ADB enabled. You can now disconnect USB.",
        }
        if device_ip:
            response["device_ip"] = device_ip
            response["connect_command"] = f"adb connect {device_ip}:{port}"
            response["next_step"] = f"Disconnect USB, then connect with: adb connect {device_ip}:{port}"
        return json.dumps(response, indent=2)
    else:
        return json.dumps({
            "status": "failed",
            "message": result.stdout.strip() or result.stderr.strip()
        })


@mcp.tool()
def forward(
    local_port: int,
    remote_port: int,
    device_id: Optional[str] = None,
    protocol: str = "tcp",
) -> str:
    """
    Set up port forwarding from local to device.

    Args:
        local_port: Local port number
        remote_port: Remote port on device
        device_id: Specific device ID (uses first device if not specified)
        protocol: Protocol (tcp or localabstract, default tcp)

    Returns:
        Status message
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    result = _run_adb(
        ["forward", f"tcp:{local_port}", f"{protocol}:{remote_port}"],
        device_id=device_id,
    )

    if result.returncode == 0:
        return json.dumps({
            "status": "success",
            "local": f"localhost:{local_port}",
            "remote": f"{protocol}:{remote_port}",
        })
    else:
        return json.dumps({"error": result.stderr})


@mcp.tool()
def list_forwards(device_id: Optional[str] = None) -> str:
    """
    List active port forwards.

    Args:
        device_id: Specific device ID (uses first device if not specified)

    Returns:
        JSON array of active forwards
    """
    result = _run_adb(["forward", "--list"], device_id=device_id)

    forwards = []
    for line in result.stdout.strip().split("\n"):
        if line:
            parts = line.split()
            if len(parts) >= 3:
                forwards.append({
                    "device": parts[0],
                    "local": parts[1],
                    "remote": parts[2],
                })

    return json.dumps(forwards, indent=2)


@mcp.tool()
def remove_forward(
    local_port: Optional[int] = None,
    device_id: Optional[str] = None,
    all_forwards: bool = False,
) -> str:
    """
    Remove port forwarding.

    Args:
        local_port: Local port to remove (or use all_forwards)
        device_id: Specific device ID (uses first device if not specified)
        all_forwards: Remove all forwards

    Returns:
        Status message
    """
    if not device_id:
        device_id = _get_first_device()
        if not device_id:
            return json.dumps({"error": "No device connected"})

    if all_forwards:
        result = _run_adb(["forward", "--remove-all"], device_id=device_id)
    elif local_port:
        result = _run_adb(["forward", "--remove", f"tcp:{local_port}"], device_id=device_id)
    else:
        return json.dumps({"error": "Specify local_port or all_forwards=True"})

    if result.returncode == 0:
        return json.dumps({"status": "removed"})
    else:
        return json.dumps({"error": result.stderr or "Failed to remove forward"})


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()

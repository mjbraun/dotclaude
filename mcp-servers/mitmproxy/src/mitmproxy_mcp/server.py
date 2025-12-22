# ABOUTME: MCP server for mitmproxy traffic interception
# ABOUTME: Exposes tools to start/stop proxy and query captured traffic

import asyncio
import json
import os
import signal
import sys
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from threading import Thread
from typing import AsyncIterator, Optional

from mcp.server.fastmcp import FastMCP

from .addon import TrafficCaptureAddon
from .url_utils import truncate_url, is_noise_domain
from .adb import (
    is_adb_available,
    list_devices as adb_list_devices,
    get_local_ip,
    enable_proxy as adb_enable_proxy,
    disable_proxy as adb_disable_proxy,
    get_current_proxy as adb_get_current_proxy,
)
from .certserver import CertServer
from .openapi import generate_openapi_spec
from .storage import TrafficStorage

# Global state for the proxy
_storage = TrafficStorage(max_size=5000)
_proxy_thread: Optional[Thread] = None
_proxy_master = None
_proxy_loop: Optional[asyncio.AbstractEventLoop] = None
_cert_server: Optional[CertServer] = None


def _get_mitmproxy_ca_cert_path() -> Path:
    """Get the path to mitmproxy's CA certificate."""
    return Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


def _run_proxy_in_thread(
    listen_host: str,
    listen_port: int,
    domain_filter: Optional[str],
):
    """Run mitmproxy in a background thread."""
    global _proxy_master, _proxy_loop

    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _proxy_loop = loop

    opts = options.Options(
        listen_host=listen_host,
        listen_port=listen_port,
    )

    master = DumpMaster(opts, loop=loop, with_termlog=False)
    _proxy_master = master

    addon = TrafficCaptureAddon(_storage, domain_filter=domain_filter)
    master.addons.add(addon)

    try:
        loop.run_until_complete(master.run())
    except Exception:
        pass
    finally:
        _proxy_loop = None
        _proxy_master = None


# Create the MCP server
mcp = FastMCP("mitmproxy")


@mcp.tool()
def start_proxy(
    port: int = 8080,
    host: str = "0.0.0.0",
    domain_filter: Optional[str] = None,
) -> str:
    """
    Start the mitmproxy interception proxy.

    Args:
        port: Port to listen on (default 8080)
        host: Host to bind to (default 0.0.0.0)
        domain_filter: Only capture traffic matching this domain substring

    Returns:
        Status message indicating success or failure
    """
    global _proxy_thread

    if _proxy_thread is not None and _proxy_thread.is_alive():
        return f"Proxy is already running on port {port}"

    _storage.clear()

    _proxy_thread = Thread(
        target=_run_proxy_in_thread,
        args=(host, port, domain_filter),
        daemon=True,
    )
    _proxy_thread.start()

    # Give it a moment to start
    import time
    time.sleep(1)

    if _proxy_thread.is_alive():
        msg = f"Proxy started on {host}:{port}"
        if domain_filter:
            msg += f" (filtering for '{domain_filter}')"
        return msg
    else:
        return "Failed to start proxy - check if port is already in use"


@mcp.tool()
def stop_proxy() -> str:
    """
    Stop the running mitmproxy proxy.

    Returns:
        Status message
    """
    global _proxy_thread, _proxy_master, _proxy_loop

    if _proxy_thread is None or not _proxy_thread.is_alive():
        return "Proxy is not running"

    if _proxy_master and _proxy_loop:
        # Schedule shutdown on the proxy's event loop
        _proxy_loop.call_soon_threadsafe(_proxy_master.shutdown)

    # Wait for thread to finish
    _proxy_thread.join(timeout=5)

    if _proxy_thread.is_alive():
        return "Proxy is taking too long to stop - it may still be shutting down"

    _proxy_thread = None
    return "Proxy stopped"


@mcp.tool()
def get_proxy_status() -> str:
    """
    Get the current status of the proxy.

    Returns:
        JSON string with status information
    """
    global _proxy_thread

    is_running = _proxy_thread is not None and _proxy_thread.is_alive()
    request_count = len(_storage)

    return json.dumps({
        "running": is_running,
        "captured_requests": request_count,
    })


@mcp.tool()
def get_ca_cert() -> str:
    """
    Get the mitmproxy CA certificate for installing on devices.

    The certificate needs to be installed as a trusted CA on devices
    that will have their HTTPS traffic intercepted.

    For Android with Magisk, use the 'MagiskTrustUserCerts' module
    or install directly to system trust store.

    Returns:
        The CA certificate in PEM format, or an error message
    """
    cert_path = _get_mitmproxy_ca_cert_path()

    if not cert_path.exists():
        # Generate cert by doing a quick proxy start/stop
        return json.dumps({
            "error": "CA certificate not found. Start the proxy once to generate it.",
            "expected_path": str(cert_path),
        })

    cert_content = cert_path.read_text()
    return json.dumps({
        "path": str(cert_path),
        "content": cert_content,
        "instructions": (
            "Install this certificate on your device:\n"
            "1. Copy the cert to your device\n"
            "2. For Android: Settings > Security > Install from storage\n"
            "3. For Android + Magisk: Use MagiskTrustUserCerts module to move to system store\n"
            "4. For iOS: Install profile, then trust in Settings > General > About > Certificate Trust Settings"
        ),
    })


@mcp.tool()
def list_requests(
    limit: int = 20,
    domain_filter: Optional[str] = None,
    exclude_noise: bool = True,
    verbose: bool = False,
) -> str:
    """
    List captured HTTP requests.

    Args:
        limit: Maximum number of requests to return (default 20)
        domain_filter: Only show requests matching this domain substring
        exclude_noise: Filter out Google/gstatic/telemetry traffic (default True)
        verbose: Show full URLs instead of compact host+path (default False)

    Returns:
        JSON array of captured requests (compact by default, verbose if requested)
    """
    from urllib.parse import urlparse

    requests = _storage.list(limit=limit * 2 if exclude_noise else limit, domain_filter=domain_filter)

    # Filter noise if requested
    if exclude_noise:
        requests = [r for r in requests if not is_noise_domain(r.url)][:limit]

    summaries = []
    for r in requests:
        parsed = urlparse(r.url)
        req_size = len(r.request_body) if r.request_body else 0
        resp_size = len(r.response_body) if r.response_body else 0

        if verbose:
            summaries.append({
                "id": r.id,
                "method": r.method,
                "url": truncate_url(r.url),
                "status": r.response_status,
                "req_size": req_size,
                "resp_size": resp_size,
            })
        else:
            # Compact format: just essentials
            summaries.append({
                "id": r.id,
                "method": r.method,
                "host": parsed.netloc,
                "endpoint": truncate_url(r.url, max_query_length=16).replace(f"{parsed.scheme}://{parsed.netloc}", ""),
                "status": r.response_status,
                "req": req_size,
                "resp": resp_size,
            })

    return json.dumps(summaries, indent=2)


@mcp.tool()
def get_request(request_id: str) -> str:
    """
    Get full details of a specific captured request.

    Args:
        request_id: The ID of the request to retrieve

    Returns:
        JSON object with full request/response details
    """
    req = _storage.get(request_id)

    if req is None:
        return json.dumps({"error": f"Request {request_id} not found"})

    return json.dumps(asdict(req), indent=2)


@mcp.tool()
def search_traffic(query: str, limit: int = 50) -> str:
    """
    Search captured traffic for a string.

    Searches in URLs, request bodies, and response bodies.

    Args:
        query: String to search for
        limit: Maximum results to return

    Returns:
        JSON array of matching requests (summary view)
    """
    results = _storage.search(query)[:limit]

    summaries = [
        {
            "id": r.id,
            "method": r.method,
            "url": r.url,
            "status": r.response_status,
            "timestamp": r.timestamp,
        }
        for r in results
    ]

    return json.dumps(summaries, indent=2)


@mcp.tool()
def clear_traffic() -> str:
    """
    Clear all captured traffic.

    Returns:
        Confirmation message
    """
    count = len(_storage)
    _storage.clear()
    return f"Cleared {count} captured requests"


@mcp.tool()
def generate_openapi(
    domain_filter: Optional[str] = None,
    title: str = "Captured API",
) -> str:
    """
    Generate an OpenAPI 3.0 spec from captured traffic.

    Analyzes all captured requests and responses to infer:
    - API endpoints with path parameters detected
    - Request body schemas (for POST/PUT/PATCH)
    - Response schemas for each status code
    - Query parameters

    Args:
        domain_filter: Only include requests matching this domain
        title: Title for the generated API spec

    Returns:
        OpenAPI 3.0 specification as JSON
    """
    request_count = len(_storage)
    if request_count == 0:
        return json.dumps({
            "error": "No captured traffic to analyze",
            "hint": "Start the proxy and capture some traffic first"
        })

    spec = generate_openapi_spec(
        _storage,
        domain_filter=domain_filter,
        title=title,
    )

    return json.dumps(spec, indent=2)


@mcp.tool()
def start_cert_server(port: int = 8081) -> str:
    """
    Start a web server to serve the CA certificate for easy download.

    Browse to http://<your-ip>:<port>/ on your device to download
    and install the certificate.

    Args:
        port: Port to serve on (default 8081)

    Returns:
        Status message with URL to access
    """
    global _cert_server

    if _cert_server is not None and _cert_server.is_running:
        return f"Certificate server is already running on port {port}"

    _cert_server = CertServer(port=port)
    _cert_server.start()

    import socket
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = "your-ip"

    return json.dumps({
        "status": "running",
        "port": port,
        "urls": [
            f"http://localhost:{port}/",
            f"http://{local_ip}:{port}/",
        ],
        "instructions": "Open one of the URLs on your device to download the certificate",
    })


@mcp.tool()
def stop_cert_server() -> str:
    """
    Stop the certificate web server.

    Returns:
        Status message
    """
    global _cert_server

    if _cert_server is None or not _cert_server.is_running:
        return "Certificate server is not running"

    _cert_server.stop()
    _cert_server = None
    return "Certificate server stopped"


@mcp.tool()
def list_android_devices() -> str:
    """
    List connected Android devices.

    Returns:
        JSON array of connected devices with their IDs and models
    """
    if not is_adb_available():
        return json.dumps({
            "error": "adb not found",
            "hint": "Install Android SDK platform-tools and ensure adb is in PATH",
        })

    try:
        devices = adb_list_devices()
        return json.dumps([
            {
                "id": d.id,
                "status": d.status,
                "model": d.model,
                "product": d.product,
            }
            for d in devices
        ], indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def enable_device_proxy(
    device_id: Optional[str] = None,
    proxy_host: Optional[str] = None,
    proxy_port: int = 8080,
) -> str:
    """
    Enable global HTTP proxy on an Android device.

    Configures the device to route all HTTP/HTTPS traffic through the proxy.
    This is necessary for mitmproxy to intercept traffic.

    Args:
        device_id: Specific device ID (optional, uses first USB device if not specified)
        proxy_host: Proxy server IP address (optional, auto-detects local IP if not specified)
        proxy_port: Proxy server port (default 8080)

    Returns:
        Status message with the proxy configuration applied
    """
    if not is_adb_available():
        return json.dumps({
            "error": "adb not found",
            "hint": "Install Android SDK platform-tools and ensure adb is in PATH",
        })

    # Auto-detect host IP if not provided
    if proxy_host is None:
        proxy_host = get_local_ip()

    try:
        success = adb_enable_proxy(proxy_host, proxy_port, device_id=device_id)
        if success:
            return json.dumps({
                "status": "enabled",
                "proxy": f"{proxy_host}:{proxy_port}",
                "device_id": device_id or "default USB device",
                "warning": "Remember to disable proxy before disconnecting the device!",
            })
        else:
            return json.dumps({
                "error": "Failed to enable proxy",
                "hint": "Check if device is connected and authorized",
            })
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def disable_device_proxy(device_id: Optional[str] = None) -> str:
    """
    Disable global HTTP proxy on an Android device.

    Removes the proxy configuration, restoring direct network access.
    IMPORTANT: Always call this before disconnecting the device!

    Args:
        device_id: Specific device ID (optional, uses first USB device if not specified)

    Returns:
        Status message
    """
    if not is_adb_available():
        return json.dumps({
            "error": "adb not found",
            "hint": "Install Android SDK platform-tools and ensure adb is in PATH",
        })

    try:
        success = adb_disable_proxy(device_id=device_id)
        if success:
            return json.dumps({
                "status": "disabled",
                "device_id": device_id or "default USB device",
            })
        else:
            return json.dumps({
                "error": "Failed to disable proxy",
                "hint": "Check if device is connected and authorized",
            })
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def get_device_proxy_status(device_id: Optional[str] = None) -> str:
    """
    Get the current proxy configuration from an Android device.

    Args:
        device_id: Specific device ID (optional, uses first USB device if not specified)

    Returns:
        Current proxy setting or indication that no proxy is configured
    """
    if not is_adb_available():
        return json.dumps({
            "error": "adb not found",
            "hint": "Install Android SDK platform-tools and ensure adb is in PATH",
        })

    try:
        proxy = adb_get_current_proxy(device_id=device_id)
        if proxy:
            return json.dumps({
                "proxy_enabled": True,
                "proxy": proxy,
                "device_id": device_id or "default USB device",
            })
        else:
            return json.dumps({
                "proxy_enabled": False,
                "device_id": device_id or "default USB device",
            })
    except Exception as e:
        return json.dumps({"error": str(e)})


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()

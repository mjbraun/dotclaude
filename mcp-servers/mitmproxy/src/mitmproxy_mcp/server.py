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
    limit: int = 50,
    domain_filter: Optional[str] = None,
) -> str:
    """
    List captured HTTP requests.

    Args:
        limit: Maximum number of requests to return (default 50)
        domain_filter: Only show requests matching this domain substring

    Returns:
        JSON array of captured requests (summary view)
    """
    requests = _storage.list(limit=limit, domain_filter=domain_filter)

    summaries = [
        {
            "id": r.id,
            "method": r.method,
            "url": r.url,
            "status": r.response_status,
            "timestamp": r.timestamp,
        }
        for r in requests
    ]

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


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()

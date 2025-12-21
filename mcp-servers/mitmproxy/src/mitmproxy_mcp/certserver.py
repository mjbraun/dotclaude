# ABOUTME: HTTP server for serving mitmproxy CA certificate
# ABOUTME: Provides easy cert download via web browser for device installation

import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from threading import Thread
from typing import Optional


_INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>mitmproxy CA Certificate</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
        }}
        h1 {{ color: #333; }}
        .download-btn {{
            display: inline-block;
            background: #007bff;
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 5px;
            font-size: 18px;
            margin: 20px 0;
        }}
        .download-btn:hover {{ background: #0056b3; }}
        .instructions {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>mitmproxy CA Certificate</h1>
    <p>Download and install this certificate to intercept HTTPS traffic.</p>

    <a href="/cert" class="download-btn">Download Certificate</a>

    <div class="instructions">
        <h3>Installation Instructions</h3>
        <h4>Android</h4>
        <ol>
            <li>Download the certificate</li>
            <li>Go to <strong>Settings → Security → Install from storage</strong></li>
            <li>Select the downloaded certificate</li>
            <li>Name it "mitmproxy" and select "VPN and apps" for credential use</li>
        </ol>
        <p><strong>For system-level trust (Android 7+):</strong> Use the <code>MagiskTrustUserCerts</code> module to move user certificates to the system store.</p>

        <h4>iOS</h4>
        <ol>
            <li>Download the certificate</li>
            <li>Go to <strong>Settings → General → Profile</strong> and install</li>
            <li>Go to <strong>Settings → General → About → Certificate Trust Settings</strong></li>
            <li>Enable full trust for the mitmproxy certificate</li>
        </ol>
    </div>
</body>
</html>
"""


class CertRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for serving the CA certificate."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._serve_index()
        elif self.path == "/cert" or self.path == "/mitmproxy-ca-cert.pem":
            self._serve_cert()
        else:
            self.send_error(404, "Not Found")

    def _serve_index(self):
        content = _INDEX_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)

    def _serve_cert(self):
        cert_path: Path = self.server.cert_path

        if not cert_path.exists():
            self.send_error(404, "Certificate not found. Start the proxy first to generate it.")
            return

        content = cert_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Disposition", "attachment; filename=mitmproxy-ca-cert.pem")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)


class CertServer:
    """HTTP server for serving the mitmproxy CA certificate."""

    def __init__(
        self,
        port: int = 8081,
        host: str = "0.0.0.0",
        cert_path: Optional[Path] = None,
    ):
        self.port = port
        self.host = host
        self.cert_path = cert_path or (Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem")
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[Thread] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        """Start the certificate server."""
        if self.is_running:
            return

        self._server = HTTPServer((self.host, self.port), CertRequestHandler)
        self._server.cert_path = self.cert_path

        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the certificate server."""
        if self._server:
            self._server.shutdown()
            self._server = None

        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

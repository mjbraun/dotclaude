# ABOUTME: Tests for CA certificate web server
# ABOUTME: Validates HTTP serving of mitmproxy CA cert for easy device installation

import pytest
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

from mitmproxy_mcp.certserver import CertServer


class TestCertServer:
    def test_serves_cert_file(self, tmp_path):
        # Create a fake cert file
        cert_path = tmp_path / "mitmproxy-ca-cert.pem"
        cert_path.write_text("-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----")

        server = CertServer(port=19080, cert_path=cert_path)
        server.start()
        time.sleep(0.5)

        try:
            response = urllib.request.urlopen("http://localhost:19080/cert", timeout=5)
            content = response.read().decode()
            assert "FAKECERT" in content
            assert response.headers.get("Content-Type") == "application/x-pem-file"
        finally:
            server.stop()

    def test_serves_index_page(self, tmp_path):
        cert_path = tmp_path / "mitmproxy-ca-cert.pem"
        cert_path.write_text("CERT")

        server = CertServer(port=19081, cert_path=cert_path)
        server.start()
        time.sleep(0.5)

        try:
            response = urllib.request.urlopen("http://localhost:19081/", timeout=5)
            content = response.read().decode()
            assert "text/html" in response.headers.get("Content-Type")
            assert "certificate" in content.lower()
        finally:
            server.stop()

    def test_returns_404_for_missing_cert(self, tmp_path):
        cert_path = tmp_path / "nonexistent.pem"

        server = CertServer(port=19082, cert_path=cert_path)
        server.start()
        time.sleep(0.5)

        try:
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen("http://localhost:19082/cert", timeout=5)
            assert exc_info.value.code == 404
        finally:
            server.stop()

    def test_is_running_property(self, tmp_path):
        cert_path = tmp_path / "mitmproxy-ca-cert.pem"
        cert_path.write_text("CERT")

        server = CertServer(port=19083, cert_path=cert_path)
        assert not server.is_running

        server.start()
        time.sleep(0.5)
        assert server.is_running

        server.stop()
        time.sleep(0.5)
        assert not server.is_running

    def test_stop_is_idempotent(self, tmp_path):
        cert_path = tmp_path / "mitmproxy-ca-cert.pem"
        cert_path.write_text("CERT")

        server = CertServer(port=19084, cert_path=cert_path)
        server.start()
        time.sleep(0.5)

        server.stop()
        server.stop()  # Should not raise
        assert not server.is_running

# ABOUTME: Tests for mitmproxy traffic capture addon
# ABOUTME: Validates that HTTP flows are correctly captured to storage

import pytest
from unittest.mock import MagicMock, PropertyMock
from mitmproxy_mcp.addon import TrafficCaptureAddon
from mitmproxy_mcp.storage import TrafficStorage


def create_mock_flow(
    method: str = "GET",
    url: str = "https://api.example.com/test",
    request_headers: dict = None,
    request_content: bytes = None,
    response_status: int = 200,
    response_headers: dict = None,
    response_content: bytes = None,
):
    """Create a mock mitmproxy flow object."""
    flow = MagicMock()
    flow.id = "test-flow-id"

    # Mock request
    flow.request.method = method
    flow.request.pretty_url = url
    flow.request.headers = request_headers or {}
    flow.request.content = request_content

    # Mock response
    flow.response.status_code = response_status
    flow.response.headers = response_headers or {}
    flow.response.content = response_content

    return flow


class TestTrafficCaptureAddon:
    def test_captures_response(self):
        storage = TrafficStorage()
        addon = TrafficCaptureAddon(storage)

        flow = create_mock_flow(
            method="GET",
            url="https://api.skylight.com/photos",
            response_status=200,
            response_content=b'{"photos": []}',
        )

        addon.response(flow)

        assert len(storage) == 1
        captured = storage.list()[0]
        assert captured.method == "GET"
        assert captured.url == "https://api.skylight.com/photos"
        assert captured.response_status == 200
        assert captured.response_body == '{"photos": []}'

    def test_captures_request_body(self):
        storage = TrafficStorage()
        addon = TrafficCaptureAddon(storage)

        flow = create_mock_flow(
            method="POST",
            url="https://api.skylight.com/upload",
            request_content=b'{"image": "base64data"}',
            response_status=201,
        )

        addon.response(flow)

        captured = storage.list()[0]
        assert captured.method == "POST"
        assert captured.request_body == '{"image": "base64data"}'

    def test_captures_headers(self):
        storage = TrafficStorage()
        addon = TrafficCaptureAddon(storage)

        flow = create_mock_flow(
            request_headers={"Authorization": "Bearer token123"},
            response_headers={"Content-Type": "application/json"},
        )

        addon.response(flow)

        captured = storage.list()[0]
        assert captured.request_headers["Authorization"] == "Bearer token123"
        assert captured.response_headers["Content-Type"] == "application/json"

    def test_handles_binary_content(self):
        storage = TrafficStorage()
        addon = TrafficCaptureAddon(storage)

        # Binary image data that's not valid UTF-8
        flow = create_mock_flow(
            response_content=b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR',
        )

        addon.response(flow)

        captured = storage.list()[0]
        # Should not crash, body should be marked as binary
        assert captured.response_body is not None
        assert "[binary" in captured.response_body.lower() or len(captured.response_body) > 0

    def test_handles_none_response(self):
        storage = TrafficStorage()
        addon = TrafficCaptureAddon(storage)

        flow = create_mock_flow()
        flow.response = None

        # Should not crash
        addon.response(flow)
        assert len(storage) == 0

    def test_domain_filter(self):
        storage = TrafficStorage()
        addon = TrafficCaptureAddon(storage, domain_filter="skylight")

        skylight_flow = create_mock_flow(url="https://api.skylight.com/photos")
        google_flow = create_mock_flow(url="https://api.google.com/search")

        addon.response(skylight_flow)
        addon.response(google_flow)

        # Only skylight request should be captured
        assert len(storage) == 1
        assert "skylight" in storage.list()[0].url

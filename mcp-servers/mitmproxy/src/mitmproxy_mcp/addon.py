# ABOUTME: Mitmproxy addon that captures HTTP traffic to storage
# ABOUTME: Hooks into request/response flow to record all traffic

import time
import uuid
from typing import Optional
from urllib.parse import urlparse

from mitmproxy import http

from .storage import TrafficStorage, CapturedRequest


class TrafficCaptureAddon:
    """Mitmproxy addon that captures HTTP traffic."""

    def __init__(
        self,
        storage: TrafficStorage,
        domain_filter: Optional[str] = None,
    ):
        self.storage = storage
        self.domain_filter = domain_filter.lower() if domain_filter else None

    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a response is received."""
        if flow.response is None:
            return

        # Apply domain filter
        if self.domain_filter:
            host = urlparse(flow.request.pretty_url).netloc.lower()
            if self.domain_filter not in host:
                return

        # Extract request data
        request_body = self._decode_content(flow.request.content)
        request_headers = dict(flow.request.headers)

        # Extract response data
        response_body = self._decode_content(flow.response.content)
        response_headers = dict(flow.response.headers)

        captured = CapturedRequest(
            id=flow.id if hasattr(flow, 'id') and flow.id else str(uuid.uuid4()),
            method=flow.request.method,
            url=flow.request.pretty_url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=flow.response.status_code,
            response_headers=response_headers,
            response_body=response_body,
            timestamp=time.time(),
        )

        self.storage.add(captured)

    def _decode_content(self, content: Optional[bytes]) -> Optional[str]:
        """Decode content bytes to string, handling binary data."""
        if content is None:
            return None

        try:
            return content.decode('utf-8')
        except UnicodeDecodeError:
            # Binary content - return a placeholder with size info
            return f"[binary data: {len(content)} bytes]"

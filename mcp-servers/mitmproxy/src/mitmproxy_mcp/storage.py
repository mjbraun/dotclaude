# ABOUTME: Storage for captured HTTP traffic with filtering and search
# ABOUTME: Thread-safe container for request/response data from mitmproxy

from dataclasses import dataclass
from threading import Lock
from typing import Optional
from urllib.parse import urlparse


@dataclass
class CapturedRequest:
    """A captured HTTP request/response pair."""
    id: str
    method: str
    url: str
    request_headers: dict
    request_body: Optional[str]
    response_status: int
    response_headers: dict
    response_body: Optional[str]
    timestamp: float


class TrafficStorage:
    """Thread-safe storage for captured HTTP traffic."""

    def __init__(self, max_size: int = 1000):
        self._requests: dict[str, CapturedRequest] = {}
        self._order: list[str] = []  # IDs in insertion order
        self._max_size = max_size
        self._lock = Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._requests)

    def add(self, request: CapturedRequest) -> None:
        """Add a captured request to storage."""
        with self._lock:
            self._requests[request.id] = request
            self._order.append(request.id)
            self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        """Remove oldest requests if over max size. Must hold lock."""
        while len(self._requests) > self._max_size:
            oldest_id = self._order.pop(0)
            del self._requests[oldest_id]

    def get(self, request_id: str) -> Optional[CapturedRequest]:
        """Get a request by ID."""
        with self._lock:
            return self._requests.get(request_id)

    def list(
        self,
        limit: Optional[int] = None,
        domain_filter: Optional[str] = None,
    ) -> list[CapturedRequest]:
        """List requests, newest first, with optional filtering."""
        with self._lock:
            # Get all requests sorted by timestamp descending
            requests = sorted(
                self._requests.values(),
                key=lambda r: r.timestamp,
                reverse=True,
            )

            # Apply domain filter
            if domain_filter:
                requests = [
                    r for r in requests
                    if domain_filter.lower() in urlparse(r.url).netloc.lower()
                ]

            # Apply limit
            if limit is not None:
                requests = requests[:limit]

            return requests

    def search(self, query: str) -> list[CapturedRequest]:
        """Search requests by URL, headers, or body content."""
        query_lower = query.lower()
        with self._lock:
            results = []
            for req in self._requests.values():
                # Search in URL
                if query_lower in req.url.lower():
                    results.append(req)
                    continue

                # Search in request body
                if req.request_body and query_lower in req.request_body.lower():
                    results.append(req)
                    continue

                # Search in response body
                if req.response_body and query_lower in req.response_body.lower():
                    results.append(req)
                    continue

            # Sort by timestamp descending
            return sorted(results, key=lambda r: r.timestamp, reverse=True)

    def clear(self) -> None:
        """Clear all stored requests."""
        with self._lock:
            self._requests.clear()
            self._order.clear()

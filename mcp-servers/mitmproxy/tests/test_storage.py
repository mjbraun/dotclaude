# ABOUTME: Tests for HTTP traffic storage
# ABOUTME: Validates request/response capture and querying

import pytest
from mitmproxy_mcp.storage import TrafficStorage, CapturedRequest


class TestTrafficStorage:
    def test_add_request(self):
        storage = TrafficStorage()
        req = CapturedRequest(
            id="req-1",
            method="GET",
            url="https://api.example.com/photos",
            request_headers={"Authorization": "Bearer token"},
            request_body=None,
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"photos": []}',
            timestamp=1234567890.0,
        )
        storage.add(req)
        assert len(storage) == 1

    def test_get_request_by_id(self):
        storage = TrafficStorage()
        req = CapturedRequest(
            id="req-1",
            method="GET",
            url="https://api.example.com/photos",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=None,
            timestamp=1234567890.0,
        )
        storage.add(req)

        retrieved = storage.get("req-1")
        assert retrieved is not None
        assert retrieved.url == "https://api.example.com/photos"

    def test_get_nonexistent_request(self):
        storage = TrafficStorage()
        assert storage.get("nonexistent") is None

    def test_list_requests(self):
        storage = TrafficStorage()
        for i in range(5):
            storage.add(CapturedRequest(
                id=f"req-{i}",
                method="GET",
                url=f"https://api.example.com/item/{i}",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body=None,
                timestamp=1234567890.0 + i,
            ))

        requests = storage.list()
        assert len(requests) == 5

    def test_list_requests_with_limit(self):
        storage = TrafficStorage()
        for i in range(10):
            storage.add(CapturedRequest(
                id=f"req-{i}",
                method="GET",
                url=f"https://api.example.com/item/{i}",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body=None,
                timestamp=1234567890.0 + i,
            ))

        requests = storage.list(limit=3)
        assert len(requests) == 3

    def test_list_requests_newest_first(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="old",
            method="GET",
            url="https://api.example.com/old",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=None,
            timestamp=1000.0,
        ))
        storage.add(CapturedRequest(
            id="new",
            method="GET",
            url="https://api.example.com/new",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=None,
            timestamp=2000.0,
        ))

        requests = storage.list()
        assert requests[0].id == "new"
        assert requests[1].id == "old"

    def test_filter_by_domain(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="skylight",
            method="GET",
            url="https://api.skylight.com/photos",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=None,
            timestamp=1000.0,
        ))
        storage.add(CapturedRequest(
            id="other",
            method="GET",
            url="https://api.google.com/something",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=None,
            timestamp=2000.0,
        ))

        requests = storage.list(domain_filter="skylight")
        assert len(requests) == 1
        assert requests[0].id == "skylight"

    def test_search_in_url(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="photos",
            method="GET",
            url="https://api.example.com/photos/list",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=None,
            timestamp=1000.0,
        ))
        storage.add(CapturedRequest(
            id="users",
            method="GET",
            url="https://api.example.com/users/list",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body=None,
            timestamp=2000.0,
        ))

        results = storage.search("photos")
        assert len(results) == 1
        assert results[0].id == "photos"

    def test_search_in_response_body(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="with-gallery",
            method="GET",
            url="https://api.example.com/data",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body='{"gallery": ["photo1.jpg", "photo2.jpg"]}',
            timestamp=1000.0,
        ))
        storage.add(CapturedRequest(
            id="without-gallery",
            method="GET",
            url="https://api.example.com/other",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body='{"users": []}',
            timestamp=2000.0,
        ))

        results = storage.search("gallery")
        assert len(results) == 1
        assert results[0].id == "with-gallery"

    def test_clear(self):
        storage = TrafficStorage()
        for i in range(5):
            storage.add(CapturedRequest(
                id=f"req-{i}",
                method="GET",
                url=f"https://api.example.com/item/{i}",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body=None,
                timestamp=1234567890.0 + i,
            ))

        assert len(storage) == 5
        storage.clear()
        assert len(storage) == 0

    def test_max_size_eviction(self):
        storage = TrafficStorage(max_size=3)
        for i in range(5):
            storage.add(CapturedRequest(
                id=f"req-{i}",
                method="GET",
                url=f"https://api.example.com/item/{i}",
                request_headers={},
                request_body=None,
                response_status=200,
                response_headers={},
                response_body=None,
                timestamp=1234567890.0 + i,
            ))

        assert len(storage) == 3
        # Should have kept the 3 newest
        assert storage.get("req-0") is None
        assert storage.get("req-1") is None
        assert storage.get("req-2") is not None

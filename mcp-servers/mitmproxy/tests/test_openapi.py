# ABOUTME: Tests for OpenAPI spec generation from captured traffic
# ABOUTME: Validates schema inference, path detection, and spec output

import json
import pytest
from mitmproxy_mcp.openapi import (
    infer_json_schema,
    detect_path_parameters,
    group_endpoints,
    generate_openapi_spec,
)
from mitmproxy_mcp.storage import TrafficStorage, CapturedRequest


class TestInferJsonSchema:
    def test_infer_string(self):
        schema = infer_json_schema("hello")
        assert schema == {"type": "string"}

    def test_infer_integer(self):
        schema = infer_json_schema(42)
        assert schema == {"type": "integer"}

    def test_infer_number(self):
        schema = infer_json_schema(3.14)
        assert schema == {"type": "number"}

    def test_infer_boolean(self):
        schema = infer_json_schema(True)
        assert schema == {"type": "boolean"}

    def test_infer_null(self):
        schema = infer_json_schema(None)
        assert schema == {"type": "null"}

    def test_infer_array_of_strings(self):
        schema = infer_json_schema(["a", "b", "c"])
        assert schema == {"type": "array", "items": {"type": "string"}}

    def test_infer_array_of_objects(self):
        schema = infer_json_schema([{"id": 1}, {"id": 2}])
        assert schema["type"] == "array"
        assert schema["items"]["type"] == "object"
        assert "id" in schema["items"]["properties"]

    def test_infer_empty_array(self):
        schema = infer_json_schema([])
        assert schema == {"type": "array", "items": {}}

    def test_infer_object(self):
        schema = infer_json_schema({"name": "test", "count": 5})
        assert schema["type"] == "object"
        assert schema["properties"]["name"] == {"type": "string"}
        assert schema["properties"]["count"] == {"type": "integer"}

    def test_infer_nested_object(self):
        schema = infer_json_schema({
            "user": {
                "id": 123,
                "name": "Alice"
            }
        })
        assert schema["type"] == "object"
        assert schema["properties"]["user"]["type"] == "object"
        assert schema["properties"]["user"]["properties"]["id"] == {"type": "integer"}

    def test_merge_schemas(self):
        # When we see multiple examples, schemas should be merged
        from mitmproxy_mcp.openapi import merge_schemas

        schema1 = {"type": "object", "properties": {"a": {"type": "string"}}}
        schema2 = {"type": "object", "properties": {"b": {"type": "integer"}}}

        merged = merge_schemas(schema1, schema2)
        assert "a" in merged["properties"]
        assert "b" in merged["properties"]


class TestDetectPathParameters:
    def test_detect_uuid(self):
        result = detect_path_parameters("/api/photos/550e8400-e29b-41d4-a716-446655440000")
        assert result == "/api/photos/{id}"

    def test_detect_numeric_id(self):
        result = detect_path_parameters("/api/users/12345")
        assert result == "/api/users/{id}"

    def test_detect_multiple_params(self):
        result = detect_path_parameters("/api/users/123/photos/456")
        assert result == "/api/users/{id}/photos/{id}"

    def test_preserve_known_segments(self):
        result = detect_path_parameters("/api/v1/photos")
        assert result == "/api/v1/photos"

    def test_detect_hex_id(self):
        result = detect_path_parameters("/api/items/a1b2c3d4e5")
        assert result == "/api/items/{id}"

    def test_short_segment_not_param(self):
        # Short segments like "v1", "api" should not be treated as params
        result = detect_path_parameters("/api/v1/users")
        assert result == "/api/v1/users"


class TestGroupEndpoints:
    def test_group_same_endpoint(self):
        requests = [
            CapturedRequest(
                id="1", method="GET", url="https://api.example.com/photos/123",
                request_headers={}, request_body=None,
                response_status=200, response_headers={"Content-Type": "application/json"},
                response_body='{"id": 123}', timestamp=1000.0
            ),
            CapturedRequest(
                id="2", method="GET", url="https://api.example.com/photos/456",
                request_headers={}, request_body=None,
                response_status=200, response_headers={"Content-Type": "application/json"},
                response_body='{"id": 456}', timestamp=1001.0
            ),
        ]

        groups = group_endpoints(requests)

        # Should be grouped as one endpoint
        assert len(groups) == 1
        key = ("GET", "/photos/{id}")
        assert key in groups
        assert len(groups[key]) == 2

    def test_group_different_methods(self):
        requests = [
            CapturedRequest(
                id="1", method="GET", url="https://api.example.com/photos",
                request_headers={}, request_body=None,
                response_status=200, response_headers={},
                response_body='[]', timestamp=1000.0
            ),
            CapturedRequest(
                id="2", method="POST", url="https://api.example.com/photos",
                request_headers={}, request_body='{"name": "test"}',
                response_status=201, response_headers={},
                response_body='{"id": 1}', timestamp=1001.0
            ),
        ]

        groups = group_endpoints(requests)

        assert len(groups) == 2
        assert ("GET", "/photos") in groups
        assert ("POST", "/photos") in groups


class TestGenerateOpenAPISpec:
    def test_basic_spec_structure(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="1", method="GET", url="https://api.example.com/photos",
            request_headers={}, request_body=None,
            response_status=200, response_headers={"Content-Type": "application/json"},
            response_body='[{"id": 1, "name": "photo1"}]', timestamp=1000.0
        ))

        spec = generate_openapi_spec(storage)

        assert spec["openapi"] == "3.0.0"
        assert "info" in spec
        assert "paths" in spec
        assert "/photos" in spec["paths"]
        assert "get" in spec["paths"]["/photos"]

    def test_includes_response_schema(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="1", method="GET", url="https://api.example.com/users/123",
            request_headers={}, request_body=None,
            response_status=200, response_headers={"Content-Type": "application/json"},
            response_body='{"id": 123, "name": "Alice", "email": "alice@example.com"}',
            timestamp=1000.0
        ))

        spec = generate_openapi_spec(storage)

        path = spec["paths"]["/users/{id}"]
        response = path["get"]["responses"]["200"]
        assert "content" in response
        schema = response["content"]["application/json"]["schema"]
        assert schema["type"] == "object"
        assert "id" in schema["properties"]
        assert "name" in schema["properties"]

    def test_includes_request_body_schema(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="1", method="POST", url="https://api.example.com/photos",
            request_headers={"Content-Type": "application/json"},
            request_body='{"title": "My Photo", "url": "https://example.com/photo.jpg"}',
            response_status=201, response_headers={},
            response_body='{"id": 1}', timestamp=1000.0
        ))

        spec = generate_openapi_spec(storage)

        path = spec["paths"]["/photos"]
        request_body = path["post"]["requestBody"]
        schema = request_body["content"]["application/json"]["schema"]
        assert "title" in schema["properties"]
        assert "url" in schema["properties"]

    def test_includes_query_parameters(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="1", method="GET",
            url="https://api.example.com/photos?page=1&limit=20&sort=date",
            request_headers={}, request_body=None,
            response_status=200, response_headers={},
            response_body='[]', timestamp=1000.0
        ))

        spec = generate_openapi_spec(storage)

        params = spec["paths"]["/photos"]["get"]["parameters"]
        param_names = [p["name"] for p in params]
        assert "page" in param_names
        assert "limit" in param_names
        assert "sort" in param_names

    def test_domain_filter(self):
        storage = TrafficStorage()
        storage.add(CapturedRequest(
            id="1", method="GET", url="https://api.skylight.com/photos",
            request_headers={}, request_body=None,
            response_status=200, response_headers={},
            response_body='[]', timestamp=1000.0
        ))
        storage.add(CapturedRequest(
            id="2", method="GET", url="https://api.google.com/search",
            request_headers={}, request_body=None,
            response_status=200, response_headers={},
            response_body='{}', timestamp=1001.0
        ))

        spec = generate_openapi_spec(storage, domain_filter="skylight")

        assert "/photos" in spec["paths"]
        assert "/search" not in spec["paths"]

    def test_merges_multiple_examples(self):
        storage = TrafficStorage()
        # First request has field "a"
        storage.add(CapturedRequest(
            id="1", method="GET", url="https://api.example.com/items/1",
            request_headers={}, request_body=None,
            response_status=200, response_headers={"Content-Type": "application/json"},
            response_body='{"a": "value1"}', timestamp=1000.0
        ))
        # Second request has field "b"
        storage.add(CapturedRequest(
            id="2", method="GET", url="https://api.example.com/items/2",
            request_headers={}, request_body=None,
            response_status=200, response_headers={"Content-Type": "application/json"},
            response_body='{"b": "value2"}', timestamp=1001.0
        ))

        spec = generate_openapi_spec(storage)

        schema = spec["paths"]["/items/{id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        # Both fields should be present in merged schema
        assert "a" in schema["properties"]
        assert "b" in schema["properties"]

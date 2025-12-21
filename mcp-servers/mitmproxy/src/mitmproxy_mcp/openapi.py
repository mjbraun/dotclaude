# ABOUTME: OpenAPI spec generation from captured HTTP traffic
# ABOUTME: Infers schemas, detects path parameters, and generates OpenAPI 3.0 specs

import json
import re
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from .storage import TrafficStorage, CapturedRequest


def infer_json_schema(value: Any) -> dict:
    """Infer a JSON Schema from a Python value."""
    if value is None:
        return {"type": "null"}
    elif isinstance(value, bool):
        return {"type": "boolean"}
    elif isinstance(value, int):
        return {"type": "integer"}
    elif isinstance(value, float):
        return {"type": "number"}
    elif isinstance(value, str):
        return {"type": "string"}
    elif isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        # Infer schema from first item, merge with others
        item_schema = infer_json_schema(value[0])
        for item in value[1:]:
            item_schema = merge_schemas(item_schema, infer_json_schema(item))
        return {"type": "array", "items": item_schema}
    elif isinstance(value, dict):
        properties = {}
        for key, val in value.items():
            properties[key] = infer_json_schema(val)
        return {"type": "object", "properties": properties}
    else:
        return {"type": "string"}


def merge_schemas(schema1: dict, schema2: dict) -> dict:
    """Merge two JSON schemas, combining their properties."""
    if not schema1:
        return schema2
    if not schema2:
        return schema1

    # If types differ, return a more permissive schema
    type1 = schema1.get("type")
    type2 = schema2.get("type")

    if type1 != type2:
        # Could return anyOf, but for simplicity just pick one
        # Prefer object > array > other
        if type1 == "object" or type2 == "object":
            if type1 == "object":
                return schema1
            return schema2
        return schema1

    if type1 == "object":
        # Merge properties
        props1 = schema1.get("properties", {})
        props2 = schema2.get("properties", {})
        merged_props = dict(props1)
        for key, val in props2.items():
            if key in merged_props:
                merged_props[key] = merge_schemas(merged_props[key], val)
            else:
                merged_props[key] = val
        return {"type": "object", "properties": merged_props}

    if type1 == "array":
        items1 = schema1.get("items", {})
        items2 = schema2.get("items", {})
        return {"type": "array", "items": merge_schemas(items1, items2)}

    return schema1


# Patterns that indicate a path segment is a parameter
_UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
_NUMERIC_PATTERN = re.compile(r'^\d+$')
_HEX_ID_PATTERN = re.compile(r'^[0-9a-f]{8,}$', re.IGNORECASE)

# Segments that should never be treated as parameters
_KNOWN_SEGMENTS = {'api', 'v1', 'v2', 'v3', 'v4', 'graphql', 'rest', 'public', 'private'}


def detect_path_parameters(path: str) -> str:
    """
    Detect path parameters and replace them with {id} placeholders.

    Examples:
        /api/photos/123 -> /api/photos/{id}
        /users/550e8400-e29b-41d4-a716-446655440000 -> /users/{id}
    """
    segments = path.split('/')
    result = []

    for segment in segments:
        if not segment:
            result.append(segment)
            continue

        # Skip known non-parameter segments
        if segment.lower() in _KNOWN_SEGMENTS:
            result.append(segment)
            continue

        # Numeric IDs are always detected, regardless of length
        if _NUMERIC_PATTERN.match(segment):
            result.append("{id}")
            continue

        # Skip very short segments for non-numeric checks
        if len(segment) <= 3:
            result.append(segment)
            continue

        # Check if it looks like an ID (UUID or hex)
        is_param = (
            _UUID_PATTERN.match(segment) or
            (_HEX_ID_PATTERN.match(segment) and len(segment) >= 8)
        )

        if is_param:
            result.append("{id}")
        else:
            result.append(segment)

    return '/'.join(result)


def group_endpoints(
    requests: list[CapturedRequest],
) -> dict[tuple[str, str], list[CapturedRequest]]:
    """
    Group requests by (method, normalized_path).

    Normalizes paths by detecting and replacing path parameters.
    """
    groups: dict[tuple[str, str], list[CapturedRequest]] = {}

    for req in requests:
        parsed = urlparse(req.url)
        normalized_path = detect_path_parameters(parsed.path)
        key = (req.method, normalized_path)

        if key not in groups:
            groups[key] = []
        groups[key].append(req)

    return groups


def _extract_query_params(requests: list[CapturedRequest]) -> list[dict]:
    """Extract query parameters from a list of requests to the same endpoint."""
    param_names = set()

    for req in requests:
        parsed = urlparse(req.url)
        query_params = parse_qs(parsed.query)
        param_names.update(query_params.keys())

    return [
        {"name": name, "in": "query", "schema": {"type": "string"}}
        for name in sorted(param_names)
    ]


def _extract_path_params(path: str) -> list[dict]:
    """Extract path parameters from a path template."""
    params = []
    for segment in path.split('/'):
        if segment.startswith('{') and segment.endswith('}'):
            param_name = segment[1:-1]
            params.append({
                "name": param_name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"}
            })
    return params


def _parse_json_body(body: Optional[str]) -> Optional[Any]:
    """Try to parse a JSON body, return None if not valid JSON."""
    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None


def generate_openapi_spec(
    storage: TrafficStorage,
    domain_filter: Optional[str] = None,
    title: str = "Generated API",
    version: str = "1.0.0",
) -> dict:
    """
    Generate an OpenAPI 3.0 spec from captured traffic.

    Args:
        storage: Traffic storage containing captured requests
        domain_filter: Only include requests matching this domain
        title: Title for the API spec
        version: Version string for the API spec

    Returns:
        OpenAPI 3.0 specification as a dictionary
    """
    requests = storage.list(domain_filter=domain_filter)
    groups = group_endpoints(requests)

    paths: dict[str, dict] = {}

    for (method, path), reqs in groups.items():
        if path not in paths:
            paths[path] = {}

        method_lower = method.lower()
        operation: dict[str, Any] = {
            "responses": {}
        }

        # Collect path parameters
        path_params = _extract_path_params(path)
        query_params = _extract_query_params(reqs)
        if path_params or query_params:
            operation["parameters"] = path_params + query_params

        # Collect request body schemas (for POST, PUT, PATCH)
        if method_lower in ('post', 'put', 'patch'):
            request_schema = None
            for req in reqs:
                body = _parse_json_body(req.request_body)
                if body is not None:
                    schema = infer_json_schema(body)
                    request_schema = merge_schemas(request_schema, schema) if request_schema else schema

            if request_schema:
                operation["requestBody"] = {
                    "content": {
                        "application/json": {
                            "schema": request_schema
                        }
                    }
                }

        # Collect response schemas grouped by status code
        response_schemas: dict[int, dict] = {}
        for req in reqs:
            status = req.response_status
            body = _parse_json_body(req.response_body)

            if body is not None:
                schema = infer_json_schema(body)
                if status in response_schemas:
                    response_schemas[status] = merge_schemas(response_schemas[status], schema)
                else:
                    response_schemas[status] = schema
            elif status not in response_schemas:
                response_schemas[status] = None

        # Build responses section
        for status, schema in response_schemas.items():
            response: dict[str, Any] = {
                "description": f"Response {status}"
            }
            if schema:
                response["content"] = {
                    "application/json": {
                        "schema": schema
                    }
                }
            operation["responses"][str(status)] = response

        # Ensure at least one response
        if not operation["responses"]:
            operation["responses"]["200"] = {"description": "Success"}

        paths[path][method_lower] = operation

    return {
        "openapi": "3.0.0",
        "info": {
            "title": title,
            "version": version,
        },
        "paths": paths,
    }

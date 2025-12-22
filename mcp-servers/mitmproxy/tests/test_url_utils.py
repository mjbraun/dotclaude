# ABOUTME: Tests for URL utility functions
# ABOUTME: Validates URL truncation and noise filtering for token-efficient output

import pytest
from mitmproxy_mcp.url_utils import truncate_url, is_noise_domain


class TestTruncateUrl:
    def test_short_url_unchanged(self):
        url = "https://api.example.com/photos"
        assert truncate_url(url) == url

    def test_truncates_long_query_string(self):
        url = "https://api.example.com/auth?state=verylongstatetoken123456789&code=abc123&other=param"
        result = truncate_url(url, max_query_length=20)
        assert "api.example.com/auth" in result
        assert len(result) < len(url)
        assert result.endswith("...")

    def test_preserves_path(self):
        url = "https://api.example.com/v1/users/123/photos?token=very_long_token_here"
        result = truncate_url(url, max_query_length=10)
        assert "/v1/users/123/photos" in result

    def test_no_query_string(self):
        url = "https://api.example.com/simple/path"
        assert truncate_url(url) == url

    def test_custom_max_length(self):
        url = "https://api.example.com/path?a=1&b=2&c=3&d=4&e=5"
        result = truncate_url(url, max_query_length=5)
        assert "..." in result


class TestIsNoiseDomain:
    def test_google_apis_is_noise(self):
        assert is_noise_domain("https://www.googleapis.com/auth/something")
        assert is_noise_domain("https://accounts.google.com/signin")
        assert is_noise_domain("https://play.google.com/log")

    def test_gstatic_is_noise(self):
        assert is_noise_domain("https://www.gstatic.com/some/resource.js")
        assert is_noise_domain("https://fonts.gstatic.com/s/roboto")

    def test_app_api_not_noise(self):
        assert not is_noise_domain("https://api.example.com/photos")
        assert not is_noise_domain("https://h90vqdmvb4.execute-api.us-west-1.amazonaws.com/dev/v1/users")

    def test_cognito_not_noise(self):
        assert not is_noise_domain("https://sofabaton.auth.us-west-1.amazoncognito.com/oauth2")

    def test_googleusercontent_is_noise(self):
        assert is_noise_domain("https://lh3.googleusercontent.com/photo.jpg")

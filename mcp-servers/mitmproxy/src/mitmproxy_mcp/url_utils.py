# ABOUTME: URL utility functions for token-efficient output
# ABOUTME: Provides URL truncation and noise domain filtering

from urllib.parse import urlparse

# Domains that generate noise traffic (auth flows, static assets, telemetry)
NOISE_DOMAINS = [
    "googleapis.com",
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "youtube.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
]


def truncate_url(url: str, max_query_length: int = 50) -> str:
    """
    Truncate a URL's query string to reduce token usage.

    Preserves scheme, host, and path. Truncates query string if too long.

    Args:
        url: The full URL
        max_query_length: Maximum length for query string before truncation

    Returns:
        Truncated URL with '...' suffix if query was truncated
    """
    parsed = urlparse(url)

    if not parsed.query or len(parsed.query) <= max_query_length:
        return url

    # Rebuild URL with truncated query
    truncated_query = parsed.query[:max_query_length] + "..."

    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return f"{base}?{truncated_query}"


def is_noise_domain(url: str) -> bool:
    """
    Check if a URL belongs to a noise domain (telemetry, auth, static assets).

    Args:
        url: The URL to check

    Returns:
        True if the domain is considered noise
    """
    parsed = urlparse(url)
    host = parsed.netloc.lower()

    for noise in NOISE_DOMAINS:
        if host.endswith(noise) or host == noise:
            return True

    return False

import binascii
import socket
import ssl
from functools import lru_cache
from urllib.parse import urlparse

import httpx
from loguru import logger
from pydantic import BaseModel, constr

from pki_tools.exceptions import FetchFailure

CACHE_TIME_SECONDS = 60 * 60 * 24 * 30  # 1 month
HTTPX_CLIENT = httpx.Client(
    transport=httpx.HTTPTransport(retries=2), timeout=30
)


class CertsUri(BaseModel):
    """
    Describes a URI where one or more public certificate(s)
    can be downloaded

    Attributes:
        uri: The URI for the public certificate(s)
            cache_time_seconds: Specifies how long the public cert should be
            cached, default is 1 month.
    """

    uri: constr(pattern=r"https*://.*")
    cache_time_seconds: int = CACHE_TIME_SECONDS

    @property
    def hostname(self):
        return urlparse(self.uri).hostname


def _byte_to_hex(bytes_in: bytes) -> str:
    return binascii.hexlify(bytes_in).decode().upper()


def _hex_to_byte(hex_string: str) -> bytes:
    byte_array = bytearray()
    for i in range(0, len(hex_string), 2):
        byte_array.append(int(hex_string[i : i + 2], 16))

    return bytes(byte_array)


@lru_cache(maxsize=None)
def _download_server_certificate(hostname: str, cache_ttl: int = None):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            return ssl.DER_cert_to_PEM_cert(der_cert)


def _do_download(client: httpx.Client, uri: str) -> httpx.Response:
    """Helper to perform the actual download and check status."""
    ret = client.get(uri)

    if ret.status_code != 200:
        logger.bind(status=ret.status_code).error(
            "Failed to fetch issuer from URI"
        )
        raise FetchFailure(f"Failed to fetch URI. Status: {ret.status_code}")

    return ret


@lru_cache(maxsize=None)
def _download_cached(uri: str, ttl: int = None, proxy: str = None) -> httpx.Response:
    """
    Download and cache content from a URI with optional proxy support.

    Args:
        uri: The URI to download from
        ttl: Time-to-live for cache (used as cache key for cache invalidation)
        proxy: Optional proxy URL (e.g., 'http://proxy.example.com:8080')

    Returns:
        httpx.Response object containing the downloaded content
    """
    # Use cached version when proxy is None
    if proxy is None:
        client = HTTPX_CLIENT
    else:
        # For proxy requests, create a new client with proxy
        client = httpx.Client(
            transport=httpx.HTTPTransport(retries=2),
            timeout=30,
            proxy=proxy
        )

    try:
        return _do_download(client, uri)
    finally:
        if proxy is not None:
            client.close()

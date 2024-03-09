import binascii
import ssl
from functools import lru_cache

from cryptography.hazmat.primitives._serialization import (
    Encoding,
    PublicFormat,
)
from pydantic import BaseModel, constr

CACHE_TIME_SECONDS = 60 * 60 * 24 * 30  # 1 month


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
        ret = self.uri.replace("https://", "")
        ret = ret.replace("http://", "")
        return ret


def _byte_to_hex(bytes_in: bytes) -> str:
    return binascii.hexlify(bytes_in).decode().upper()


def _hex_to_byte(hex_string: str) -> bytes:
    byte_array = bytearray()
    for i in range(0, len(hex_string), 2):
        byte_array.append(int(hex_string[i : i + 2], 16))

    return bytes(byte_array)


def _der_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.PKCS1,
    )


@lru_cache(maxsize=None)
def _download_server_certificate(hostname: str, cache_ttl: int = None):
    return ssl.get_server_certificate((hostname, 443))

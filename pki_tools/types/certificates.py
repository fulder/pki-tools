import time
from functools import lru_cache
from typing import List, Type, T

from cryptography import x509
from loguru import logger

from pydantic import BaseModel, constr


from pki_tools.exceptions import OcspIssuerFetchFailure
from pki_tools.types.certificate import Certificate
from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.utils import HTTPX_CLIENT

CACHE_TIME_SECONDS = 60 * 60 * 24 * 30  # 1 month


class CertsUri(BaseModel):
    """
    Describes a URI where one or more public certificate(s)
    can be downloaded

    Examples::
        CertsUri(uri="https://my.ca.link.com/ca.pem")
    Attributes:
        uri -- The URI for the public certificate(s)
        cache_time_seconds -- Specifies how long the public cert should be
        cached, default is 1 month.
    """

    uri: constr(pattern=r"https*://.*")
    cache_time_seconds: int = CACHE_TIME_SECONDS


class Certificates(CryptoParser):
    """
    Attributes:
        certificates -- a list of
        [Certificates](https://pki-tools.fulder.dev/pki_tools/types/#certificates)
    """

    certificates: List[Certificate]

    @classmethod
    def from_cryptography(
        cls: Type[T], crypto_certs: List[x509.Certificate]
    ) -> T:
        certificates = []
        for crypt_cert in crypto_certs:
            certificates.append(Certificate.from_cryptography(crypt_cert))
        return cls(certificates=certificates, _x509_obj=crypto_certs)

    @classmethod
    def from_file(cls: T, file_path: str) -> T:
        """
        Reads a file containing one or more PEM certificate(s) into a
        [Certificates](https://pki-tools.fulder.dev/pki_tools/types/#certificates)
        object

        Arguments:
            file_path -- Path and filename of the PEM certificate
        Returns:
             A
             [Certificates](https://pki-tools.fulder.dev/pki_tools/types/#certificates)
             object representing the certificate(s) from file
        """
        with open(file_path, "r") as f:
            cert_pem = f.read()

        crypto_certs = x509.load_pem_x509_certificates(cert_pem.encode())
        return cls.from_cryptography(crypto_certs)

    @classmethod
    def from_pem_string(cls: T, pem_string: str) -> T:
        crypto_certs = x509.load_pem_x509_certificates(pem_string.encode())
        return cls.from_cryptography(crypto_certs)

    @classmethod
    def from_uri(
        cls: T,
        uri: str,
        cache_time_seconds: int = CACHE_TIME_SECONDS,
    ) -> T:
        """
        Loads
        [Certificates](https://pki-tools.fulder.dev/pki_tools/types/#certificates)
        from a str URI

        Arguments:
             uri -- A str containing the URI where the certificate(s)
             can be downloaded.
             cache_time_seconds -- Decides how long the certificates
             should be cached, default is 1 month
        """
        chain_uri = CertsUri(uri=uri, cache_time_seconds=cache_time_seconds)
        cache_ttl = round(time.time() / chain_uri.cache_time_seconds)
        return cls._from_uri(chain_uri.uri, cache_ttl)

    @classmethod
    @lru_cache(maxsize=None)
    def _from_uri(cls: T, uri: str, ttl=None) -> T:
        ret = HTTPX_CLIENT.get(uri)

        if ret.status_code != 200:
            logger.bind(status=ret.status_code).error(
                "Failed to fetch issuer from URI"
            )
            raise OcspIssuerFetchFailure(
                f"Issuer URI fetch failed. Status: {ret.status_code}"
            )

        return cls.from_pem_string(ret.text)

    @property
    def pem_string(self):
        all_certs = ""
        for cert in self.certificates:
            all_certs += cert.pem_string

        return all_certs

    def to_file(self, file_path: str):
        """
        Saves one or more certificate(s) into a file

        Arguments:
            file_path -- Path and filename where to store the certificate(s)
        """
        with open(file_path, "w") as f:
            f.write(self.pem_string)

        logger.debug(f"Certificate(s) saved to {file_path}")

    def _to_cryptography(self) -> List[x509.Certificate]:
        certs = []
        for cert in self.certificates:
            certs.append(cert._to_cryptography())
        return certs

    def _string_dict(self):
        certs = {"Certificates": []}
        for cert in self.certificates:
            certs["Certificates"].append(cert._to_string_dict())
        return certs

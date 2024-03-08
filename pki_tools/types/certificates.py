import time
from functools import lru_cache
from typing import List, Type

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

    Attributes:
        uri: The URI for the public certificate(s)
            cache_time_seconds: Specifies how long the public cert should be
            cached, default is 1 month.
    """

    uri: constr(pattern=r"https*://.*")
    cache_time_seconds: int = CACHE_TIME_SECONDS


class Certificates(CryptoParser):
    """
    A list of one or more certificates

    Attributes:
        certificates: a list of
            [Certificate][pki_tools.types.certificate.Certificate]
    """

    certificates: List[Certificate]

    @classmethod
    def from_cryptography(
        cls: Type["Certificates"], crypto_certs: List[x509.Certificate]
    ) -> "Certificates":
        """
        Create a Certificates object from a list of cryptography certificates.

        Args:
            crypto_certs: List of cryptography certificates.

        Returns:
            Instance of Certificates containing the provided certificates.
        """
        certificates = []
        for crypt_cert in crypto_certs:
            certificates.append(Certificate.from_cryptography(crypt_cert))
        return cls(certificates=certificates, _x509_obj=crypto_certs)

    @classmethod
    def from_file(cls: Type["Certificates"], file_path: str) -> "Certificates":
        """
        Reads a file containing one or more PEM certificate(s) into a
        Certificates object.

        Args:
            file_path: Path and filename of the PEM certificate.

        Returns:
            A Certificates object representing the certificate(s) from file.
        """
        with open(file_path, "r") as f:
            cert_pem = f.read()

        crypto_certs = x509.load_pem_x509_certificates(cert_pem.encode())
        return cls.from_cryptography(crypto_certs)

    @classmethod
    def from_pem_string(
        cls: Type["Certificates"], pem_string: str
    ) -> "Certificates":
        """
        Create a Certificates object from a PEM string.

        Args:
            pem_string: PEM string containing certificate(s).

        Returns:
            Instance of Certificates containing the certificates from the PEM
            string.
        """
        crypto_certs = x509.load_pem_x509_certificates(pem_string.encode())
        return cls.from_cryptography(crypto_certs)

    @classmethod
    def from_uri(
        cls: Type["Certificates"],
        uri: str,
        cache_time_seconds: int = CACHE_TIME_SECONDS,
    ) -> "Certificates":
        """
        Loads Certificates from a URI.

        Args:
            uri: An URI where the certificate(s) can be downloaded.
            cache_time_seconds: Specifies how long the certificates
                should be cached, default is 1 month.
                Defaults to CACHE_TIME_SECONDS.

        Returns:
            Instance of Certificates containing the certificates
            fetched from the URI.
        """
        chain_uri = CertsUri(uri=uri, cache_time_seconds=cache_time_seconds)
        cache_ttl = round(time.time() / chain_uri.cache_time_seconds)
        return cls._from_uri(chain_uri.uri, cache_ttl)

    @classmethod
    @lru_cache(maxsize=None)
    def _from_uri(
        cls: Type["Certificates"], uri: str, ttl=None
    ) -> "Certificates":
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
    def pem_string(self) -> str:
        """
        Returns a string containing the PEM-encoded certificates.

        Returns:
            PEM string containing all the certificates.
        """
        all_certs = ""
        for cert in self.certificates:
            all_certs += cert.pem_string

        return all_certs

    def to_file(self, file_path: str) -> None:
        """
        Saves one or more certificate(s) into a file.

        Args:
            file_path: Path and filename where to store the certificate(s).
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
            certs["Certificates"].append(cert._string_dict())
        return certs

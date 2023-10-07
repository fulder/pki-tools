import binascii
import re
import time
import typing
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from typing import List, Type, Union, Optional, ClassVar

import requests
from cryptography import x509
from cryptography.hazmat._oid import NameOID, ExtensionOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, dsa, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from cryptography.x509.extensions import (
    Extensions as x509Extensions,
    AuthorityKeyIdentifier as x509AuthorityKeyIdentifier,
    ExtensionNotFound,
    ExtensionTypeVar,
)
from cryptography.x509.ocsp import OCSPResponse
from loguru import logger
from pydantic import constr, BaseModel, Field, ConfigDict

import pki_tools
from pki_tools import exceptions


class PemCert(str):
    """
    PemCert is a string containing the PEM formatted certificate

    Example:
    ::
        PemCert(
            \"\"\"
            -----BEGIN CERTIFICATE-----
            MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
            MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
            VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
            NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
            TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
            ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
            V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
            gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
            FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
            CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
            BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
            BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
            Wm7DCfrPNGVwFWUQOmsPue9rZBgO
            -----END CERTIFICATE-----
            \"\"\"
        )
    """


PEM_REGEX = re.compile(
    r"\s*-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+\s*"
)
CACHE_TIME_SECONDS = 60 * 60 * 24 * 30  # 1 month


class ChainUri(BaseModel):
    """
    Describes the CA chain URI where the public certificate(s)
    can be downloaded

    Examples::
        ChainUri(uri="https://my.ca.link.com/ca.pem")
    Attributes:
        uri -- The URI for the public CA certificate(s)
        cache_time_seconds -- Specifies how long the public cert should be
        cached, default is 1 month.
    """

    uri: constr(pattern=r"https*://.*")
    cache_time_seconds: int = CACHE_TIME_SECONDS


class Chain(BaseModel):
    """
    Chain holds a list of certificates in a
    [chain of trust](https://en.wikipedia.org/wiki/Chain_of_trust)

    Attributes:
        certificates -- list of
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
    Examples:
    From File::
        chain = Chain.from_fle("/path/to/chain.pem")
    From PEM::
        pem_string="-----BEGIN CERTIFICATE-----...."
        chain = Chain.from_pem_str(pem_string)
    From URI::
        chain = Chain.from_uri("https://chain.domain/chain.pem")
    Using Chain::
        cert: x509.Certificate = ...
        chain.check_chain()
        chain.get_issuer(cert)
    """

    certificates: List[x509.Certificate]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def check_chain(self):
        """
        Validate the chain (if it contains more than one certificate)
        checking expiration and signatures of all certificates in the chain

        Raises:
            [exceptions.NotCompleteChain](https://pki-tools.fulder.dev/pki_tools/exceptions/#notcompletechain)
            -- When the chain contain only one not self-signed certificate

            [exceptions.CertExpired](https://pki-tools.fulder.dev/pki_tools/exceptions/#certexpired)
            -- If some certificate in the chain has expired

            [exceptions.InvalidSignedType](https://pki-tools.fulder.dev/pki_tools/exceptions/#invalidsignedtype)
            -- When the issuer has a non-supported type

            [exceptions.SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
            -- When the signature verification fails
        """
        if len(self.certificates) == 1:
            if (
                self.certificates[0].issuer.rfc4514_string()
                == self.certificates[0].subject.rfc4514_string()
            ):
                logger.debug(
                    "Chain contains only one self signed cert, "
                    "nothing to check"
                )
                return
            else:
                raise exceptions.NotCompleteChain()

        for cert in self.certificates:
            log = logger.bind(subject=cert.subject)
            if (
                cert.not_valid_after < datetime.now()
                or cert.not_valid_before > datetime.now()
            ):
                log.error("Certificate expired")
                raise exceptions.CertExpired(
                    f"Certificate in chain with subject: '{cert.subject}' "
                    f"has expired"
                )

            issuer = self.get_issuer(cert)

            pki_tools.verify_signature(cert, issuer)

    def get_issuer(
        self,
        signed: [
            x509.Certificate,
            x509.CertificateRevocationList,
            OCSPResponse,
        ],
    ) -> x509.Certificate:
        """
        Returns the issuer of a signed entity

        Arguments:
            signed: The signed certificate can either be a
            [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate),
            [x509.CertificateRevocationList](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.CertificateRevocationList)
            or a
            [x509.CertificateRevocationList](https://cryptography.io/en/latest/x509/ocsp/#cryptography.x509.ocsp.OCSPResponse)
            issuer: The issuer of the signed entity

        Returns:
            The
            [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
            representing the issuer of the `signed` entity

        Raises:
            [exceptions.CertIssuerMissingInChain](https://pki-tools.fulder.dev/pki_tools/exceptions/#certissuermissinginchain)
            -- When the issuer of the entitie is missing in the chain
        """
        cert_subject = signed.issuer.rfc4514_string()
        log = logger.bind(subject=cert_subject)

        for next_chain_cert in self.certificates:
            if cert_subject == next_chain_cert.subject.rfc4514_string():
                log.trace("Found issuer cert in chain")
                return next_chain_cert

        raise exceptions.CertIssuerMissingInChain()

    @classmethod
    def from_file(cls: Type["Chain"], file_path: str) -> "Chain":
        """
        Creates a Chain from a file path containing one or more PEM
        certificate(s)

        Arguments:
             file_path -- The path to the file containing the PEM certificate(s)
        """
        certificates = pki_tools.read_many_from_file(file_path)
        return cls(certificates=certificates)

    @classmethod
    def from_pem_str(cls: Type["Chain"], pem_certs: str) -> "Chain":
        """
        Creates a Chain from a string containing one or more certificate(s)
        in PEM format

        Arguments:
             pem_certs -- A string containing one or more certificate(s)
        """
        certificates = x509.load_pem_x509_certificates(pem_certs.encode())
        return cls(certificates=certificates)

    @classmethod
    def from_uri(
        cls: Type["Chain"],
        uri: str,
        cache_time_seconds: int = CACHE_TIME_SECONDS,
    ) -> "Chain":
        """
        Creates a Chain from a str URI

        Arguments:
             chain_uri -- A str containing the URI where the certificate
             chain can be downloaded.
             cache_time_seconds -- Decides how long the chain should be cached,
             default is 1 month
        """
        chain_uri = ChainUri(uri=uri, cache_time_seconds=cache_time_seconds)
        cache_ttl = round(time.time() / chain_uri.cache_time_seconds)
        return Chain._from_uri(chain_uri.uri, cache_ttl)

    @classmethod
    @lru_cache(maxsize=None)
    def _from_uri(cls: Type["Chain"], uri: str, ttl=None) -> "Chain":
        ret = requests.get(uri)

        if ret.status_code != 200:
            logger.bind(status=ret.status_code).error(
                "Failed to fetch issuer from URI"
            )
            raise pki_tools.exceptions.OcspIssuerFetchFailure(
                f"Issuer URI fetch failed. Status: {ret.status_code}"
            )

        return cls(certificates=x509.load_pem_x509_certificates(ret.content))


def _is_pem_str(check):
    if not isinstance(check, PemCert) and not isinstance(check, str):
        return False

    return re.match(PEM_REGEX, check)

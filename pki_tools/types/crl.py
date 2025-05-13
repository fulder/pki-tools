import re
import time
from datetime import datetime
from typing import Type, Optional, Dict, List

from cryptography import x509
from loguru import logger

from pki_tools.types.extensions import Extensions
from pki_tools.exceptions import MissingInit, LoadError
from pki_tools.types.key_pair import (
    CryptoPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
)
from pki_tools.types.crypto_parser import (
    CryptoParser,
    InitCryptoParser,
    CryptoConfig,
    HelperFunc,
)
from pki_tools.types.name import Name
from pki_tools.types.signature_algorithm import SignatureAlgorithm
from pki_tools.types.utils import (
    CACHE_TIME_SECONDS,
    CertsUri,
    _download_cached,
)


class RevokedCertificate(CryptoParser):
    """
    Represents a revoked certificate.

    Attributes:
        serial: The serial number of the certificate.
        date: The revocation date of the certificate.
        extensions: Extensions associated with the certificate.
    """

    serial: int
    date: datetime
    extensions: Optional[Extensions] = None

    @classmethod
    def from_cryptography(
        cls: Type["RevokedCertificate"], crypto_obj: x509.RevokedCertificate
    ) -> "RevokedCertificate":
        """
        Create a RevokedCertificate object from a cryptography
        RevokedCertificate.

        Args:
            crypto_obj: Cryptography RevokedCertificate.

        Returns:
            RevokedCertificate: Instance of RevokedCertificate.
        """
        extensions = None
        if crypto_obj.extensions:
            extensions = Extensions.from_cryptography(crypto_obj.extensions)

        ret = cls(
            serial=crypto_obj.serial_number,
            date=crypto_obj.revocation_date_utc,
            extensions=extensions,
            _x509_obj=crypto_obj,
        )

        return ret

    def _to_cryptography(self) -> x509.RevokedCertificate:
        builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(self.serial)
            .revocation_date(self.date)
        )

        if self.extensions is not None:
            for extension in self.extensions:
                builder = builder.add_extension(
                    extval=extension._to_cryptography(),
                    critical=extension.critical,
                )

        return builder.build()

    def _string_dict(self) -> Dict:
        return {
            "Serial Number": self.serial,
            "Revocation Date": str(self.date),
            "Extensions": self.extensions._string_dict(),
        }


CRL_REGEXP = re.compile(r"\s*-+BEGIN X509 CRL-+[\w+/\s=]*-+END X509 CRL-+\s*")


class CertificateRevocationList(InitCryptoParser):
    """
    Represents a certificate revocation list (CRL).

    Attributes:
        issuer: The name of the issuer.
        last_update: The last update time of the CRL.
        next_update: The next update time of the CRL.
        revoked_certs: List of revoked certificates.
    """

    issuer: Name
    last_update: datetime
    next_update: datetime
    revoked_certs: Optional[List[RevokedCertificate]] = None
    extensions: Optional[Extensions] = None

    _private_key: CryptoPrivateKey

    @classmethod
    def from_cryptography(
        cls: Type["CertificateRevocationList"],
        crypto_crl: x509.CertificateRevocationList,
    ) -> "CertificateRevocationList":
        """
        Create a CertificateRevocationList object from a cryptography
        CertificateRevocationList.

        Args:
            crypto_crl: Cryptography CertificateRevocationList.

        Returns:
            Instance of CertificateRevocationList.
        """

        extensions = None
        if crypto_crl.extensions is not None:
            extensions = Extensions.from_cryptography(crypto_crl.extensions)

        ret = cls(
            issuer=Name.from_cryptography(crypto_crl.issuer),
            last_update=crypto_crl.last_update_utc,
            next_update=crypto_crl.next_update_utc,
            extensions=extensions,
        )
        ret._x509_obj = crypto_crl
        return ret

    @classmethod
    def from_uri(
        cls: Type["CertificateRevocationList"],
        uri: str,
        cache_time_seconds: int = CACHE_TIME_SECONDS,
    ) -> "CertificateRevocationList":
        """
        Loads CertificateRevocationList from a URI.

        Args:
            uri: URI where the CRL can be downloaded.
            cache_time_seconds: Specifies how long the CRL
                should be cached, default is 1 month.

        Returns:
            Instance of CertificateRevocationList containing the revoked
                certificates fetched from the URI.
        """

        cache_ttl = round(time.time() / cache_time_seconds)
        crl_uri = CertsUri(uri=uri)
        res = _download_cached(crl_uri.uri, cache_ttl)

        try:
            return CertificateRevocationList.from_der_bytes(res.content)
        except (TypeError, ValueError) as e:
            logger.bind(error=str(e)).trace("Error during loading of CRL DER")
            pass

        try:
            return CertificateRevocationList.from_pem_string(
                res.content.decode()
            )
        except TypeError as e:
            logger.bind(crl=res.content).error("Failed to load CRL")
            raise LoadError(e) from None

    @property
    def tbs_bytes(self) -> bytes:
        """
        Return the bytes to be signed of the CRL.

        Returns:
            TBS bytes of the CRL.
        """
        return self._crypto_object.tbs_certlist_bytes

    def sign(
        self,
        private_key: CryptoPrivateKey,
        algorithm: Optional[SignatureAlgorithm] = None,
    ) -> None:
        """
        Sign the CRL with the provided private key and algorithm.

        Args:
            private_key: Private key used to sign the CRL.
            algorithm: Signature algorithm to use for signing.
        """
        self._private_key = private_key
        self._signature_algorithm = algorithm
        self._x509_obj = self._to_cryptography()

    def get_revoked(self, cert_serial: int) -> Optional[RevokedCertificate]:
        """
        Get a revoked certificate by serial number.

        Args:
            cert_serial: Serial number of the certificate.

        Returns:
            RevokedCertificate object if found, else None.
        """
        crypto_revoked = (
            self._crypto_object.get_revoked_certificate_by_serial_number(
                cert_serial
            )
        )
        if crypto_revoked is not None:
            return RevokedCertificate.from_cryptography(crypto_revoked)
        return None

    def _to_cryptography(self) -> x509.CertificateRevocationList:
        if not hasattr(self, "_private_key"):
            raise MissingInit("Please use 'sign' function")

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer._to_cryptography())
        builder = builder.last_update(self.last_update)
        builder = builder.next_update(self.next_update)

        if self.extensions is not None:
            for extension in self.extensions:
                builder = builder.add_extension(
                    extval=extension._to_cryptography(),
                    critical=extension.critical,
                )

        for cert in self.revoked_certs:
            builder = builder.add_revoked_certificate(cert._to_cryptography())

        if isinstance(self._private_key, Ed25519PrivateKey) or isinstance(
            self._private_key, Ed448PrivateKey
        ):
            alg = None
        else:
            alg = self._signature_algorithm.algorithm._to_cryptography()

        return builder.sign(
            private_key=self._private_key._to_cryptography(),
            algorithm=alg,
        )

    def _string_dict(self) -> Dict[str, str]:
        certs = []
        for cert in self.revoked_certs:
            certs.append(cert._string_dict())

        return {"Issuer": self.name._string_dict(), "Certs": certs}

    @classmethod
    def _crypto_config(cls) -> CryptoConfig:
        return CryptoConfig(
            load_pem=HelperFunc(func=x509.load_pem_x509_crl),
            load_der=HelperFunc(func=x509.load_der_x509_crl),
            pem_regexp=CRL_REGEXP,
        )

from datetime import datetime
from typing import Type, Optional, Dict, List

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from loguru import logger

from pki_tools.types.extensions import Extensions
from pki_tools.exceptions import CrlLoadError, MissingInit
from pki_tools.types.key_pair import CryptoKeyPair
from pki_tools.types.crypto_parser import CryptoParser, InitCryptoParser
from pki_tools.types.name import Name
from pki_tools.types.signature_algorithm import HashAlgorithm


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
            date=crypto_obj.revocation_date,
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
        ret = cls(
            issuer=Name.from_cryptography(crypto_crl.issuer),
            last_update=crypto_crl.last_update_utc,
            next_update=crypto_crl.next_update_utc,
        )
        ret._x509_obj = crypto_crl
        return ret

    @classmethod
    def from_bytes(
        cls: Type["CertificateRevocationList"], data: bytes
    ) -> "CertificateRevocationList":
        """
        Load a CertificateRevocationList object from bytes data.

        Args:
            data: Bytes data in DER or PEM format containing the CRL.

        Raises:
            CrlLoadError: If loading of CRL fails.

        Returns:
            Instance of CertificateRevocationList.
        """
        try:
            crypto_crl = x509.load_der_x509_crl(data)
            return CertificateRevocationList.from_cryptography(crypto_crl)
        except (TypeError, ValueError) as e:
            logger.bind(error=str(e)).trace("Error during loading of CRL DER")
            pass

        try:
            crypto_crl = x509.load_pem_x509_crl(data)
            return CertificateRevocationList.from_cryptography(crypto_crl)
        except TypeError as e:
            logger.bind(crl=data).error("Failed to load CRL")
            raise CrlLoadError(e) from None

    @property
    def tbs_bytes(self) -> bytes:
        """
        Return the bytes to be signed of the CRL.

        Returns:
            TBS bytes of the CRL.
        """
        return self._crypto_object.tbs_certlist_bytes

    @property
    def der_bytes(self) -> bytes:
        """
        Return the DER bytes of the CRL.

        Returns:
            DER bytes of the CRL.
        """
        return self._crypto_object.public_bytes(serialization.Encoding.DER)

    def sign(
        self, private_key: CryptoKeyPair, algorithm: HashAlgorithm
    ) -> None:
        """
        Sign the CRL with the provided private key and algorithm.

        Args:
            private_key: Key pair containing the private key used to
                sign the CRL.
            algorithm: Hash algorithm to use for signing.
        """
        self._private_key = private_key
        self._algorithm = algorithm
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

    def to_file(self, file_path: str) -> None:
        """
        Save the CRL to a file.

        Args:
            file_path: Path to save the file.
        """
        with open(file_path, "w") as f:
            f.write(self.der_bytes.decode())

    def _to_cryptography(self) -> x509.CertificateRevocationList:
        if not hasattr(self, "_private_key"):
            raise MissingInit("Please use 'sign' function")

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer._to_cryptography())
        builder = builder.last_update(self.last_update)
        builder = builder.next_update(self.next_update)

        for cert in self.revoked_certs:
            builder = builder.add_revoked_certificate(cert._to_cryptography())

        return builder.sign(
            private_key=self._private_key._to_cryptography(),
            algorithm=self._algorithm._to_cryptography(),
        )

    def _string_dict(self) -> Dict[str, str]:
        certs = []
        for cert in self.revoked_certs:
            certs.append(cert._string_dict())

        return {"Issuer": self.name._string_dict(), "Certs": certs}

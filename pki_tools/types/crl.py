from datetime import datetime
from typing import Type, List, Optional, Dict

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
    serial: int
    date: datetime
    extensions: Optional[Extensions] = None

    @classmethod
    def from_cryptography(
        cls: Type["RevokedCertificate"], crypto_obj: x509.RevokedCertificate
    ) -> "RevokedCertificate":
        extensions = None
        if crypto_obj.extensions is not None:
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
    issuer: Name
    last_update: datetime
    next_update: datetime
    revoked_certs: List[RevokedCertificate]

    @classmethod
    def from_cryptography(
        cls: Type["CertificateRevocationList"],
        crypto_crl: x509.CertificateRevocationList,
    ) -> "CertificateRevocationList":
        revoked_certs = []
        for cert in crypto_crl:
            revoked_certs.append(RevokedCertificate.from_cryptography(cert))

        ret = cls(
            issuer=Name.from_cryptography(crypto_crl.issuer),
            revoked_certs=revoked_certs,
            last_update=crypto_crl.last_update,
            next_update=crypto_crl.next_update,
        )
        ret._x509_obj = crypto_crl
        return ret

    @classmethod
    def from_bytes(cls, data: bytes):
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
        return self._crypto_object.tbs_certlist_bytes

    @property
    def der_bytes(self) -> bytes:
        return self._crypto_object.public_bytes(serialization.Encoding.DER)

    def sign(self, private_key: CryptoKeyPair, algorithm: HashAlgorithm):
        self._private_key = private_key
        self._algorithm = algorithm
        self._x509_obj = self._to_cryptography()

    def get_revoked(self, cert_serial: int):
        for cert in self.revoked_certs:
            if cert.serial == cert_serial:
                return cert
        return None

    def to_file(self, file_path):
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

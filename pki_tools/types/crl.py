from datetime import datetime, timedelta
from typing import Type, List, Optional

from cryptography import x509

from pki_tools.types.extensions import Extensions
from pki_tools.exceptions import MissingPrivateKey
from pki_tools.types.key_pair import CryptoKeyPair
from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.types.name import Name
from pki_tools.types.signature_algorithm import HashAlgorithm


class RevokedCertificate(CryptoParser):
    serial: int
    date: datetime
    extensions: Optional[Extensions]

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
        builder = x509.RevokedCertificateBuilder().serial_number(
            self.serial
        ).revocation_date(
            self.date
        )

        if self.extensions is not None:
            for extension in self.extensions:
                builder = builder.add_extension(
                    extval=extension._to_cryptography(),
                    critical=extension.critical,
                )

        return builder.build()

    def _string_dict(self) -> dict:
        return {
            "Serial Number": self.serial,
            "Revocation Date": str(self.date),
            "Extensions": self.extensions._string_dict()
        }


class CertificateRevocationList(CryptoParser):
    issuer: Name
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
            revoked_certs=revoked_certs
        )
        ret._x509_obj = crypto_crl
        return ret

    @property
    def tbs_bytes(self) -> bytes:
        return self._x509_obj.tbs_certlist_bytes

    def sign(self, private_key: CryptoKeyPair, algorithm: HashAlgorithm, days=60):
        self._private_key = private_key
        self._algorithm = algorithm
        self._days = days
        self._x509_obj = self._to_cryptography()

    def _to_cryptography(self) -> x509.CertificateRevocationList:
        if not hasattr(self, "_private_key"):
            raise MissingPrivateKey("Please use 'sign' function")

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer._to_cryptography())
        builder = builder.last_update(datetime.today())
        builder = builder.next_update(datetime.today() + timedelta(days=self._days))

        for cert in self.certs:
            builder.add_revoked_certificate(cert._to_cryptography())

        return builder.sign(
            private_key=self._private_key._to_cryptography(),
            algorithm=self._algorithm._to_cryptography(),
        )

    def _string_dict(self) -> dict[str, str]:
        certs = []
        for cert in self.revoked_certs:
            certs.append(cert._string_dict())

        return {
            "Issuer": self.name._string_dict(),
            "Certs": certs
        }
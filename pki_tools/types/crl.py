from typing import Type

from cryptography import x509

from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.types.name import Name


class CertificateRevocationList(CryptoParser):
    issuer: Name

    @classmethod
    def from_cryptography(
        cls: Type["CertificateRevocationList"],
        crypto_crl: x509.CertificateRevocationList,
    ) -> "CertificateRevocationList":
        ret = cls(issuer=Name.from_cryptography(crypto_crl.issuer))
        ret._x509_obj = crypto_crl
        return ret

    @property
    def tbs_bytes(self) -> bytes:
        return self._x509_obj.tbs_certlist_bytes

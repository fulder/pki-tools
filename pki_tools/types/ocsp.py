import hashlib
from typing import Type

from cryptography.x509 import ocsp
from loguru import logger

from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.types.utils import _byte_to_hex


class OCSPResponse(CryptoParser):
    response_status: str
    certificate_status: str
    issuer_key_hash: str

    @classmethod
    def from_cryptography(
        cls: Type["OCSPResponse"], crypto_ocsp_response: ocsp.OCSPResponse
    ) -> "OCSPResponse":
        try:
            ocsp_response_key_hash = _byte_to_hex(
                crypto_ocsp_response.issuer_key_hash
            )
        except Exception as e:
            logger.bind(
                exceptionType=type(e),
                exception=str(e),
                issuerHash=crypto_ocsp_response.issuer_key_hash,
            ).error("Couldn't convert issuer key hash to hex")
            raise

        ret = cls(
            response_status=crypto_ocsp_response.response_status.name,
            certificate_status=crypto_ocsp_response.certificate_status.name,
            issuer_key_hash=ocsp_response_key_hash,
        )
        ret._x509_obj = crypto_ocsp_response
        return ret

    @property
    def tbs_bytes(self) -> bytes:
        return self._x509_obj.tbs_response_bytes

    def hash_with_alg(self, der_key) -> str:
        hash_algorithm = hashlib.new(self._x509_obj.hash_algorithm.name)
        hash_algorithm.update(der_key)
        return hash_algorithm.hexdigest().upper()

    @property
    def is_successful(self):
        return self.response_status == "SUCCESSFUL"

    @property
    def is_revoked(self):
        return self.certificate_status == "REVOKED"

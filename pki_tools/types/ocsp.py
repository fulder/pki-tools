import hashlib
from datetime import datetime
from typing import Type, Optional

from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPCertStatus
from loguru import logger

from pki_tools import Certificate
from pki_tools.exceptions import MissingPrivateKey
from pki_tools.types import CryptoKeyPair
from pki_tools.types.crypto_parser import CryptoParser, CryptoObject
from pki_tools.types.signature_algorithm import HashAlgorithm
from pki_tools.types.utils import _byte_to_hex


class OCSPResponse(CryptoParser):
    response_status: str
    certificate_status: Optional[str]
    issuer_key_hash: Optional[str]

    @classmethod
    def from_cryptography(
        cls: Type["OCSPResponse"], crypto_ocsp_response: ocsp.OCSPResponse
    ) -> "OCSPResponse":
        response_status = crypto_ocsp_response.response_status.name

        ocsp_response_key_hash = None
        certificate_status = None
        if response_status == "SUCCESSFUL":
            certificate_status = crypto_ocsp_response.certificate_status.name
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
            response_status=response_status,
            certificate_status=certificate_status,
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

    def sign(
            self,
            cert: Certificate,
            issuer: Certificate,
            algorithm: HashAlgorithm,
            key_pair: CryptoKeyPair,
    ):
        self._cert = cert
        self._issuer = issuer
        self._algorithm = algorithm
        self._private_key = key_pair
        self._x509_obj = self._to_cryptography()

    def _to_cryptography(self) -> ocsp.OCSPResponse:
        if not hasattr(self, "_private_key"):
            raise MissingPrivateKey("Please use 'sign' function")

        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=self._cert._to_cryptography(),
            issuer=self._issuer._to_cryptography(),
            algorithm=self._algorithm._to_cryptography(),
            cert_status=OCSPCertStatus[self.response_status],
            this_update=datetime.now(),
            next_update=datetime.now(),
            revocation_reason=None
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, self._cert)

        return builder.sign(
            self._private_key._to_cryptography(),
            self._algorithm.der_bytes
        )

    def _string_dict(self) -> dict[str, str]:
        return {
            "Response Status": self.response_status,
            "Certificate Status": self.certificate_status,
            "Issuer Key Hash": self.issuer_key_hash,
        }
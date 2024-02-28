import base64
import hashlib
from datetime import datetime
from typing import Type, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPCertStatus
from loguru import logger

from pki_tools.types.extensions import Extensions
from pki_tools.types.certificate import Certificate
from pki_tools.exceptions import MissingPrivateKey, MissingOcspCert
from pki_tools.types.key_pair import CryptoKeyPair
from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.types.signature_algorithm import HashAlgorithm
from pki_tools.types.utils import _byte_to_hex


class OCSPResponse(CryptoParser):
    response_status: str
    certificate_status: Optional[str] = None
    issuer_key_hash: Optional[str] = None
    revocation_time: Optional[datetime] = None

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

        revocation_time = None
        if crypto_ocsp_response.revocation_time is not None:
            revocation_time = crypto_ocsp_response.revocation_time

        ret = cls(
            response_status=response_status,
            certificate_status=certificate_status,
            issuer_key_hash=ocsp_response_key_hash,
            revocation_time=revocation_time,
            _x509_obj = crypto_ocsp_response,
        )
        ret._x509_obj = crypto_ocsp_response
        return ret

    @classmethod
    def from_der_bytes( cls: Type["OCSPResponse"], der: bytes) -> "OCSPResponse":
        crypto_obj = ocsp.load_der_ocsp_response(der)
        return OCSPResponse.from_cryptography(crypto_obj)

    @property
    def tbs_bytes(self) -> bytes:
        return self._x509_obj.tbs_response_bytes

    @property
    def der_bytes(self) -> bytes:
        return self._x509_obj.public_bytes(Encoding.DER)

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
        cert_status = None
        if self.certificate_status is not None:
            cert_status = getattr(OCSPCertStatus, self.certificate_status)

        builder = builder.add_response(
            cert=self._cert._to_cryptography(),
            issuer=self._issuer._to_cryptography(),
            algorithm=self._algorithm._to_cryptography(),
            cert_status=cert_status,
            this_update=datetime.now(),
            next_update=datetime.now(),
            revocation_reason=None,
            revocation_time=self.revocation_time,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, self._cert._to_cryptography())

        return builder.sign(
            self._private_key._to_cryptography(),
            self._algorithm._to_cryptography()
        )

    def _string_dict(self) -> dict[str, str]:
        return {
            "Response Status": self.response_status,
            "Certificate Status": self.certificate_status,
            "Issuer Key Hash": self.issuer_key_hash,
        }


class OCSPRequest(CryptoParser):
    hash_algorithm: HashAlgorithm

    serial_number: Optional[int] = None
    extensions: Optional[Extensions] = None


    def from_cryptography(
        cls: Type["OCSPRequest"], crypto_obj: ocsp.OCSPRequest
    ) -> "OCSPRequest":
        return cls(
            serial_number=crypto_obj.serial_number,
            extensions=Extensions.from_cryptography(crypto_obj.extensions),
            _x590_obj=crypto_obj,
        )

    @property
    def request_path(self):
        if self._x509_obj is None:
            raise MissingOcspCert("Please use 'create' function")

        return base64.b64encode(
            self._x509_obj.public_bytes(serialization.Encoding.DER)
        ).decode()

    def create(self, cert: Certificate, issuer_cert: Certificate):
        self._cert = cert
        self._issuer = issuer_cert
        self._x509_obj = self._to_cryptography()

    def _to_cryptography(self) -> ocsp.OCSPRequest:
        if not hasattr(self, "_cert"):
            raise MissingOcspCert("Please use 'create' function")

        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            self._cert._to_cryptography(),
            self._issuer._to_cryptography(),
            self.hash_algorithm._to_cryptography(),
        )
        return builder.build()

    def _string_dict(self) -> dict:
        ret = self.hash_algorithm._string_dict()

        if self.serial_number is not None:
            ret["Serial Number"] = self.serial_number
        if self.extensions is not None:
            ret["Extensions"] = self.extensions._string_dict()

        return ret

import base64
import hashlib
import re
from datetime import datetime
from enum import Enum
from typing import Type, Optional, Dict

from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPCertStatus
from loguru import logger

from pki_tools.types.extensions import Extensions
from pki_tools.types.certificate import Certificate
from pki_tools.exceptions import (
    MissingInit,
)
from pki_tools.types.key_pair import (
    CryptoPrivateKey,
    Ed25519PrivateKey,
    Ed448PrivateKey,
)
from pki_tools.types.crypto_parser import (
    InitCryptoParser,
    CryptoConfig,
    HelperFunc,
)
from pki_tools.types.signature_algorithm import (
    HashAlgorithm,
    SignatureAlgorithm,
)
from pki_tools.types.utils import _byte_to_hex


class OcspResponseStatus(Enum):
    """
    Enumeration of OCSP response statuses.
    """

    SUCCESSFUL = "SUCCESSFUL"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    TRY_LATER = "TRY_LATER"
    SIG_REQUIRED = "SIG_REQUIRED"
    UNAUTHORIZED = "UNAUTHORIZED"


class OcspCertificateStatus(Enum):
    """
    Enumeration of OCSP certificate statuses.
    """

    GOOD = "GOOD"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


RESPONSE_REGEXP = re.compile(
    r"\s*-+BEGIN OCSP RESPONSE-+[\w+/\s=]*-+END OCSP RESPONSE-+\s*"
)


class OCSPResponse(InitCryptoParser):
    """
    Represents an OCSP response.

    Attributes:
        response_status: The OCSP response status.
        certificate_status: The OCSP certificate status.
        issuer_key_hash: The issuer key hash.
        revocation_time: The revocation time.

    --8<-- "docs/examples/ocsp_response.md"
    """

    response_status: OcspResponseStatus
    certificate_status: Optional[OcspCertificateStatus] = None
    issuer_key_hash: Optional[str] = None
    revocation_time: Optional[datetime] = None

    @classmethod
    def from_cryptography(
        cls: Type["OCSPResponse"], crypto_ocsp_response: ocsp.OCSPResponse
    ) -> "OCSPResponse":
        """
        Constructs an OCSPResponse object from a cryptography
        OCSPResponse object.

        Args:
            crypto_ocsp_response: The cryptography OCSPResponse object.

        Returns:
            OCSPResponse: The constructed OCSPResponse object.

        --8<-- "docs/examples/ocsp_response_from_cryptography.md"
        """
        response_status = crypto_ocsp_response.response_status

        ocsp_response_key_hash = None
        certificate_status = None
        revocation_time = None
        if response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
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

            if crypto_ocsp_response.revocation_time_utc is not None:
                revocation_time = crypto_ocsp_response.revocation_time_utc

        ret = cls(
            response_status=getattr(OcspResponseStatus, response_status.name),
            certificate_status=certificate_status,
            issuer_key_hash=ocsp_response_key_hash,
            revocation_time=revocation_time,
            _x509_obj=crypto_ocsp_response,
        )
        ret._x509_obj = crypto_ocsp_response
        return ret

    @property
    def tbs_bytes(self) -> bytes:
        """
        Returns the bytes to be singed of the OCSP response.

        Returns:
            bytes: The TBS bytes.
        """
        return self._crypto_object.tbs_response_bytes

    @property
    def pem_bytes(self) -> bytes:
        """
        Returns the PEM bytes of the object

        Returns:
            The PEM bytes.
        """
        ocsp_request_b64 = base64.b64encode(self.der_bytes).decode()

        # Create the PEM string with headers and footers
        return (
            "-----BEGIN OCSP RESPONSE-----\n"
            + "\n".join(
                [
                    ocsp_request_b64[i : i + 64]
                    for i in range(0, len(ocsp_request_b64), 64)
                ]
            )
            + "\n-----END OCSP RESPONSE-----\n"
        ).encode()

    def hash_with_alg(self, der_key: bytes) -> str:
        """
        Hashes a DER key bytes with the algorithm of the OCSP response.

        Args:
            der_key: The DER key.

        Returns:
            str: The hashed key.
        """

        hash_algorithm = hashlib.new(self._crypto_object.hash_algorithm.name)
        hash_algorithm.update(der_key)
        return hash_algorithm.hexdigest().upper()

    @property
    def is_successful(self) -> bool:
        """
        Checks if the OCSP response is successful.

        Returns:
            True if the response is successful, False otherwise.
        """
        return self.response_status == OcspResponseStatus.SUCCESSFUL

    @property
    def is_revoked(self) -> bool:
        """
        Checks if the certificate is revoked.

        Returns:
            True if the certificate is revoked, False otherwise.
        """
        return self.certificate_status == OcspCertificateStatus.REVOKED

    def sign(
        self,
        cert: Certificate,
        issuer: Certificate,
        response_algorithm: SignatureAlgorithm,
        private_key: CryptoPrivateKey,
        signature_algorithm: Optional[SignatureAlgorithm] = None,
    ):
        """
        Signs the OCSP response.

        Args:
            cert: The certificate.
            issuer: The issuer certificate.
            response_algorithm: The signature algorithm for the response.
            private_key: The private key to sign the response.
            signature_algorithm: The signature algorithm.
        """
        self._cert = cert
        self._issuer = issuer
        self._response_algorithm = response_algorithm
        self._private_key = private_key
        self._signature_algorithm = signature_algorithm
        self._x509_obj = self._to_cryptography()

    def _to_cryptography(self) -> ocsp.OCSPResponse:
        if not hasattr(self, "_private_key"):
            raise MissingInit(
                f"Please use OCSPResponse.{self._init_func} function"
            )

        builder = ocsp.OCSPResponseBuilder()
        cert_status = None
        if self.certificate_status is not None:
            cert_status = getattr(OCSPCertStatus, self.certificate_status.name)

        builder = builder.add_response(
            cert=self._cert._to_cryptography(),
            issuer=self._issuer._to_cryptography(),
            algorithm=self._response_algorithm.algorithm._to_cryptography(),
            cert_status=cert_status,
            this_update=datetime.now(),
            next_update=datetime.now(),
            revocation_reason=None,
            revocation_time=self.revocation_time,
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH, self._cert._to_cryptography()
        )

        if isinstance(self._private_key, Ed25519PrivateKey) or isinstance(
            self._private_key, Ed448PrivateKey
        ):
            alg = None
        else:
            alg = self._signature_algorithm.algorithm._to_cryptography()

        return builder.sign(
            self._private_key._to_cryptography(),
            alg,
        )

    def _string_dict(self) -> Dict[str, str]:
        ret = {
            "Response Status": self.response_status.value,
        }
        if self.certificate_status is not None:
            ret["Certificate Status"] = self.certificate_status.value
        if self.issuer_key_hash is not None:
            ret["Issuer Key Hash"] = self.issuer_key_hash
        if self.revocation_time is not None:
            ret["Revocation Time"] = self.revocation_time
        return ret

    @classmethod
    def _load_pem(cls, pem: bytes):
        pem_lines = pem.decode().strip().split("\n")
        base64_data = "".join(pem_lines[1:-1])
        der_bytes = base64.b64decode(base64_data)

        return ocsp.load_der_ocsp_response(der_bytes)

    @classmethod
    def _crypto_config(cls) -> CryptoConfig:
        return CryptoConfig(
            load_pem=HelperFunc(func=cls._load_pem),
            load_der=HelperFunc(func=ocsp.load_der_ocsp_response),
            pem_regexp=RESPONSE_REGEXP,
        )


REQUEST_REGEXP = re.compile(
    r"\s*-+BEGIN OCSP REQUEST-+[\w+/\s=]*-+END OCSP REQUEST-+\s*"
)


class OCSPRequest(InitCryptoParser):
    """
    Represents an OCSP request.

    Attributes:
        hash_algorithm: The hash algorithm.
        serial_number: The serial number.
        extensions: The extensions.

    --8<-- "docs/examples/ocsp_request.md"
    """

    hash_algorithm: HashAlgorithm

    serial_number: Optional[int] = None
    extensions: Optional[Extensions] = None

    _init_func = "create"

    @classmethod
    def from_cryptography(
        cls: Type["OCSPRequest"], crypto_obj: ocsp.OCSPRequest
    ) -> "OCSPRequest":
        """
        Constructs an OCSPRequest object from a cryptography OCSPRequest
        object.

        Args:
            crypto_obj: The cryptography OCSPRequest object.

        Returns:
            The constructed OCSPRequest object.

        --8<-- "docs/examples/ocsp_request_from_cryptography.md"
        """
        alg = HashAlgorithm.from_cryptography(crypto_obj.hash_algorithm)
        ret = cls(
            hash_algorithm=alg,
            serial_number=crypto_obj.serial_number,
            extensions=Extensions.from_cryptography(crypto_obj.extensions),
            _x590_obj=crypto_obj,
        )
        ret._x509_obj = crypto_obj
        return ret

    @property
    def pem_bytes(self) -> bytes:
        """
        Returns the PEM bytes of the object

        Returns:
            The PEM bytes.
        """
        ocsp_request_b64 = base64.b64encode(self.der_bytes).decode()

        return (
            "-----BEGIN OCSP REQUEST-----\n"
            + "\n".join(
                [
                    ocsp_request_b64[i : i + 64]
                    for i in range(0, len(ocsp_request_b64), 64)
                ]
            )
            + "\n-----END OCSP REQUEST-----\n"
        ).encode()

    @property
    def request_path(self) -> str:
        """
        The request path of the OCSP Response.

        Returns:
            The request path.
        """
        return base64.b64encode(self.der_bytes).decode()

    def create(self, cert: Certificate, issuer_cert: Certificate):
        """
        Creates an OCSP request.

        Args:
            cert: The certificate.
            issuer_cert: The issuer of the OCSP Response.
        """
        self._cert = cert
        self._issuer = issuer_cert
        self._x509_obj = self._to_cryptography()

    def _to_cryptography(self) -> ocsp.OCSPRequest:
        if not hasattr(self, "_cert"):
            raise MissingInit(
                f"Please use " f"OCSPRequest.{self._init_func} function"
            )

        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            self._cert._to_cryptography(),
            self._issuer._to_cryptography(),
            self.hash_algorithm._to_cryptography(),
        )
        return builder.build()

    def _string_dict(self) -> Dict:
        ret = self.hash_algorithm._string_dict()

        if self.serial_number is not None:
            ret["Serial Number"] = str(self.serial_number)
        if self.extensions is not None:
            ret["Extensions"] = self.extensions._string_dict()

        return ret

    @classmethod
    def _load_pem(cls, pem: bytes):
        pem_lines = pem.decode().strip().split("\n")
        base64_data = "".join(pem_lines[1:-1])
        der_bytes = base64.b64decode(base64_data)

        return ocsp.load_der_ocsp_request(der_bytes)

    @classmethod
    def _crypto_config(cls) -> CryptoConfig:
        return CryptoConfig(
            load_pem=HelperFunc(func=cls._load_pem),
            load_der=HelperFunc(func=ocsp.load_der_ocsp_request),
            pem_regexp=REQUEST_REGEXP,
        )

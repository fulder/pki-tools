import base64
import random
import re
from typing import Optional
import datetime

import yaml

from cryptography.hazmat.primitives import serialization

from pki_tools.types.key_pair import KeyPair, CryptoKeyPair
from pki_tools.types.name import Name
from pki_tools.types.extensions import Extensions

from pki_tools.exceptions import (
    CertLoadError,
    MissingInit,
    SignatureVerificationFailed,
)
from pki_tools.types.signature_algorithm import (
    SignatureAlgorithm,
    HashAlgorithm,
    HashAlgorithmName,
    PKCS1v15Padding,
)
from pki_tools.types.utils import _byte_to_hex, _der_key

from typing import Type

from cryptography import x509

from pydantic import BaseModel


from pki_tools.types.crypto_parser import InitCryptoParser

from loguru import logger
from pydantic import ConfigDict


PEM_CERT_REGEX = re.compile(
    r"\s*-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+\s*"
)
PEM_CSR_REGEX = re.compile(
    r"\s*-+BEGIN CERTIFICATE REQUEST-+[\w+/\s=]*-+END CERTIFICATE REQUEST-+\s*"
)
CACHE_TIME_SECONDS = 60 * 60 * 24 * 30  # 1 month


class Validity(BaseModel):
    not_before: datetime.datetime
    not_after: datetime.datetime

    def _string_dict(self):
        return {
            "Not Before": self.not_before,
            "Not After": self.not_after,
        }


class TbsCertificate(BaseModel):
    issuer: Name
    validity: Validity
    subject: Name

    extensions: Optional[Extensions] = None
    serial_number: Optional[int] = None
    version: Optional[int] = None
    signature_algorithm: Optional[SignatureAlgorithm] = None
    subject_public_key_info: Optional[KeyPair] = None

    def _string_dict(self):
        subject_key_info = self.subject_public_key_info._string_dict()
        signature_alg = self.signature_algorithm.algorithm.name.value
        return {
            "Version": self.version,
            "Serial Number": self.hex_serial,
            "Signature Algorithm": signature_alg,
            "Issuer": str(self.issuer),
            "Validity": self.validity._string_dict(),
            "Subject": str(self.subject),
            "Subject Public Key Info": subject_key_info,
            "Extensions": self.extensions._string_dict(),
        }


class Certificate(TbsCertificate, InitCryptoParser):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    signature_value: Optional[str] = None

    _private_key: Optional[CryptoKeyPair]

    @classmethod
    def from_cryptography(
        cls: Type["Certificate"],
        cert: x509.Certificate,
    ) -> "Certificate":
        ret = cls(
            version=cert.version.value,
            serial_number=cert.serial_number,
            signature_algorithm=SignatureAlgorithm.from_cryptography(
                cert.signature_hash_algorithm,
                cert.signature_algorithm_parameters,
            ),
            issuer=Name.from_cryptography(cert.issuer),
            validity=Validity(
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
            ),
            subject=Name.from_cryptography(cert.subject),
            subject_public_key_info=KeyPair.from_cryptography(
                cert.public_key()
            ),
            extensions=Extensions.from_cryptography(cert.extensions),
            signature_value=_byte_to_hex(cert.signature),
            _x509_obj=cert,
        )
        ret._x509_obj = cert
        return ret

    @classmethod
    def from_pem_string(cls: Type["Certificate"], cert_pem) -> "Certificate":
        """
        Loads a certificate from a PEM string into a
        [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
        object

        Arguments:
            cert_pem -- The PEM encoded certificate in string format
        Returns:
            A
            [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
            created from the PEM
        Raises:
             exceptions.CertLoadError - If the certificate could not be loaded
        """
        try:
            cert_pem = re.sub(r"\n\s*", "\n", cert_pem)
            if not _is_pem_cert_string(cert_pem):
                raise ValueError

            crypto_cert = x509.load_pem_x509_certificate(cert_pem.encode())
            return Certificate.from_cryptography(crypto_cert)
        except ValueError as e:
            logger.bind(cert=cert_pem).debug("Failed to load cert from PEM")
            raise CertLoadError(e)

    @classmethod
    def from_file(cls: Type["Certificate"], file_path: str) -> "Certificate":
        """
        Reads a file containing one PEM certificate into a
        [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
        object

        Arguments:
            file_path -- Path and filename of the PEM certificate
        Returns:
             The
             [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
             representing the certificate from file
        """

        with open(file_path, "r") as f:
            cert_pem = f.read()

        return Certificate.from_pem_string(cert_pem)

    @property
    def tbs_bytes(self) -> bytes:
        return self._crypto_object.tbs_certificate_bytes

    @property
    def pem_bytes(self) -> bytes:
        return self._crypto_object.public_bytes(serialization.Encoding.PEM)

    @property
    def pem_string(self) -> str:
        return self.pem_bytes.decode()

    @property
    def hex_serial(self) -> str:
        """
        Parses the certificate serial into hex format

        Returns:
            String representing the hex value of the certificate serial number
        """
        hex_serial = format(self.serial_number, "x").zfill(32)
        return hex_serial.upper()

    @property
    def public_key(self) -> bytes:
        return self._crypto_object.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def sign_alg_oid_name(self) -> str:
        name = self._crypto_object.signature_algorithm_oid._name.upper()
        return name.replace("ENCRYPTION", "")

    @property
    def der_public_key(self) -> bytes:
        return _der_key(self._crypto_object.public_key())

    def digest(
        self,
        algorithm: HashAlgorithm = HashAlgorithm(
            name=HashAlgorithmName.SHA512
        ),
    ):
        fingerprint = self._crypto_object.fingerprint(
            algorithm._to_cryptography()
        )
        return base64.urlsafe_b64encode(fingerprint).decode("ascii")

    def to_file(self, file_path):
        with open(file_path, "w") as f:
            f.write(self.pem_string)

    def verify_signature(
        self: Type["Certificate"],
        signed: InitCryptoParser,
    ) -> None:
        """
        Verifies a signature of a signed entity against this issuer certificate

        Args:
            signed: The signed entity can either be a
            [Certificate](https://pki-tools.fulder.dev/pki_tools/types/#certificate)
            [CertificateRevocationList](https://pki-tools.fulder.dev/pki_tools/types/#certificaterevocationlist)
            or a
            [OCSPResponse](https://pki-tools.fulder.dev/pki_tools/types/#ocspresponse)
        Raises:
            [InvalidSignedType](https://pki-tools.fulder.dev/pki_tools/exceptions/#invalidsignedtype)
            -- When the issuer has a non-supported type
            [SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
            -- When the signature verification fails
        """
        try:
            self._crypto_object.public_key().verify(
                signed._crypto_object.signature,
                signed.tbs_bytes,
                PKCS1v15Padding()._to_cryptography(),
                signed._crypto_object.signature_hash_algorithm,
            )
            logger.trace("Signature valid")
        except Exception as e:
            logger.bind(
                exceptionType=type(e).__name__,
                exception=str(e),
            ).error("Signature verification failed")
            raise SignatureVerificationFailed(
                f"signature doesn't match issuer "
                f"with subject: {str(self.subject)}"
            )

    def sign(
        self, key_pair: CryptoKeyPair, signature_algorithm: SignatureAlgorithm
    ):
        self._private_key = key_pair
        self.serial_number = random.randint(1, 2**32 - 1)
        self.signature_algorithm = signature_algorithm
        self._x509_obj = self._to_cryptography()

    def __str__(self) -> str:
        return yaml.safe_dump(
            self._string_dict(),
            indent=2,
            default_flow_style=False,
            explicit_start=True,
            default_style="",
        )

    def _to_cryptography(self) -> x509.Certificate:
        if hasattr(self, "_x509_obj"):
            return self._x509_obj

        if not hasattr(self, "_private_key"):
            raise MissingInit(
                f"Please use Certificate.{self._init_func} " f"function"
            )

        subject = issuer = self.subject._to_cryptography()
        crypto_key = self._private_key._to_cryptography()
        if not hasattr(crypto_key, "public_key"):
            raise MissingInit("Invalid key type, use private key")

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(
                subject,
            )
            .issuer_name(
                issuer,
            )
            .serial_number(
                x509.random_serial_number(),
            )
            .public_key(
                crypto_key.public_key(),
            )
            .not_valid_before(
                self.validity.not_before,
            )
            .not_valid_after(
                self.validity.not_after,
            )
        )

        if self.extensions is not None:
            for extension in self.extensions:
                cert_builder = cert_builder.add_extension(
                    extension._to_cryptography(), extension.critical
                )

        alg = self.signature_algorithm.algorithm._to_cryptography()
        cert = cert_builder.sign(crypto_key, alg)

        return cert

    def _string_dict(self):
        return {
            "Certificate": {
                "TbsCertificate": super()._string_dict(),
                "Signature Value": self.signature_value,
            }
        }


def _is_pem_cert_string(check: str):
    if not isinstance(check, str):
        return False

    return re.match(PEM_CERT_REGEX, check)


def _is_pem_csr_string(check: str):
    if not isinstance(check, str):
        return False

    return re.match(PEM_CSR_REGEX, check)

import base64
import random
import re
import time
from typing import Optional, Dict
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
from pki_tools.types.utils import (
    _byte_to_hex,
    _der_key,
    CertsUri,
    CACHE_TIME_SECONDS,
    _download_server_certificate,
    _download_pem,
)

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


class Validity(BaseModel):
    """
    Describes the validity of a certificate

    Attributes:
        not_before: The start date of when the certificate will be valid
        not_after: The date of when the certificate expires
    """

    not_before: datetime.datetime
    not_after: datetime.datetime

    def _string_dict(self) -> Dict[str, str]:
        return {
            "Not Before": str(self.not_before),
            "Not After": str(self.not_after),
        }


class Certificate(InitCryptoParser):
    """
    An object describing a x509 Certificate

    Attributes:
        issuer: Certificate issuer
        subject: Certificate subject
        validity: Contains information about NotBefore and NotAfter

        extensions: Certificate (v3) extensions
        serial_number: Serial number
        version: The version of the certificate
        signature_algorithm: Describes the algorithm used to sign the
            certificate
        subject_public_key_info: The public key information
    """

    issuer: Name
    validity: Validity
    subject: Name

    extensions: Optional[Extensions] = None
    serial_number: Optional[int] = None
    version: Optional[int] = None
    signature_algorithm: Optional[SignatureAlgorithm] = None
    subject_public_key_info: Optional[KeyPair] = None

    signature_value: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    _private_key: Optional[CryptoKeyPair]

    @classmethod
    def from_cryptography(
        cls: Type["Certificate"],
        cert: x509.Certificate,
    ) -> "Certificate":
        """
        Create a Certificate object from a [cryptography.x509.Certificate][]
        object.

        Args:
            cert: The [cryptography.x509.Certificate][] object.

        Returns:
            Certificate: The created Certificate object.
        """

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
    def from_pem_string(
        cls: Type["Certificate"], cert_pem: str
    ) -> "Certificate":
        """
        Loads a certificate from a PEM string into a
        [Certificate][pki_tools.types.certificate.Certificate]
        object

        Arguments:
            cert_pem: The PEM encoded certificate in string format

        Returns:
            A Certificate created from the PEM

        Raises:
            CertLoadError: If the certificate could not be loaded
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
        [Certificate][pki_tools.types.certificate.Certificate]
        object

        Arguments:
            file_path:  Path and filename of the PEM certificate

        Returns:
             The Certificate loaded from the specified file
        """

        with open(file_path, "r") as f:
            cert_pem = f.read()

        return Certificate.from_pem_string(cert_pem)

    @classmethod
    def from_server(
        cls: Type["Certificate"],
        uri: str,
        cache_time_seconds: int = CACHE_TIME_SECONDS,
    ) -> "Certificate":
        """
        Loads a server certificate from a URI

        Args:
            uri: The https URI of the server containing the certificate
            cache_time_seconds: How long the request should be cached in memory

        Returns:
            The loaded [Certificate][pki_tools.types.certificate] object
        """
        cert_uri = CertsUri(uri=uri, cache_time_seconds=cache_time_seconds)

        cache_ttl = round(time.time() / cert_uri.cache_time_seconds)
        pem = _download_server_certificate(cert_uri.hostname, cache_ttl)
        return Certificate.from_pem_string(pem)

    @classmethod
    def from_uri(
        cls: Type["Certificate"],
        uri: str,
        cache_time_seconds: int = CACHE_TIME_SECONDS,
    ) -> "Certificate":
        """
        Loads Certificates from a URI.

        Args:
            uri: URI where the certificate can be downloaded.
            cache_time_seconds: Specifies how long the certificate
                should be cached, default is 1 month.
                Defaults to CACHE_TIME_SECONDS.

        Returns:
            Instance of Certificate containing the certificates
            fetched from the URI.
        """

        cache_ttl = round(time.time() / cache_time_seconds)
        cert_uri = CertsUri(uri=uri)
        pem = _download_pem(cert_uri.uri, cache_ttl)

        return Certificate.from_pem_string(pem)

    @property
    def tbs_bytes(self) -> bytes:
        """
        Returns:
            The to be signed bytes of this certificate
        """
        return self._crypto_object.tbs_certificate_bytes

    @property
    def pem_bytes(self) -> bytes:
        """
        Returns:
            Certificate PEM bytes
        """
        return self._crypto_object.public_bytes(serialization.Encoding.PEM)

    @property
    def pem_string(self) -> str:
        """
        Returns:
            Certificate PEM decoded into a string
        """
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
        """
        Returns:
            The bytes of the public key in PEM format
        """
        return self._crypto_object.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def sign_alg_oid_name(self) -> str:
        """
        Returns:
            The name of the signature algorithm such as: `SHA512WITHRSA`
        """
        name = self._crypto_object.signature_algorithm_oid._name.upper()
        return name.replace("ENCRYPTION", "")

    @property
    def der_public_key(self) -> bytes:
        """
        Returns:
            The bytes of the public key in DER format
        """
        return _der_key(self._crypto_object.public_key())

    def digest(
        self,
        algorithm: HashAlgorithm = HashAlgorithm(
            name=HashAlgorithmName.SHA512
        ),
    ) -> str:
        """
        Gets the base64 encoded fingerprint of the certificate

        Args:
            algorithm: The algorithm to use to hash the fingerprint with

        Returns:
            Hashed and base64 encoded certificate fingerprint
        """
        fingerprint = self._crypto_object.fingerprint(
            algorithm._to_cryptography()
        )
        return base64.urlsafe_b64encode(fingerprint).decode("ascii")

    def to_file(self, file_path: str) -> None:
        """
        Saves the certificate PEM string to the specified file,
        creating it if it doesn't exist.

        Args:
            file_path: The path to the file (can be relative the caller or
                absolute)
        """
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
                [Certificate][pki_tools.types.certificate.Certificate],
                [CertificateRevocationList][pki_tools.types.crl.CertificateRevocationList]
                or a [OCSPResponse][pki_tools.types.ocsp.OCSPResponse]

        Raises:
            InvalidSignedType: When the issuer has a non-supported type
            SignatureVerificationFailed: When the signature verification fails
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
        self,
        key_pair: CryptoKeyPair,
        signature_algorithm: SignatureAlgorithm,
        req_key: Optional[CryptoKeyPair] = None,
    ) -> None:
        """
        Signs a created [Certificate][pki_tools.types.certificate.Certificate]
        object with a given
        [CryptoKeyPair][pki_tools.types.key_pair.CryptoKeyPair]

        Args:
            key_pair: Keypair containing the private key to sing the
                certificate with
            signature_algorithm: Algorithm to use for the signature
            req_key: Can be used to sign another public key, defaults to the
                public key part in `key_pair`
        """
        self._private_key = key_pair
        self.serial_number = random.randint(1, 2**32 - 1)
        self.signature_algorithm = signature_algorithm

        if req_key is not None:
            self.subject_public_key_info = KeyPair(
                algorithm=req_key.__class__.__name__,
                parameters=req_key._string_dict(),
            )
            self.subject_public_key_info.create(req_key)

        self._x509_obj = self._to_cryptography()

    def __str__(self) -> str:
        return yaml.safe_dump(
            self._string_dict(),
            indent=2,
            default_flow_style=False,
            explicit_start=False,
            default_style="",
        )

    def _to_cryptography(self) -> x509.Certificate:
        if hasattr(self, "_x509_obj"):
            return self._x509_obj

        if not hasattr(self, "_private_key"):
            raise MissingInit(
                f"Please use Certificate.{self._init_func} " f"function"
            )

        subject = self.subject._to_cryptography()
        issuer = self.issuer._to_cryptography()
        crypto_key = self._private_key._to_cryptography()
        if not hasattr(crypto_key, "public_key"):
            raise MissingInit("Invalid key type, use private key")

        public_key = crypto_key.public_key()
        if self.subject_public_key_info is not None:
            pub_key_pair = self.subject_public_key_info._key_pair
            public_key = pub_key_pair._to_cryptography().public_key()

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
            .public_key(public_key)
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
            "Signature Value": self.signature_value,
        }


def _is_pem_cert_string(check: str):
    if not isinstance(check, str):
        return False

    return re.match(PEM_CERT_REGEX, check)


def _is_pem_csr_string(check: str):
    if not isinstance(check, str):
        return False

    return re.match(PEM_CSR_REGEX, check)

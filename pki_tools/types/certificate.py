import base64
import random
import re
import time
from typing import Optional, Dict
import datetime


from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from pki_tools.types.key_pair import (
    CryptoKeyPair,
    CryptoPublicKey,
    Ed448PublicKey,
    Ed25519PublicKey,
)
from pki_tools.types.name import Name
from pki_tools.types.extensions import Extensions

from pki_tools.exceptions import (
    MissingInit,
    SignatureVerificationFailed,
)
from pki_tools.types.signature_algorithm import (
    SignatureAlgorithm,
    HashAlgorithm,
    HashAlgorithmName,
)
from pki_tools.types.utils import (
    _byte_to_hex,
    CertsUri,
    CACHE_TIME_SECONDS,
    _download_server_certificate,
    _download_cached,
)

from typing import Type

from cryptography import x509

from pydantic import BaseModel


from pki_tools.types.crypto_parser import (
    InitCryptoParser,
    CryptoConfig,
    HelperFunc,
    CryptoParser,
)

from loguru import logger
from pydantic import ConfigDict


PEM_CERT_REGEX = re.compile(
    r"\s*-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+\s*"
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

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        if self.not_before.tzinfo is None:
            self.not_before = self.not_before.replace(
                tzinfo=datetime.timezone.utc
            )
        if self.not_after.tzinfo is None:
            self.not_after = self.not_after.replace(
                tzinfo=datetime.timezone.utc
            )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "Not Before": str(self.not_before),
            "Not After": str(self.not_after),
        }


class SubjectPublicKeyInfo(CryptoParser):
    """
    Represents a certificate SubjectPublicKeyInfo.

    Attributes:
        algorithm: The key algorithm in string format
        parameters: The dict representation of the key
    """

    algorithm: CryptoPublicKey
    parameters: Optional[Dict[str, str]]

    @classmethod
    def from_cryptography(
        cls: Type["SubjectPublicKeyInfo"],
        crypto_obj: CertificatePublicKeyTypes,
    ) -> "SubjectPublicKeyInfo":
        public_key = CryptoPublicKey.from_cryptography(crypto_obj)

        return cls(
            algorithm=public_key,
            parameters=public_key._string_dict(),
            _x509_obj=crypto_obj,
        )

    def _to_cryptography(self) -> CertificatePublicKeyTypes:
        return self.algorithm._to_cryptography()

    def _string_dict(self) -> Dict:
        params = {}
        for k, v in self.parameters.items():
            key = " ".join(ele.title() for ele in k.split("_"))
            if v == "None":
                continue

            params[key] = v

        return {
            "Public Key Algorithm": self.algorithm._string_dict(),
            "Parameters": params,
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

    --8<-- "docs/examples/certificate.md"
    """

    issuer: Name
    validity: Validity
    subject: Name

    extensions: Optional[Extensions] = None
    serial_number: Optional[int] = None
    version: Optional[int] = None
    signature_algorithm: Optional[SignatureAlgorithm] = None
    subject_public_key_info: Optional[SubjectPublicKeyInfo] = None

    signature_value: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    _key_pair: Optional[CryptoKeyPair]

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

        --8<-- "docs/examples/certificate_from_cryptography.md"
        """
        extensions = None
        if cert.extensions:
            extensions = Extensions.from_cryptography(cert.extensions)

        signature_algorithm = None
        if cert.signature_hash_algorithm:
            signature_algorithm = SignatureAlgorithm.from_cryptography(
                cert.signature_hash_algorithm,
                cert.signature_algorithm_parameters,
            )

        ret = cls(
            version=cert.version.value,
            serial_number=cert.serial_number,
            signature_algorithm=signature_algorithm,
            issuer=Name.from_cryptography(cert.issuer),
            validity=Validity(
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
            ),
            subject=Name.from_cryptography(cert.subject),
            subject_public_key_info=SubjectPublicKeyInfo.from_cryptography(
                cert.public_key()
            ),
            extensions=extensions,
            signature_value=_byte_to_hex(cert.signature),
            _x509_obj=cert,
        )
        ret._x509_obj = cert
        return ret

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

        --8<-- "docs/examples/certificate_from_server.md"
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

        Returns:
            Instance of Certificate containing the certificates
            fetched from the URI.

        --8<-- "docs/examples/certificate_from_uri.md"
        """

        cache_ttl = round(time.time() / cache_time_seconds)
        cert_uri = CertsUri(uri=uri)
        res = _download_cached(cert_uri.uri, cache_ttl)

        return Certificate.from_pem_string(res.text)

    @property
    def tbs_bytes(self) -> bytes:
        """
        Returns:
            The to be signed bytes of this certificate
        """
        return self._crypto_object.tbs_certificate_bytes

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
        return self.subject_public_key_info.algorithm.pem_bytes

    @property
    def sign_alg_oid_name(self) -> str:
        """
        Returns:
            The name of the signature algorithm such as: `SHA512WITHRSA`
        """
        name = self._crypto_object.signature_algorithm_oid._name.upper()
        return name.replace("ENCRYPTION", "")

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
            self.subject_public_key_info.algorithm.verify(signed)
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
        signature_algorithm: Optional[SignatureAlgorithm] = None,
        req_key: Optional[CryptoPublicKey] = None,
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
        self._key_pair = key_pair
        self.serial_number = random.randint(1, 2**32 - 1)
        self.signature_algorithm = signature_algorithm

        if req_key is None:
            req_key = key_pair.public_key

        self.subject_public_key_info = SubjectPublicKeyInfo(
            algorithm=req_key,
            parameters=req_key._string_dict(),
        )

        self._x509_obj = self._to_cryptography()

    def _to_cryptography(self) -> x509.Certificate:
        if hasattr(self, "_x509_obj"):
            return self._x509_obj

        if not hasattr(self, "_key_pair"):
            raise MissingInit(
                f"Please use Certificate.{self._init_func} " f"function"
            )

        subject = self.subject._to_cryptography()
        issuer = self.issuer._to_cryptography()
        crypto_key = self._key_pair.private_key._to_cryptography()

        alg = self.subject_public_key_info.algorithm
        public_key = alg._to_cryptography()

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

        if isinstance(
            self.subject_public_key_info.algorithm, Ed448PublicKey
        ) or isinstance(
            self.subject_public_key_info.algorithm, Ed25519PublicKey
        ):
            alg = None
        else:
            alg = self.signature_algorithm.algorithm._to_cryptography()

        cert = cert_builder.sign(crypto_key, alg)

        return cert

    def _string_dict(self):
        ret = {
            "Issuer": str(self.issuer),
            "Validity": self.validity._string_dict(),
            "Subject": str(self.subject),
        }
        if self.version is not None:
            ret["Version"] = self.version
        if self.extensions:
            ret["Extensions"] = self.extensions._string_dict()
        if self.serial_number is not None:
            ret["Serial Number"] = self.hex_serial
        if self.signature_value is not None:
            ret["Signature Value"] = self.signature_value
        if self.subject_public_key_info is not None:
            subject_key_info = self.subject_public_key_info._string_dict()
            ret["Subject Public Key Info"] = subject_key_info
        if self.signature_algorithm is not None:
            signature_alg = self.signature_algorithm.algorithm.name.value
            ret["Signature Algorithm"] = signature_alg

        return ret

    @classmethod
    def _crypto_config(cls) -> CryptoConfig:
        return CryptoConfig(
            load_pem=HelperFunc(func=x509.load_pem_x509_certificate),
            load_der=HelperFunc(func=x509.load_der_x509_certificate),
            pem_regexp=PEM_CERT_REGEX,
        )

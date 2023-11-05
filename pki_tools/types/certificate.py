import re
from typing import Union, Optional, Dict

import yaml

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, dsa, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from pki_tools.types.name import Name
from pki_tools.types.extensions import Extensions

from pki_tools.exceptions import CertLoadError
from pki_tools.types.utils import _byte_to_hex

from typing import Type

from cryptography import x509

from pydantic import BaseModel


from pki_tools.types.crypto_parser import CryptoParser

from datetime import datetime

from loguru import logger
from pydantic import ConfigDict


PEM_REGEX = re.compile(
    r"\s*-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+\s*"
)
CACHE_TIME_SECONDS = 60 * 60 * 24 * 30  # 1 month


class SignatureAlgorithm(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    algorithm: hashes.HashAlgorithm
    parameters: Union[None, padding.PSS, padding.PKCS1v15, ec.ECDSA] = None


class Validity(BaseModel):
    not_before: datetime
    not_after: datetime

    def _string_dict(self):
        return {
            "Not Before": self.not_before,
            "Not After": self.not_after,
        }


class SubjectPublicKeyInfo(CryptoParser):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    algorithm: str
    parameters: Dict[str, str]

    @classmethod
    def from_cryptography(cls, cert_public_key: CertificatePublicKeyTypes):
        name = str(cert_public_key.__class__).split(".")[-2].upper()
        parameters = {}
        if isinstance(cert_public_key, dsa.DSAPublicKey):
            pub_numbers = cert_public_key.public_numbers()
            param_numbers = pub_numbers.parameter_numbers
            parameters = {
                "key_size": str(cert_public_key.key_size),
                "public_key_y": pub_numbers.y,
                "prime_p": param_numbers.p,
                "subprime_q": param_numbers.q,
                "generator_g": param_numbers.g,
            }
        elif isinstance(cert_public_key, rsa.RSAPublicKey):
            pub_numbers = cert_public_key.public_numbers()
            parameters = {
                "key_size": str(cert_public_key.key_size),
                "modulus_n": str(pub_numbers.n),
                "exponent_e": str(pub_numbers.e),
            }
        elif isinstance(cert_public_key, ec.EllipticCurvePublicKey):
            pub_numbers = cert_public_key.public_numbers()
            parameters = {
                "key_size": str(cert_public_key.key_size),
                "x_coordinate": str(pub_numbers.x),
                "y_coordinate": str(pub_numbers.y),
                "curve": pub_numbers.curve.name,
            }

        return cls(algorithm=name, parameters=parameters)

    def _string_dict(self):
        params = {}
        for k, v in self.parameters.items():
            key = " ".join(ele.title() for ele in k.split("_"))
            params[key] = v

        return {"Public Key Algorithm": self.algorithm, "Parameters": params}


class TbsCertificate(BaseModel):
    version: int
    serial_number: int
    signature_algorithm: SignatureAlgorithm
    issuer: Name
    validity: Validity
    subject: Name
    subject_public_key_info: SubjectPublicKeyInfo
    extensions: Optional[Extensions]

    def _string_dict(self):
        return {
            "Version": self.version,
            "Serial Number": self.hex_serial,
            "Signature Algorithm": self.signature_algorithm.algorithm.name,
            "Issuer": str(self.issuer),
            "Validity": self.validity._string_dict(),
            "Subject": str(self.subject),
            "Subject Public Key Info": self.subject_public_key_info._string_dict(),
            "Extensions": self.extensions._string_dict(),
        }

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
        return self.subject_public_key_info.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )


class Certificate(TbsCertificate, CryptoParser):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    signature_value: str

    @classmethod
    def from_cryptography(
        cls: Type["Certificate"], cert: x509.Certificate
    ) -> "Certificate":
        ret = cls(
            version=cert.version.value,
            serial_number=cert.serial_number,
            signature_algorithm=SignatureAlgorithm(
                algorithm=cert.signature_hash_algorithm,
                parameters=cert.signature_algorithm_parameters,
            ),
            issuer=Name.from_cryptography(cert.issuer),
            validity=Validity(
                not_before=cert.not_valid_before,
                not_after=cert.not_valid_after,
            ),
            subject=Name.from_cryptography(cert.subject),
            subject_public_key_info=SubjectPublicKeyInfo.from_cryptography(
                cert.public_key()
            ),
            extensions=Extensions.from_cryptography(cert.extensions),
            signature_value=_byte_to_hex(cert.signature),
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
            if not _is_pem_string(cert_pem):
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
        return self._x509_obj.tbs_certificate_bytes

    def to_file(self, file_path):
        with open(file_path, "w") as f:
            f.write(self.pem_string)

    def _string_dict(self):
        return {
            "Certificate": {
                "TbsCertificate": super()._string_dict(),
                "Signature Value": self.signature_value,
            }
        }

    @property
    def pem_string(self):
        return self._x509_obj.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def public_key(self) -> CertificatePublicKeyTypes:
        return self._x509_obj.public_key()

    def __str__(self) -> str:
        return yaml.safe_dump(
            self._string_dict(),
            indent=2,
            default_flow_style=False,
            explicit_start=True,
            default_style="",
        )


def _is_pem_string(check: str):
    if not isinstance(check, str):
        return False

    return re.match(PEM_REGEX, check)

from datetime import datetime
from typing import Union, Optional

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, dsa, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from pydantic import BaseModel, ConfigDict

from pki_tools.types.certificate.name import Name
from pki_tools.types.certificate.extensions import Extensions
from pki_tools.types import _byte_to_hex


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


class SubjectPublicKeyInfo(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    algorithm: str
    parameters: dict[str, str]

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


class Certificate(TbsCertificate):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    signature_value: str

    @classmethod
    def parse_certificate(cls, cert: x509.Certificate):
        return cls(
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

    def _string_dict(self):
        return {
            "Certificate": {
                "TbsCertificate": super()._string_dict(),
                "Signature Value": self.signature_value,
            }
        }

    def __str__(self) -> str:
        return yaml.safe_dump(
            self._string_dict(),
            indent=2,
            default_flow_style=False,
            explicit_start=True,
            default_style="",
        )

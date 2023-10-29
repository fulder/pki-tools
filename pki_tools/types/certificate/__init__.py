from datetime import datetime
from typing import Union, Optional


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

    def __str__(self):
        return f"""Validity:
            Not Before: {self.not_before}
            Not After: {self.not_after}"""


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

    def __str__(self):
        params = ""
        for k, v in self.parameters.items():
            key = " ".join(ele.title() for ele in k.split("_"))
            params += f"""
                {key}: {v}"""

        return f"""
            Public Key Algorithm: {self.algorithm}
            Parameters: {params}"""


class TbsCertificate(BaseModel):
    version: int
    serial_number: int
    signature_algorithm: SignatureAlgorithm
    issuer: Name
    validity: Validity
    subject: Name
    subject_public_key_info: SubjectPublicKeyInfo
    extensions: Optional[Extensions]

    def __str__(self):
        return f"""
        Version: {self.version}
        Serial Number: {self.hex_serial}
        Signature Algorithm: {self.signature_algorithm.algorithm.name}
        Issuer: {self.issuer}
        {self.validity}
        {self.subject}
        Subject Public Key Info: {self.subject_public_key_info}
        Extensions: {self.extensions}
        Signature Algorithm: {self.signature_algorithm.algorithm.name}"""

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
            signature_value=_byte_to_hex(cert.signature)
        )

    def __str__(self) -> str:
        return f"""
Certificate:
    TbsCertificate:{super().__str__()}
    Signature Value: {self.signature_value}"""


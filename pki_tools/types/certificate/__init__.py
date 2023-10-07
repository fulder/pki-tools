import binascii
import re
import time
import typing
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from typing import List, Type, Union, Optional, ClassVar

import requests
from cryptography import x509
from cryptography.hazmat._oid import NameOID, ExtensionOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, dsa, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from cryptography.x509.extensions import (
    Extensions as x509Extensions,
    AuthorityKeyIdentifier as x509AuthorityKeyIdentifier,
    ExtensionNotFound,
    ExtensionTypeVar,
)
from cryptography.x509.ocsp import OCSPResponse
from loguru import logger
from pydantic import constr, BaseModel, Field, ConfigDict

import pki_tools
from pki_tools import exceptions
from pki_tools.types.certificate.extensions import Extensions
from pki_tools.types import _is_pem_str, PemCert


class Subject(BaseModel):
    """
    Subject type describes certificate subject or issuer.
    The attributes are following the
    [RFC5280#Section-4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4)

    Note that every attribute is a list of string in order to support
    multivalued RDNs.

    Attributes:
        c -- Country Name (2.5.4.6)
        o -- Organization Name (2.5.4.10)
        ou -- Organizational Unit Name (2.5.4.11)
        dnq -- Distinguished Name Qualifier (2.5.4.46)
        s -- State Or Province Name (2.5.4.8)
        cn -- Common Name (2.5.4.3)
        serial -- Serial Number (2.5.4.5)
        ln -- Locality Name (2.5.4.7)
        t -- Title (2.5.4.12)
        sn -- Surname (2.5.4.4)
        gn -- Given Name (2.5.4.42)
        i -- Initials (2.5.4.43)
        p -- Pseudonym (2.5.4.65)
        gq -- Generation Qualifier (2.5.4.44)
        dc -- Domain Component (0.9.2342.19200300.100.1.25)
    """

    model_config = ConfigDict(populate_by_name=True)

    c: List[str] = Field(alias=NameOID.COUNTRY_NAME.dotted_string, default=[])
    o: List[str] = Field(
        alias=NameOID.ORGANIZATION_NAME.dotted_string, default=[]
    )
    ou: List[str] = Field(
        alias=NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, default=[]
    )
    dnq: List[str] = Field(
        alias=NameOID.DN_QUALIFIER.dotted_string, default=[]
    )
    s: List[str] = Field(
        alias=NameOID.STATE_OR_PROVINCE_NAME.dotted_string, default=[]
    )
    cn: List[str] = Field(alias=NameOID.COMMON_NAME.dotted_string, default=[])
    serial: List[str] = Field(
        alias=NameOID.SERIAL_NUMBER.dotted_string, default=[]
    )

    ln: List[str] = Field(
        alias=NameOID.LOCALITY_NAME.dotted_string, default=[]
    )
    t: List[str] = Field(alias=NameOID.TITLE.dotted_string, default=[])
    sn: List[str] = Field(alias=NameOID.SURNAME.dotted_string, default=[])
    gn: List[str] = Field(alias=NameOID.GIVEN_NAME.dotted_string, default=[])
    i: List[str] = Field(alias=NameOID.INITIALS.dotted_string, default=[])
    p: List[str] = Field(alias=NameOID.PSEUDONYM.dotted_string, default=[])
    gq: List[str] = Field(
        alias=NameOID.GENERATION_QUALIFIER.dotted_string, default=[]
    )
    dc: List[str] = Field(
        alias=NameOID.DOMAIN_COMPONENT.dotted_string, default=[]
    )

    @classmethod
    def from_cryptography(cls, name: x509.Name):
        subject = defaultdict(set)
        for attribute in name:
            for att in name.get_attributes_for_oid(attribute.oid):
                subject[att.oid.dotted_string].add(att.value)
        return cls(**subject)

    def to_crypto_name(self) -> x509.Name:
        name_list = []
        for attr_name in vars(self):
            vals = getattr(self, attr_name)
            if not vals:
                continue

            oid = Subject.model_fields[attr_name].alias
            for val in vals:
                name_list.append(
                    x509.NameAttribute(x509.ObjectIdentifier(oid), val)
                )

        return x509.Name(name_list)

    def __str__(self):
        attrs = []
        for a in self.model_dump():
            for val in getattr(self, a):
                attrs.append(f"{a.upper()} = {val}")
        subject_str = ", ".join(attrs)
        return f"Subject: {subject_str}"


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
    issuer: Subject
    validity: Validity
    subject: Subject
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


class Certificate(TbsCertificate):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    signature_value: str

    @classmethod
    def parse_certificate(cls, cert: [x509.Certificate, PemCert]):
        if _is_pem_str(cert):
            cert = pki_tools.cert_from_pem(cert)

        return cls(
            version=cert.version.value,
            serial_number=cert.serial_number,
            signature_algorithm=SignatureAlgorithm(
                algorithm=cert.signature_hash_algorithm,
                parameters=cert.signature_algorithm_parameters,
            ),
            issuer=Subject.from_cryptography(cert.issuer),
            validity=Validity(
                not_before=cert.not_valid_before,
                not_after=cert.not_valid_after,
            ),
            subject=Subject.from_cryptography(cert.subject),
            subject_public_key_info=SubjectPublicKeyInfo.from_cryptography(
                cert.public_key()
            ),
            extensions=Extensions.from_cryptography(cert.extensions),
            signature_value=binascii.hexlify(cert.signature).decode(),
        )

    def __str__(self) -> str:
        return f"""
Certificate:
    TbsCertificate:{super().__str__()}
    Signature Value: {self.signature_value}"""

    @property
    def hex_serial(self) -> str:
        """
        Parses the certificate serial into hex format

        Returns:
            String representing the hex value of the certificate serial number
        """
        hex_serial = format(self.serial_number, "x").zfill(32)
        return hex_serial

    @property
    def public_key(self) -> bytes:
        return self.subject_public_key_info.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

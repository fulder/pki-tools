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


class PemCert(str):
    """
    PemCert is a string containing the PEM formatted certificate

    Example:
    ::
        PemCert(
            \"\"\"
            -----BEGIN CERTIFICATE-----
            MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
            MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC
            VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx
            NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD
            TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu
            ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j
            V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj
            gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA
            FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE
            CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS
            BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE
            BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju
            Wm7DCfrPNGVwFWUQOmsPue9rZBgO
            -----END CERTIFICATE-----
            \"\"\"
        )
    """


PEM_REGEX = re.compile(
    r"\s*-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+\s*"
)
CACHE_TIME_SECONDS = 60 * 60 * 24 * 30  # 1 month


class ChainUri(BaseModel):
    """
    Describes the CA chain URI where the public certificate(s)
    can be downloaded

    Examples::
        ChainUri(uri="https://my.ca.link.com/ca.pem")
    Attributes:
        uri -- The URI for the public CA certificate(s)
        cache_time_seconds -- Specifies how long the public cert should be
        cached, default is 1 month.
    """

    uri: constr(pattern=r"https*://.*")
    cache_time_seconds: int = CACHE_TIME_SECONDS


class Chain(BaseModel):
    """
    Chain holds a list of certificates in a
    [chain of trust](https://en.wikipedia.org/wiki/Chain_of_trust)

    Attributes:
        certificates -- list of
        [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
    Examples:
    From File::
        chain = Chain.from_fle("/path/to/chain.pem")
    From PEM::
        pem_string="-----BEGIN CERTIFICATE-----...."
        chain = Chain.from_pem_str(pem_string)
    From URI::
        chain = Chain.from_uri("https://chain.domain/chain.pem")
    Using Chain::
        cert: x509.Certificate = ...
        chain.check_chain()
        chain.get_issuer(cert)
    """

    certificates: List[x509.Certificate]

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def check_chain(self):
        """
        Validate the chain (if it contains more than one certificate)
        checking expiration and signatures of all certificates in the chain

        Raises:
            [exceptions.NotCompleteChain](https://pki-tools.fulder.dev/pki_tools/exceptions/#notcompletechain)
            -- When the chain contain only one not self-signed certificate

            [exceptions.CertExpired](https://pki-tools.fulder.dev/pki_tools/exceptions/#certexpired)
            -- If some certificate in the chain has expired

            [exceptions.InvalidSignedType](https://pki-tools.fulder.dev/pki_tools/exceptions/#invalidsignedtype)
            -- When the issuer has a non-supported type

            [exceptions.SignatureVerificationFailed](https://pki-tools.fulder.dev/pki_tools/exceptions/#signatureverificationfailed)
            -- When the signature verification fails
        """
        if len(self.certificates) == 1:
            if (
                self.certificates[0].issuer.rfc4514_string()
                == self.certificates[0].subject.rfc4514_string()
            ):
                logger.debug(
                    "Chain contains only one self signed cert, "
                    "nothing to check"
                )
                return
            else:
                raise exceptions.NotCompleteChain()

        for cert in self.certificates:
            log = logger.bind(subject=cert.subject)
            if (
                cert.not_valid_after < datetime.now()
                or cert.not_valid_before > datetime.now()
            ):
                log.error("Certificate expired")
                raise exceptions.CertExpired(
                    f"Certificate in chain with subject: '{cert.subject}' "
                    f"has expired"
                )

            issuer = self.get_issuer(cert)

            pki_tools.verify_signature(cert, issuer)

    def get_issuer(
        self,
        signed: [
            x509.Certificate,
            x509.CertificateRevocationList,
            OCSPResponse,
        ],
    ) -> x509.Certificate:
        """
        Returns the issuer of a signed entity

        Arguments:
            signed: The signed certificate can either be a
            [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate),
            [x509.CertificateRevocationList](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.CertificateRevocationList)
            or a
            [x509.CertificateRevocationList](https://cryptography.io/en/latest/x509/ocsp/#cryptography.x509.ocsp.OCSPResponse)
            issuer: The issuer of the signed entity

        Returns:
            The
            [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate)
            representing the issuer of the `signed` entity

        Raises:
            [exceptions.CertIssuerMissingInChain](https://pki-tools.fulder.dev/pki_tools/exceptions/#certissuermissinginchain)
            -- When the issuer of the entitie is missing in the chain
        """
        cert_subject = signed.issuer.rfc4514_string()
        log = logger.bind(subject=cert_subject)

        for next_chain_cert in self.certificates:
            if cert_subject == next_chain_cert.subject.rfc4514_string():
                log.trace("Found issuer cert in chain")
                return next_chain_cert

        raise exceptions.CertIssuerMissingInChain()

    @classmethod
    def from_file(cls: Type["Chain"], file_path: str) -> "Chain":
        """
        Creates a Chain from a file path containing one or more PEM
        certificate(s)

        Arguments:
             file_path -- The path to the file containing the PEM certificate(s)
        """
        certificates = pki_tools.read_many_from_file(file_path)
        return cls(certificates=certificates)

    @classmethod
    def from_pem_str(cls: Type["Chain"], pem_certs: str) -> "Chain":
        """
        Creates a Chain from a string containing one or more certificate(s)
        in PEM format

        Arguments:
             pem_certs -- A string containing one or more certificate(s)
        """
        certificates = x509.load_pem_x509_certificates(pem_certs.encode())
        return cls(certificates=certificates)

    @classmethod
    def from_uri(
        cls: Type["Chain"],
        uri: str,
        cache_time_seconds: int = CACHE_TIME_SECONDS,
    ) -> "Chain":
        """
        Creates a Chain from a str URI

        Arguments:
             chain_uri -- A str containing the URI where the certificate
             chain can be downloaded.
             cache_time_seconds -- Decides how long the chain should be cached,
             default is 1 month
        """
        chain_uri = ChainUri(uri=uri, cache_time_seconds=cache_time_seconds)
        cache_ttl = round(time.time() / chain_uri.cache_time_seconds)
        return Chain._from_uri(chain_uri.uri, cache_ttl)

    @classmethod
    @lru_cache(maxsize=None)
    def _from_uri(cls: Type["Chain"], uri: str, ttl=None) -> "Chain":
        ret = requests.get(uri)

        if ret.status_code != 200:
            logger.bind(status=ret.status_code).error(
                "Failed to fetch issuer from URI"
            )
            raise pki_tools.exceptions.OcspIssuerFetchFailure(
                f"Issuer URI fetch failed. Status: {ret.status_code}"
            )

        return cls(certificates=x509.load_pem_x509_certificates(ret.content))


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


class AuthorityKeyIdentifier(BaseModel):
    key_identifier: Optional[bytes]
    authority_cert_issuer: Optional[List[str]]
    authority_cert_serial_number: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509AuthorityKeyIdentifier):
        issuers = []
        if extension.authority_cert_issuer is not None:
            for general_name in extension.authority_cert_issuer:
                issuers.append(general_name.value)

        return cls(
            key_identifier=extension.key_identifier,
            authority_cert_issuer=issuers,
            authority_cert_serial_number=extension.authority_cert_serial_number,
        )

    def __str__(self):
        ret = ""
        if self.key_identifier is not None:
            ret += f"""
                KeyIdentifier: {self.key_identifier.decode()}"""
        if self.authority_cert_issuer is not None:
            issuers = ""
            for issuer in self.authority_cert_issuer:
                issuers += f"""
                    {issuer}"""
            ret += f"""
                Authority Cert Issuer: {issuers}"""
        if self.authority_cert_serial_number is not None:
            ret += f"""
                Authority Cert Serial Number: {self.authority_cert_serial_number}"""
        if ret != "":
            return f"""
            AuthorityKeyIdentifier: {ret}"""
        return ""


class SubjectKeyIdentifier(BaseModel):
    


class Extensions(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    authority_key_identifier: Optional[AuthorityKeyIdentifier] = Field(alias=ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string, default=None)
    subject_key_identifier: Optional[SubjectKeyIdentifier] = Field(alias=ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string, default=None)

    @classmethod
    def from_cryptography(cls, cert_extensions: x509Extensions):
        extensions_dict = {}

        for name, field_info in cls.model_fields.items():
            try:
                oid = ObjectIdentifier(field_info.alias)
                ext_val = cert_extensions.get_extension_for_oid(oid).value

                classType = typing.get_args(field_info.annotation)[0]
                extensions_dict[oid.dotted_string] = classType.from_cryptography(ext_val)
            except ExtensionNotFound:
                logger.debug(f"Extension with OID: {oid._name} not found")

        return cls(**extensions_dict)

    @staticmethod
    def _get_extension_from_oid(
        cert_extensions: x509Extensions, oid: ObjectIdentifier, classType
    ) -> Optional[ExtensionTypeVar]:
        try:
            ext_val = cert_extensions.get_extension_for_oid(oid).value
            classType.from_cryptography(ext_val)
        except ExtensionNotFound:
            logger.debug(f"Extension with OID: {oid._name} not found")
            return None

    def __str__(self):
        extensions = ""
        for field_name in self.model_fields:
            att_val = getattr(self, field_name)

            if str(att_val) != "":
                extensions += str(att_val)

        return extensions


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


def _is_pem_str(check):
    if not isinstance(check, PemCert) and not isinstance(check, str):
        return False

    return re.match(PEM_REGEX, check)

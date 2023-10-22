import binascii
import typing
from typing import List, Optional


from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier


from cryptography.x509.extensions import (
Extension as x509Extension,
CertificatePolicies as x509CertificatePolicies,
    Extensions as x509Extensions,
    AuthorityKeyIdentifier as x509AuthorityKeyIdentifier,
SubjectKeyIdentifier as x509SubjectKeyIdentifier,
PolicyInformation as x509PolicyInformation,
KeyUsage as x509KeyUsage,
UserNotice as x509UserNotice,
NoticeReference as x509NoticeReference,
    ExtensionNotFound,
    ExtensionTypeVar,
)

from loguru import logger
from pydantic import BaseModel, Field, ConfigDict

from pki_tools.types import _byte_to_hex


class Extension(BaseModel):
    critical: Optional[bool] = False



class AuthorityKeyIdentifier(Extension):
    key_identifier: Optional[bytes]
    authority_cert_issuer: Optional[List[str]]
    authority_cert_serial_number: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509AuthorityKeyIdentifier):
        issuers = []
        if extension.authority_cert_issuer is not None:
            for general_name in extension.authority_cert_issuer:
                issuers.append(general_name.value)

        opt_issuers = None
        if issuers:
            opt_issuers = issuers
        return cls(
            key_identifier=extension.key_identifier,
            authority_cert_issuer=opt_issuers,
            authority_cert_serial_number=extension.authority_cert_serial_number,
        )

    def __str__(self):
        ret = ""
        if self.key_identifier is not None:
            hex_key = _byte_to_hex(self.key_identifier)
            ret += f"""
                Key Identifier: {hex_key}"""
        if self.authority_cert_issuer is not None:
            print(self.authority_cert_issuer)
            issuers = ""
            for issuer in self.authority_cert_issuer:
                issuers += f"""
                    {issuer}"""
            ret += f"""
                Authority Cert Issuer: {issuers}"""
        if self.authority_cert_serial_number is not None:
            ret += f"""
                Authority Cert Serial Number: {self.authority_cert_serial_number}"""

        name = "Authority Key Identifier"
        if self.critical:
            name += " (critical)"
        if ret != "":
            return f"""
            {name}: {ret}"""
        return ""


class SubjectKeyIdentifier(Extension):
    subject_key_identifier: bytes

    @classmethod
    def from_cryptography(cls, extension: x509SubjectKeyIdentifier):
        return cls(
            subject_key_identifier=extension.key_identifier
        )

    def __str__(self):
        name = "Subject Key Identifier"
        if self.critical:
            name += " (critical)"
        hex_key = _byte_to_hex(self.subject_key_identifier)
        return f"""
            {name}:
                Subject Key Identifier: {hex_key}"""


class KeyUsage(Extension):
    digital_signature: bool = False
    content_commitment: bool = False
    key_encipherment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    encipher_only: bool = False
    decipher_only: bool = False

    @classmethod
    def from_cryptography(cls,
                          extension: x509KeyUsage):
        try:
            encipher_only=extension.encipher_only
        except ValueError:
            encipher_only=False
        try:
            decipher_only=extension.decipher_only
        except ValueError:
            decipher_only=False

        return cls(
            digital_signature=extension.digital_signature,
            content_commitment=extension.content_commitment,
            key_encipherment=extension.key_encipherment,
            data_encipherment=extension.data_encipherment,
            key_agreement=extension.key_agreement,
            key_cert_sign=extension.key_cert_sign,
            crl_sign=extension.crl_sign,
            encipher_only=encipher_only,
            decipher_only=decipher_only,
        )

    def __str__(self):
        name = "Key Usage"
        if self.critical:
            name += " (critical)"

        true_fields = []
        for field in self.model_fields:
            if field == "critical":
                continue

            field_title = " ".join(ele.title() for ele in field.split("_"))
            if getattr(self, field):
                true_fields.append(field_title)
        return f"""
            {name}: 
                {', '.join(true_fields)}"""


class NoticeReference(BaseModel):
    organization: str
    notice_numbers: list[int]

    @classmethod
    def from_cryptography(cls, notice_reference: x509NoticeReference):
        return cls(
            organization=notice_reference.organization,
            notice_numbers=notice_reference.notice_numbers,
        )

    def __str__(self):
        return f"""Organization: {self.organization}
                            Notice Numbers: {self.notice_numbers}"""


class UserNotice(BaseModel):
    notice_reference: Optional[NoticeReference]
    explicit_text: Optional[str]

    @classmethod
    def from_cryptography(cls, policy_info: x509UserNotice):
        return cls(
            notice_reference=NoticeReference.from_cryptography(policy_info.notice_reference),
            explicit_text=policy_info.explicit_text,
        )

    def __str__(self):
        return f"""User Notice:
                            {self.notice_reference}
                            Explicit Text: {self.explicit_text}"""


class PolicyInformation(BaseModel):
    policy_identifier: str
    policy_qualifiers: Optional[list[typing.Union[str, UserNotice]]]

    @classmethod
    def from_cryptography(cls, policy_info: x509PolicyInformation):
        policy_qualifiers = None
        if policy_info.policy_qualifiers is not None:
            policy_qualifiers = []
            for qualifier in policy_info.policy_qualifiers:
                if isinstance(qualifier, str):
                    policy_qualifiers.append(f"CPS: {qualifier}")
                else:
                    policy_qualifiers.append(UserNotice.from_cryptography(qualifier))

        return cls(
            policy_identifier=policy_info.policy_identifier.dotted_string,
            policy_qualifiers=policy_qualifiers,
        )

    def __str__(self):
        policy_qualifiers = ""
        if self.policy_qualifiers is not None:
            for qualifier in self.policy_qualifiers:
                policy_qualifiers += f"""
                            {qualifier}"""

        ret = f"""
                Policy Information:
                    Policy Identifier: {self.policy_identifier}"""
        if policy_qualifiers != "":
            ret += f"""
                    Policy Qualifiers: {policy_qualifiers}"""
        return ret



class CertificatePolicies(Extension):
    policy_information: List[PolicyInformation]

    @classmethod
    def from_cryptography(cls, extension: x509CertificatePolicies):
        res = []
        for policy_information in extension:
            info = PolicyInformation.from_cryptography(policy_information)
            res.append(info)

        return cls(policy_information=res)

    def __str__(self):
        name = "Certificate Policies"
        if self.critical:
            name += " (critical)"

        policy_info = ""
        for info in self.policy_information:
            policy_info += f"""{info}"""

        return f"""
            {name}: {policy_info}"""

class Extensions(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    authority_key_identifier: Optional[AuthorityKeyIdentifier] = Field(
        alias=ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string, default=None
    )
    subject_key_identifier: Optional[SubjectKeyIdentifier] = Field(
        alias=ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string, default=None)
    key_usage: Optional[KeyUsage] = Field(
        alias=ExtensionOID.KEY_USAGE.dotted_string, default=None)
    certificate_policies: Optional[CertificatePolicies] = Field(
        alias=ExtensionOID.CERTIFICATE_POLICIES.dotted_string, default=None)
    # policy_mappings

    @classmethod
    def from_cryptography(cls, cert_extensions: x509Extensions):
        extensions_dict = {}

        for name, field_info in cls.model_fields.items():
            class_type = typing.get_args(field_info.annotation)[0]
            oid = ObjectIdentifier(field_info.alias)
            try:
                x509_ext = cert_extensions.get_extension_for_oid(oid)

                ext = class_type.from_cryptography(x509_ext.value)

                extensions_dict[oid.dotted_string] = ext
                extensions_dict[oid.dotted_string].critical = x509_ext.critical
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

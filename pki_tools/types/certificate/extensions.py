import typing
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier


from cryptography.x509.extensions import (
    ExtensionNotFound,
    ExtensionTypeVar,
)

from loguru import logger
from pydantic import BaseModel, Field, ConfigDict
from pki_tools.types.certificate.name import Name
from pki_tools.types import _byte_to_hex


class Extension(BaseModel):
    critical: Optional[bool] = False

    @property
    def name(self):
        name = "".join(
            [" " + c if c.isupper() else c for c in self.__class__.__name__]
        )[1:]
        if self.critical:
            name += " (critical)"
        return name


class AuthorityKeyIdentifier(Extension):
    key_identifier: Optional[bytes]
    authority_cert_issuer: Optional[List[str]]
    authority_cert_serial_number: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509.AuthorityKeyIdentifier):
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

    def string_dict(self):
        ret = {}

        if self.key_identifier is not None:
            hex_key = _byte_to_hex(self.key_identifier)
            ret["Key Identifier"] = hex_key
        if self.authority_cert_issuer is not None:
            ret["Authority Cert Issuer"] = self.authority_cert_issuer
        if self.authority_cert_serial_number is not None:
            ret[
                "Authority Cert Serial Number"
            ] = self.authority_cert_serial_number

        if ret:
            return {self.name: ret}
        return {}


class SubjectKeyIdentifier(Extension):
    subject_key_identifier: bytes

    @classmethod
    def from_cryptography(cls, extension: x509.SubjectKeyIdentifier):
        return cls(subject_key_identifier=extension.key_identifier)

    def string_dict(self):
        hex_key = _byte_to_hex(self.subject_key_identifier)
        return {self.name: {"Subject Key Identifier": hex_key}}


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
    def from_cryptography(cls, extension: x509.KeyUsage):
        try:
            encipher_only = extension.encipher_only
        except ValueError:
            encipher_only = False
        try:
            decipher_only = extension.decipher_only
        except ValueError:
            decipher_only = False

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

    def string_dict(self):
        true_fields = []
        for field in self.model_fields:
            if field == "critical":
                continue

            field_title = " ".join(ele.title() for ele in field.split("_"))
            if getattr(self, field):
                true_fields.append(field_title)

        return {self.name: ", ".join(true_fields)}


class NoticeReference(Extension):
    organization: str
    notice_numbers: list[int]

    @classmethod
    def from_cryptography(cls, notice_reference: x509.NoticeReference):
        return cls(
            organization=notice_reference.organization,
            notice_numbers=notice_reference.notice_numbers,
        )

    def string_dict(self):
        return {
            self.name: {
                "Organization": self.organization,
                "Notice Numbers": self.notice_numbers,
            }
        }


class UserNotice(Extension):
    notice_reference: Optional[NoticeReference]
    explicit_text: Optional[str]

    @classmethod
    def from_cryptography(cls, policy_info: x509.UserNotice):
        return cls(
            notice_reference=NoticeReference.from_cryptography(
                policy_info.notice_reference
            ),
            explicit_text=policy_info.explicit_text,
        )

    def string_dict(self):
        ret = {self.name: {}}

        if self.notice_reference is not None:
            ret[self.name].update(self.notice_reference.string_dict())
        if self.explicit_text is not None:
            ret[self.name]["Explicit Text"] = self.explicit_text
        return ret


class PolicyInformation(Extension):
    policy_identifier: str
    policy_qualifiers: Optional[list[typing.Union[str, UserNotice]]]

    @classmethod
    def from_cryptography(cls, policy_info: x509.PolicyInformation):
        policy_qualifiers = None
        if policy_info.policy_qualifiers is not None:
            policy_qualifiers = []
            for qualifier in policy_info.policy_qualifiers:
                if isinstance(qualifier, str):
                    policy_qualifiers.append(f"CPS: {qualifier}")
                else:
                    policy_qualifiers.append(
                        UserNotice.from_cryptography(qualifier)
                    )

        return cls(
            policy_identifier=policy_info.policy_identifier.dotted_string,
            policy_qualifiers=policy_qualifiers,
        )

    def string_dict(self):
        ret = {
            self.name: {
                "Policy Identifier": self.policy_identifier,
                "Policy Qualifiers": [],
            }
        }

        if self.policy_qualifiers is not None:
            for qualifier in self.policy_qualifiers:
                if isinstance(qualifier, str):
                    ret[self.name]["Policy Qualifiers"].append(qualifier)
                else:
                    ret[self.name]["Policy Qualifiers"].append(
                        qualifier.string_dict()
                    )

        return ret


class CertificatePolicies(Extension):
    policy_information: List[PolicyInformation]

    @classmethod
    def from_cryptography(cls, extension: x509.CertificatePolicies):
        res = []
        for policy_information in extension:
            info = PolicyInformation.from_cryptography(policy_information)
            res.append(info)

        return cls(policy_information=res)

    def string_dict(self):
        ret = {self.name: []}
        for policy_information in self.policy_information:
            ret[self.name].append(policy_information.string_dict())

        return ret


class AlternativeName(Extension):
    general_names: list[str]

    @classmethod
    def from_cryptography(cls, extension: x509.SubjectAlternativeName):
        names = []
        for general_name in extension:
            names.append(_general_name_to_str(general_name))

        return cls(general_names=names)

    def string_dict(self):
        return {self.name: self.general_names}


class SubjectAlternativeName(AlternativeName):
    pass


class IssuerAlternativeName(AlternativeName):
    pass


class SubjectDirectoryAttributes(Extension):
    attributes: list[str]

    @classmethod
    def from_cryptography(cls, extension: x509.UnrecognizedExtension):
        attributes = []
        vals = extension.value
        if not isinstance(vals, list):
            vals = [vals]

        for val in vals:
            if isinstance(val, bytes):
                val = _byte_to_hex(val)

            attributes.append(val)

        return cls(attributes=attributes)

    def string_dict(self):
        return {self.name: self.attributes}


class BasicConstraints(Extension):
    ca: bool
    path_len_constraint: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509.BasicConstraints):
        return cls(ca=extension.ca, path_len_constraint=extension.path_length)

    def string_dict(self):
        ret = {
            self.name: {
                "CA": self.ca,
            }
        }

        if self.path_len_constraint is not None:
            ret["Path Lenght"] = self.path_len_constraint

        return ret


class NameConstraints(Extension):
    permitted_subtrees: Optional[list[str]]
    excluded_subtrees: Optional[list[str]]

    @classmethod
    def from_cryptography(cls, extension: x509.NameConstraints):
        permitted_subtrees = []
        for permitted in extension.permitted_subtrees:
            permitted_subtrees.append(_general_name_to_str(permitted))
        if not permitted_subtrees:
            permitted_subtrees = None

        excluded_subtrees = []
        for excluded in extension.excluded_subtrees:
            excluded_subtrees.append(_general_name_to_str(excluded))
        if not excluded_subtrees:
            excluded_subtrees = None

        return cls(
            permitted_subtrees=permitted_subtrees,
            excluded_subtrees=excluded_subtrees,
        )

    def string_dict(self):
        return {
            self.name: {
                "Permitted Subtrees": self.permitted_subtrees,
                "Excluded Subtrees": self.excluded_subtrees,
            }
        }


class Extensions(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    authority_key_identifier: Optional[AuthorityKeyIdentifier] = Field(
        alias=ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string, default=None
    )
    subject_key_identifier: Optional[SubjectKeyIdentifier] = Field(
        alias=ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string, default=None
    )
    key_usage: Optional[KeyUsage] = Field(
        alias=ExtensionOID.KEY_USAGE.dotted_string, default=None
    )
    certificate_policies: Optional[CertificatePolicies] = Field(
        alias=ExtensionOID.CERTIFICATE_POLICIES.dotted_string, default=None
    )
    # policy_mappings
    subject_alternative_name: Optional[SubjectAlternativeName] = Field(
        alias=ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string, default=None
    )
    issuer_alternative_name: Optional[IssuerAlternativeName] = Field(
        alias=ExtensionOID.ISSUER_ALTERNATIVE_NAME.dotted_string, default=None
    )
    subject_directory_attributes: Optional[SubjectDirectoryAttributes] = Field(
        alias=ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES.dotted_string,
        default=None,
    )
    basic_constraints: Optional[BasicConstraints] = Field(
        alias=ExtensionOID.BASIC_CONSTRAINTS.dotted_string,
        default=None,
    )
    name_constraints: Optional[NameConstraints] = Field(
        alias=ExtensionOID.NAME_CONSTRAINTS.dotted_string,
        default=None,
    )

    @classmethod
    def from_cryptography(cls, cert_extensions: x509.Extensions):
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
        cert_extensions: x509.Extensions, oid: ObjectIdentifier, classType
    ) -> Optional[ExtensionTypeVar]:
        try:
            ext_val = cert_extensions.get_extension_for_oid(oid).value
            classType.from_cryptography(ext_val)
        except ExtensionNotFound:
            logger.debug(f"Extension with OID: {oid._name} not found")
            return None

    def string_dict(self):
        extensions = {}
        for field_name in self.model_fields:
            att_val = getattr(self, field_name)

            if att_val is None or str(att_val) == "":
                continue

            extensions.update(att_val.string_dict())

        return extensions


def _general_name_to_str(general_name):
    name_str = f"{type(general_name).__name__}: "
    if isinstance(general_name, x509.OtherName):
        value = _byte_to_hex(general_name.value)
        name_str += f"{general_name.type_id.dotted_string} - {value}"
    elif isinstance(general_name, x509.RegisteredID):
        name_str += str(general_name.value.dotted_string)
    elif isinstance(general_name, x509.DirectoryName):
        name = Name.from_cryptography(general_name.value)
        name_list = []
        for k, v in name.string_dict().items():
            name_list.append(f"{k}: {v}")
        name_str += ", ".join(name_list)
    else:
        name_str += str(general_name.value)
    return name_str


def _general_names_to_str(general_names: list[str]):
    names = ""
    for general_name in general_names:
        names += f"""
                     {general_name}"""
    return names

import typing
from typing import List, Optional, Iterable, Union

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier


from cryptography.x509.extensions import (
    ExtensionNotFound,
    ExtensionTypeVar,
)

from loguru import logger
from pydantic import BaseModel, Field, ConfigDict

from pki_tools.types.name import Name
from pki_tools.types.utils import _byte_to_hex


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

    def _string_dict(self):
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

    def _string_dict(self):
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

    def _string_dict(self):
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
    notice_numbers: List[int]

    @classmethod
    def from_cryptography(cls, notice_reference: x509.NoticeReference):
        return cls(
            organization=notice_reference.organization,
            notice_numbers=notice_reference.notice_numbers,
        )

    def _string_dict(self):
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

    def _string_dict(self):
        ret = {self.name: {}}

        if self.notice_reference is not None:
            ret[self.name].update(self.notice_reference._string_dict())
        if self.explicit_text is not None:
            ret[self.name]["Explicit Text"] = self.explicit_text
        return ret


class PolicyInformation(Extension):
    policy_identifier: str
    policy_qualifiers: Optional[List[Union[str, UserNotice]]]

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

    def _string_dict(self):
        name = f"Policy {self.policy_identifier}"
        ret = {name: []}

        if self.policy_qualifiers is not None:
            for qualifier in self.policy_qualifiers:
                if isinstance(qualifier, str):
                    ret[name].append(qualifier)
                else:
                    ret[name].append(qualifier._string_dict())
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

    def _string_dict(self):
        ret = {self.name: []}
        for policy_information in self.policy_information:
            ret[self.name].append(policy_information._string_dict())

        return ret


class AlternativeName(Extension):
    general_names: List[str]

    @classmethod
    def from_cryptography(cls, extension: x509.SubjectAlternativeName):
        names = []
        for general_name in extension:
            names.append(_general_name_to_str(general_name))

        return cls(general_names=names)

    def _string_dict(self):
        return {self.name: self.general_names}


class SubjectAlternativeName(AlternativeName):
    pass


class IssuerAlternativeName(AlternativeName):
    pass


class SubjectDirectoryAttributes(Extension):
    attributes: List[str]

    @classmethod
    def from_cryptography(cls, extension: x509.UnrecognizedExtension):
        attributes = []
        vals = extension.value
        if not isinstance(vals, List):
            vals = [vals]

        for val in vals:
            if isinstance(val, bytes):
                val = _byte_to_hex(val)

            attributes.append(val)

        return cls(attributes=attributes)

    def _string_dict(self):
        return {self.name: self.attributes}


class BasicConstraints(Extension):
    ca: bool
    path_len_constraint: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509.BasicConstraints):
        return cls(ca=extension.ca, path_len_constraint=extension.path_length)

    def _string_dict(self):
        ret = {
            self.name: {
                "CA": self.ca,
            }
        }

        if self.path_len_constraint is not None:
            ret["Path Lenght"] = self.path_len_constraint

        return ret


class NameConstraints(Extension):
    permitted_subtrees: Optional[List[str]]
    excluded_subtrees: Optional[List[str]]

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

    def _string_dict(self):
        return {
            self.name: {
                "Permitted Subtrees": self.permitted_subtrees,
                "Excluded Subtrees": self.excluded_subtrees,
            }
        }


class PolicyConstraints(Extension):
    require_explicit_policy: Optional[int]
    inhibit_policy_mapping: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509.PolicyConstraints):
        return cls(
            require_explicit_policy=extension.require_explicit_policy,
            inhibit_policy_mapping=extension.inhibit_policy_mapping,
        )

    def _string_dict(self):
        ret = {self.name: {}}

        if self.require_explicit_policy is not None:
            ret[self.name][
                "Require Explicit Policy"
            ] = self.require_explicit_policy
        if self.inhibit_policy_mapping is not None:
            ret[self.name][
                "Inhibit Policy Mapping"
            ] = self.inhibit_policy_mapping

        return ret


EKU_OID_MAPPING = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Email Protection",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.17": "IPsec IKE",
    "2.5.29.37.0": "Any Extended Key Usage",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.5": "Kerberos PKINIT KDC",
    "1.3.6.1.4.1.11129.2.4.4": "Certificate Transparency",
}


class ExtendedKeyUsage(Extension):
    ext_key_usage_syntax: List[str]

    @classmethod
    def from_cryptography(cls, extension: x509.ExtendedKeyUsage):
        ext_key_usage_syntax = []
        for key_usage in extension:
            name = EKU_OID_MAPPING.get(
                key_usage.dotted_string,
                f"Unknown OID ({key_usage.dotted_string})",
            )
            ext_key_usage_syntax.append(name)
        return cls(ext_key_usage_syntax=ext_key_usage_syntax)

    def _string_dict(self):
        return {self.name: self.ext_key_usage_syntax}


class DistributionPoint(Extension):
    full_name: Optional[List[str]]
    name_relative_to_crl_issuer: Optional[List[str]]
    reasons: Optional[List[str]]
    crl_issuer: Optional[List[str]]

    @classmethod
    def from_cryptography(cls, extension: x509.DistributionPoint):
        full_names = None
        if extension.full_name is not None:
            full_names = []
            for full_name in extension.full_name:
                full_names.append(_general_name_to_str(full_name))

        relative_names = None
        if extension.relative_name is not None:
            relative_names = []
            for rel_name in extension.relative_name:
                relative_names.append(rel_name.rfc4514_string())

        reasons = None
        if extension.reasons is not None:
            reasons = []
            for reason in extension.reasons:
                reasons.append(reason.value)

        crl_issuers = None
        if extension.crl_issuer is not None:
            crl_issuers = []
            for crl_issuer in extension.crl_issuer:
                crl_issuers.append(_general_name_to_str(crl_issuer))

        return cls(
            full_name=full_names,
            name_relative_to_crl_issuer=relative_names,
            reasons=reasons,
            crl_issuer=crl_issuers,
        )

    def _string_dict(self):
        ret = {}
        if self.full_name is not None:
            ret["Full Name"] = self.full_name
        if self.name_relative_to_crl_issuer is not None:
            ret[
                "Name Relative To CRL Issuer"
            ] = self.name_relative_to_crl_issuer
        if self.reasons is not None:
            ret["Reasons"] = self.reasons
        if self.crl_issuer is not None:
            ret["CRL Issuer"] = self.crl_issuer
        return ret


class CrlDistributionPoints(Extension):
    crl_distribution_points: List[DistributionPoint]

    def __iter__(self) -> Iterable[DistributionPoint]:
        return iter(self.crl_distribution_points)

    @classmethod
    def from_cryptography(cls, extension: x509.CRLDistributionPoints):
        crl_distribution_points = []
        for crl_distribution_point in extension:
            parsed = DistributionPoint.from_cryptography(
                crl_distribution_point
            )
            crl_distribution_points.append(parsed)

        return cls(crl_distribution_points=crl_distribution_points)

    def _string_dict(self):
        ret = {self.name: []}
        for dist_point in self.crl_distribution_points:
            ret[self.name].append(dist_point._string_dict())

        return ret


class InhibitAnyPolicy(Extension):
    skip_certs: int

    @classmethod
    def from_cryptography(cls, extension: x509.InhibitAnyPolicy):
        return cls(skip_certs=extension.skip_certs)

    def _string_dict(self):
        return {self.name: {"Skip Certs": self.skip_certs}}


class FreshestCrl(CrlDistributionPoints):
    pass


class AccessDescription(Extension):
    access_method: str
    access_location: str

    @classmethod
    def from_cryptography(cls, extension: x509.AccessDescription):
        return cls(
            access_method=extension.access_method._name,
            access_location=_general_name_to_str(extension.access_location),
        )

    def _string_dict(self):
        return {
            "Access Method": self.access_method,
            "Access Location": self.access_location,
        }


class AuthorityInformationAccess(Extension):
    access_description: List[AccessDescription]

    def __iter__(self) -> Iterable[AccessDescription]:
        return iter(self.access_description)

    @classmethod
    def from_cryptography(cls, extension: x509.AuthorityInformationAccess):
        access_descriptions = []
        for access_description in extension:
            access_descriptions.append(
                AccessDescription.from_cryptography(access_description)
            )
        return cls(access_description=access_descriptions)

    def _string_dict(self):
        access_descriptions = []
        for access_description in self.access_description:
            access_descriptions.append(access_description._string_dict())

        return {self.name: {"Access Description": access_descriptions}}


class SubjectInformationAccess(AuthorityInformationAccess):
    pass


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
    policy_constraints: Optional[PolicyConstraints] = Field(
        alias=ExtensionOID.POLICY_CONSTRAINTS.dotted_string,
        default=None,
    )
    extended_key_usage: Optional[ExtendedKeyUsage] = Field(
        alias=ExtensionOID.EXTENDED_KEY_USAGE.dotted_string,
        default=None,
    )
    crl_distribution_points: Optional[CrlDistributionPoints] = Field(
        alias=ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string,
        default=None,
    )
    inhibit_any_policy: Optional[InhibitAnyPolicy] = Field(
        alias=ExtensionOID.INHIBIT_ANY_POLICY.dotted_string,
        default=None,
    )
    freshest_crl: Optional[FreshestCrl] = Field(
        alias=ExtensionOID.FRESHEST_CRL.dotted_string,
        default=None,
    )
    authority_information_access: Optional[AuthorityInformationAccess] = Field(
        alias=ExtensionOID.AUTHORITY_INFORMATION_ACCESS.dotted_string,
        default=None,
    )
    subject_information_access: Optional[SubjectInformationAccess] = Field(
        alias=ExtensionOID.SUBJECT_INFORMATION_ACCESS.dotted_string,
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
                logger.trace(f"Extension with OID: {oid._name} not found")

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

    def _string_dict(self):
        extensions = {}
        for field_name in self.model_fields:
            att_val = getattr(self, field_name)

            if att_val is None or str(att_val) == "":
                continue

            extensions.update(att_val._string_dict())

        return extensions


def _general_name_to_str(general_name):
    if general_name is None:
        return None
    name_str = f"{type(general_name).__name__}: "
    if isinstance(general_name, x509.OtherName):
        value = _byte_to_hex(general_name.value)
        name_str += f"{general_name.type_id.dotted_string} - {value}"
    elif isinstance(general_name, x509.RegisteredID):
        name_str += str(general_name.value.dotted_string)
    elif isinstance(general_name, x509.DirectoryName):
        name_str += str(Name.from_cryptography(general_name.value))
    else:
        name_str += str(general_name.value)
    return name_str


def _general_names_to_str(general_names: List[str]):
    names = ""
    for general_name in general_names:
        names += f"""
                     {general_name}"""
    return names

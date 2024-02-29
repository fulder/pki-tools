import importlib
import typing
from enum import Enum
from typing import List, Optional, Iterable, Union, Type, Dict

from cryptography import x509
from cryptography.hazmat._oid import (
    ExtensionOID,
    AuthorityInformationAccessOID,
)
from cryptography.hazmat.bindings._rust import ObjectIdentifier

from cryptography.x509.extensions import (
    ExtensionNotFound,
    ExtensionTypeVar,
)

from loguru import logger
from pydantic import Field, ConfigDict

from pki_tools.types.crypto_parser import CryptoParser
from pki_tools.types.name import Name
from pki_tools.types.utils import _byte_to_hex, _hex_to_byte

GENERAL_NAME_MODULE = importlib.import_module("cryptography.x509.general_name")
EXTENSIONS_MODULE = importlib.import_module("cryptography.x509.extensions")


class Extension(CryptoParser):
    critical: Optional[bool] = False

    @property
    def name(self):
        name = "".join(
            [" " + c if c.isupper() else c for c in self.__class__.__name__]
        )[1:]
        if self.critical:
            name += " (critical)"
        return name


class GeneralName(CryptoParser):
    name: str
    value: Union[str, Name]

    @classmethod
    def from_cryptography(
        cls: Type["GeneralName"], crypto_obj: x509.GeneralName
    ) -> "GeneralName":
        if isinstance(crypto_obj, x509.DNSName):
            return DnsName(crypto_obj.value)
        elif isinstance(crypto_obj, x509.IPAddress):
            return IpAddress(str(crypto_obj.value))
        elif isinstance(crypto_obj, x509.DirectoryName):
            return DirectoryName.from_cryptography(crypto_obj)
        elif isinstance(crypto_obj, x509.OtherName):
            return OtherName.from_cryptography(crypto_obj)
        elif isinstance(crypto_obj, x509.RegisteredID):
            return RegisteredId.from_cryptography(crypto_obj)

        return globals()[crypto_obj.__class__.__name__](crypto_obj.value)

    def _to_cryptography(self) -> x509.GeneralName:
        return getattr(GENERAL_NAME_MODULE, self.name)(self.value)

    def _string_dict(self) -> typing.Dict[str, str]:
        return {
            "name": self.name,
            "value": self.value,
        }


class DnsName(GeneralName):
    def __init__(self, value: str):
        super().__init__(name="DNSName", value=value)


class DirectoryName(GeneralName):
    def __init__(self, value: Name):
        super().__init__(name="DirectoryName", value=value)

    @classmethod
    def from_cryptography(
        cls: Type["DirectoryName"], crypto_obj: x509.GeneralName
    ) -> "DirectoryName":
        return cls(value=Name.from_cryptography(crypto_obj.value))

    def _to_cryptography(self) -> x509.GeneralName:
        return x509.DirectoryName(self.value._to_cryptography())


class IpAddress(GeneralName):
    def __init__(self, value: str):
        super().__init__(name="IPAddress", value=value)

    def _to_cryptography(self) -> x509.GeneralName:
        cls_name = "IPv4"
        if ":" in self.value:
            cls_name = "IPv6"

        if "/" in self.value:
            cls_name += "Network"
        else:
            cls_name += "Address"

        module = importlib.import_module("ipaddress")
        value = getattr(module, cls_name)(self.value)
        return x509.IPAddress(value)


class OtherName(GeneralName):
    oid: str

    def __init__(self, value: str, oid: str):
        super().__init__(name="OtherName", value=value, oid=oid)

    @classmethod
    def from_cryptography(
        cls: Type["OtherName"], crypto_obj: x509.OtherName
    ) -> "OtherName":
        return cls(
            value=_byte_to_hex(crypto_obj.value),
            oid=crypto_obj.type_id.dotted_string,
        )

    def _to_cryptography(self) -> x509.OtherName:
        return x509.OtherName(
            type_id=x509.ObjectIdentifier(self.oid),
            value=_hex_to_byte(self.value),
        )


class RFC822Name(GeneralName):
    def __init__(self, value: str):
        super().__init__(name="RFC822Name", value=value)


class RegisteredId(GeneralName):
    def __init__(self, value: str):
        super().__init__(name="RegisteredID", value=value)

    @classmethod
    def from_cryptography(
        cls: Type["RegisteredId"], crypto_obj: x509.RegisteredID
    ) -> "RegisteredId":
        return cls(value=str(crypto_obj.value.dotted_string))

    def _to_cryptography(self) -> x509.RegisteredID:
        return x509.RegisteredID(x509.ObjectIdentifier(self.value))


class UniformResourceIdentifier(GeneralName):
    def __init__(self, value: str):
        super().__init__(name="UniformResourceIdentifier", value=value)


class AuthorityKeyIdentifier(Extension):
    key_identifier: Optional[bytes]
    authority_cert_issuer: Optional[List[GeneralName]]
    authority_cert_serial_number: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509.AuthorityKeyIdentifier):
        issuers = None
        if extension.authority_cert_issuer is not None:
            issuers = []
            for general_name in extension.authority_cert_issuer:
                issuers.append(GeneralName.from_cryptography(general_name))

        return cls(
            key_identifier=extension.key_identifier,
            authority_cert_issuer=issuers,
            authority_cert_serial_number=extension.authority_cert_serial_number,
            _x509_obj=extension,
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

    def _to_cryptography(self) -> x509.AuthorityKeyIdentifier:
        authority_cert_issuer = []
        for general_name in self.authority_cert_issuer:
            authority = getattr(GENERAL_NAME_MODULE, general_name.name)(
                general_name.value
            )
            authority_cert_issuer.append(authority)

        return x509.AuthorityKeyIdentifier(
            key_identifier=self.key_identifier,
            authority_cert_issuer=authority_cert_issuer,
            authority_cert_serial_number=self.authority_cert_serial_number,
        )


class SubjectKeyIdentifier(Extension):
    subject_key_identifier: bytes

    @classmethod
    def from_cryptography(cls, extension: x509.SubjectKeyIdentifier):
        return cls(
            subject_key_identifier=extension.key_identifier,
            _x509_obj=extension,
        )

    def _string_dict(self):
        hex_key = _byte_to_hex(self.subject_key_identifier)
        return {self.name: {"Subject Key Identifier": hex_key}}

    def _to_cryptography(self) -> x509.SubjectKeyIdentifier:
        return x509.SubjectKeyIdentifier(self.subject_key_identifier)


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
            _x509_obj=extension,
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

    def _to_cryptography(self) -> x509.KeyUsage:
        return x509.KeyUsage(
            digital_signature=self.digital_signature,
            content_commitment=self.content_commitment,
            key_encipherment=self.key_encipherment,
            data_encipherment=self.data_encipherment,
            key_agreement=self.key_agreement,
            key_cert_sign=self.key_cert_sign,
            crl_sign=self.crl_sign,
            encipher_only=self.encipher_only,
            decipher_only=self.decipher_only,
        )


class NoticeReference(Extension):
    organization: str
    notice_numbers: List[int]

    @classmethod
    def from_cryptography(cls, notice_reference: x509.NoticeReference):
        return cls(
            organization=notice_reference.organization,
            notice_numbers=notice_reference.notice_numbers,
            _x509_obj=notice_reference,
        )

    def _string_dict(self):
        return {
            self.name: {
                "Organization": self.organization,
                "Notice Numbers": self.notice_numbers,
            }
        }

    def _to_cryptography(self) -> x509.NoticeReference:
        return x509.NoticeReference(
            organization=self.organization,
            notice_numbers=self.notice_numbers,
        )


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
            _x509_obj=policy_info,
        )

    def _string_dict(self):
        ret = {self.name: {}}

        if self.notice_reference is not None:
            ret[self.name].update(self.notice_reference._string_dict())
        if self.explicit_text is not None:
            ret[self.name]["Explicit Text"] = self.explicit_text
        return ret

    def _to_cryptography(self) -> x509.UserNotice:
        return x509.UserNotice(
            notice_reference=self.notice_reference._to_cryptography(),
            explicit_text=self.explicit_text,
        )


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
                    policy_qualifiers.append(qualifier)
                else:
                    policy_qualifiers.append(
                        UserNotice.from_cryptography(qualifier)
                    )

        return cls(
            policy_identifier=policy_info.policy_identifier.dotted_string,
            policy_qualifiers=policy_qualifiers,
            _x509_obj=policy_info,
        )

    def _string_dict(self):
        name = f"Policy {self.policy_identifier}"
        ret = {name: []}

        if self.policy_qualifiers is not None:
            for qualifier in self.policy_qualifiers:
                if isinstance(qualifier, str):
                    ret[name].append(f"CPS: {qualifier}")
                else:
                    ret[name].append(qualifier._string_dict())
        return ret

    def _to_cryptography(self) -> x509.PolicyInformation:
        qualifiers = []
        for qualifier in self.policy_qualifiers:
            if isinstance(qualifier, str):
                qualifiers.append(qualifier)
            else:
                qualifiers.append(qualifier._to_cryptography())

        return x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier(self.policy_identifier),
            policy_qualifiers=qualifiers,
        )


class CertificatePolicies(Extension):
    policy_information: List[PolicyInformation]

    @classmethod
    def from_cryptography(cls, extension: x509.CertificatePolicies):
        res = []
        for policy_information in extension:
            info = PolicyInformation.from_cryptography(policy_information)
            res.append(info)

        return cls(
            policy_information=res,
            _x509_obj=extension,
        )

    def _string_dict(self):
        ret = {self.name: []}
        for policy_information in self.policy_information:
            ret[self.name].append(policy_information._string_dict())

        return ret

    def _to_cryptography(self) -> x509.CertificatePolicies:
        policies = []
        for policy in self.policy_information:
            policies.append(policy._to_cryptography())

        return x509.CertificatePolicies(policies)


class AlternativeName(Extension):
    general_names: List[GeneralName]

    @classmethod
    def from_cryptography(
        cls,
        extension: Union[
            x509.SubjectAlternativeName, x509.IssuerAlternativeName
        ],
    ):
        names = []
        for general_name in extension:
            names.append(GeneralName.from_cryptography(general_name))

        return cls(
            general_names=names,
            _x509_obj=extension,
        )

    def _string_dict(self):
        general_names = []
        for general_name in self.general_names:
            general_names.append(general_name._string_dict())
        return {self.name: general_names}

    def _to_cryptography(
        self,
    ) -> Union[x509.SubjectAlternativeName, x509.IssuerAlternativeName]:
        general_names = []
        for general_name in self.general_names:
            general_names.append(general_name._to_cryptography())

        subclass_name = type(self).__name__

        return getattr(EXTENSIONS_MODULE, subclass_name)(general_names)


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

        return cls(attributes=attributes, _x509_obj=extension)

    def _to_cryptography(self) -> x509.UnrecognizedExtension:
        values = []
        for attribute in self.attributes:
            try:
                attribute = _hex_to_byte(attribute)
            except Exception:
                pass

            values.append(attribute)

        if len(values) == 1:
            values = values[0].encode()
        else:
            values = bytes(values)
        return x509.UnrecognizedExtension(
            oid=ObjectIdentifier("2.5.29.9"), value=values
        )

    def _string_dict(self):
        return {self.name: self.attributes}


class BasicConstraints(Extension):
    ca: bool
    path_len_constraint: Optional[int] = None

    @classmethod
    def from_cryptography(cls, extension: x509.BasicConstraints):
        return cls(
            ca=extension.ca,
            path_len_constraint=extension.path_length,
            _x509_obj=extension,
        )

    def _string_dict(self):
        ret = {
            self.name: {
                "CA": self.ca,
            }
        }

        if self.path_len_constraint is not None:
            ret["Path Lenght"] = self.path_len_constraint

        return ret

    def _to_cryptography(self) -> x509.BasicConstraints:
        return x509.BasicConstraints(
            ca=self.ca,
            path_length=self.path_len_constraint,
        )


class NameConstraints(Extension):
    permitted_subtrees: Optional[List[GeneralName]]
    excluded_subtrees: Optional[List[GeneralName]]

    @classmethod
    def from_cryptography(cls, extension: x509.NameConstraints):
        permitted_subtrees = []
        for permitted in extension.permitted_subtrees:
            permitted_subtrees.append(GeneralName.from_cryptography(permitted))
        if not permitted_subtrees:
            permitted_subtrees = None

        excluded_subtrees = []
        for excluded in extension.excluded_subtrees:
            excluded_subtrees.append(GeneralName.from_cryptography(excluded))
        if not excluded_subtrees:
            excluded_subtrees = None

        return cls(
            permitted_subtrees=permitted_subtrees,
            excluded_subtrees=excluded_subtrees,
            _x509_obj=extension,
        )

    def _string_dict(self):
        permitted_subtrees = []
        for permitted_subtree in self.permitted_subtrees:
            permitted_subtrees.append(permitted_subtree._string_dict())

        excluded_subtrees = []
        for excluded_subtree in self.excluded_subtrees:
            excluded_subtrees.append(excluded_subtree._string_dict())

        return {
            self.name: {
                "Permitted Subtrees": permitted_subtrees,
                "Excluded Subtrees": excluded_subtrees,
            }
        }

    def _to_cryptography(self) -> x509.NameConstraints:
        permitted_subtrees = None
        if self.permitted_subtrees is not None:
            permitted_subtrees = []
            for permitted_subtree in self.permitted_subtrees:
                permitted_subtrees.append(permitted_subtree._to_cryptography())

        excluded_subtrees = None
        if self.excluded_subtrees is not None:
            excluded_subtrees = []
            for excluded_subtree in self.excluded_subtrees:
                excluded_subtrees.append(excluded_subtree._to_cryptography())

        return x509.NameConstraints(
            permitted_subtrees=permitted_subtrees,
            excluded_subtrees=excluded_subtrees,
        )


class PolicyConstraints(Extension):
    require_explicit_policy: Optional[int]
    inhibit_policy_mapping: Optional[int]

    @classmethod
    def from_cryptography(cls, extension: x509.PolicyConstraints):
        return cls(
            require_explicit_policy=extension.require_explicit_policy,
            inhibit_policy_mapping=extension.inhibit_policy_mapping,
            _x509_obj=extension,
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

    def _to_cryptography(self) -> x509.PolicyConstraints:
        return x509.PolicyConstraints(
            require_explicit_policy=self.require_explicit_policy,
            inhibit_policy_mapping=self.inhibit_policy_mapping,
        )


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
            ext_key_usage_syntax.append(key_usage.dotted_string)
        return cls(
            ext_key_usage_syntax=ext_key_usage_syntax,
            _x509_obj=extension,
        )

    def _string_dict(self):
        names = []
        for oid in self.ext_key_usage_syntax:
            names.append(
                EKU_OID_MAPPING.get(
                    oid,
                    f"Unknown OID ({oid})",
                )
            )

        return {self.name: names}

    def _to_cryptography(self) -> x509.ExtendedKeyUsage:
        oids = []
        for oid in self.ext_key_usage_syntax:
            oids.append(x509.ObjectIdentifier(oid))
        return x509.ExtendedKeyUsage(oids)


class AttributeTypeAndValue(CryptoParser):
    oid: str
    value: str

    @classmethod
    def from_cryptography(cls, x509_obj: x509.NameAttribute):
        return cls(
            oid=x509_obj.oid.dotted_string,
            value=x509_obj.value,
            _x509_obj=x509_obj,
        )

    def _to_cryptography(self) -> x509.NameAttribute:
        return x509.NameAttribute(
            oid=x509.ObjectIdentifier(self.oid),
            value=self.value,
        )

    def _string_dict(self) -> Dict[str, str]:
        return {
            "OID": self.oid,
            "Value": self.value,
        }


class RelativeDistinguishedName(CryptoParser):
    attributes: List[AttributeTypeAndValue]

    def __iter__(self) -> Iterable:
        return iter(self.attributes)

    @classmethod
    def from_cryptography(cls, x509_obj: x509.RelativeDistinguishedName):
        attributes = []
        for name_attribute in x509_obj:
            attributes.append(
                AttributeTypeAndValue.from_cryptography(name_attribute)
            )

        cls(attributes=attributes, _x509_obj=x509_obj)

    def _string_dict(self) -> typing.Dict:
        attributes = []
        for att in self.attributes:
            attributes.append(att._string_dict())

        return {"RelativeDistinguishedName": attributes}

    def _to_cryptography(self) -> x509.RelativeDistinguishedName:
        name_attributes = []
        for att in self.attributes:
            name_attributes.append(att._to_cryptography())
        return x509.RelativeDistinguishedName(name_attributes)


class Reason(Enum):
    unspecified = "unspecified"
    key_compromise = "key_compromise"
    ca_compromise = "ca_compromise"
    affiliation_changed = "affiliation_changed"
    superseded = "superseded"
    cessation_of_operation = "cessation_of_operation"
    certificate_hold = "certificate_hold"
    privilege_withdrawn = "privilege_withdrawn"
    aa_compromise = "aa_compromise"
    remove_from_crl = "remove_from_crl"


class DistributionPoint(CryptoParser):
    full_name: Optional[List[GeneralName]] = None
    name_relative_to_crl_issuer: Optional[RelativeDistinguishedName] = None
    reasons: Optional[List[Reason]] = None
    crl_issuer: Optional[List[GeneralName]] = None

    @classmethod
    def from_cryptography(cls, extension: x509.DistributionPoint):
        full_names = None
        if extension.full_name is not None:
            full_names = []
            for full_name in extension.full_name:
                full_names.append(GeneralName.from_cryptography(full_name))

        relative_name = None
        if extension.relative_name is not None:
            relative_name = RelativeDistinguishedName.from_cryptography(
                extension.relative_name
            )

        reasons = None
        if extension.reasons is not None:
            reasons = []
            for reason in extension.reasons:
                reasons.append(getattr(Reason, reason.name))

        crl_issuers = None
        if extension.crl_issuer is not None:
            crl_issuers = []
            for crl_issuer in extension.crl_issuer:
                crl_issuers.append(GeneralName.from_cryptography(crl_issuer))

        return cls(
            full_name=full_names,
            name_relative_to_crl_issuer=relative_name,
            reasons=reasons,
            crl_issuer=crl_issuers,
            _x509_obj=extension,
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
            ret["Reasons"] = []
            for reason in self.reasons:
                ret["Reasons"].append(
                    getattr(x509.ReasonFlags, reason.name).value
                )
        if self.crl_issuer is not None:
            ret["CRL Issuer"] = self.crl_issuer
        return ret

    def _to_cryptography(self) -> x509.DistributionPoint:
        full_names = None
        if self.full_name is not None:
            full_names = []
            for full_name in self.full_name:
                full_names.append(full_name._to_cryptography())

        relative_names = None
        if self.name_relative_to_crl_issuer is not None:
            relative_names = (
                self.name_relative_to_crl_issuer._to_cryptography()
            )

        reasons = None
        if self.reasons is not None:
            reasons = []
            for reason in self.reasons:
                reasons.append(getattr(x509.ReasonFlags, reason.name))

        crl_issuers = None
        if self.crl_issuer is not None:
            crl_issuers = []
            for crl_issuer in self.crl_issuer:
                crl_issuers.append(crl_issuer._to_cryptography())

        return x509.DistributionPoint(
            full_name=full_names,
            relative_name=relative_names,
            reasons=frozenset(reasons),
            crl_issuer=crl_issuers,
        )


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

        return cls(
            crl_distribution_points=crl_distribution_points,
            _x509_obj=extension,
        )

    def _string_dict(self):
        ret = {self.name: []}
        for dist_point in self.crl_distribution_points:
            ret[self.name].append(dist_point._string_dict())

        return ret

    def _to_cryptography(self) -> x509.CRLDistributionPoints:
        dist_points = []
        for dist_point in self.crl_distribution_points:
            dist_points.append(dist_point._to_cryptography())

        return x509.CRLDistributionPoints(dist_points)


class InhibitAnyPolicy(Extension):
    skip_certs: int

    @classmethod
    def from_cryptography(cls, extension: x509.InhibitAnyPolicy):
        return cls(
            skip_certs=extension.skip_certs,
            _x509_obj=extension,
        )

    def _string_dict(self):
        return {self.name: {"Skip Certs": self.skip_certs}}

    def _to_cryptography(self) -> x509.InhibitAnyPolicy:
        return x509.InhibitAnyPolicy(self.skip_certs)


class FreshestCrl(CrlDistributionPoints):
    def _to_cryptography(self) -> x509.FreshestCRL:
        dist_points = []
        for dist_point in self.crl_distribution_points:
            dist_points.append(dist_point._to_cryptography())

        return x509.FreshestCRL(dist_points)


class AccessDescriptionId(Enum):
    CA_ISSUERS = "1.3.6.1.5.5.7.48.2"
    OCSP = "1.3.6.1.5.5.7.48.1"


class AccessDescription(CryptoParser):
    access_method: AccessDescriptionId
    access_location: GeneralName

    @classmethod
    def from_cryptography(cls, extension: x509.AccessDescription):
        access_method = AccessDescriptionId(
            extension.access_method.dotted_string
        )
        return cls(
            access_method=access_method,
            access_location=GeneralName.from_cryptography(
                extension.access_location
            ),
            _x509_obj=extension,
        )

    def _string_dict(self):
        return {
            "Access Method": self.access_method.name,
            "Access Location": self.access_location._string_dict(),
        }

    def _to_cryptography(self) -> x509.AccessDescription:
        return x509.AccessDescription(
            access_method=getattr(
                AuthorityInformationAccessOID, self.access_method.name
            ),
            access_location=self.access_location._to_cryptography(),
        )


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
        return cls(
            access_description=access_descriptions,
            _x509_obj=extension,
        )

    def _string_dict(self):
        access_descriptions = []
        for access_description in self.access_description:
            access_descriptions.append(access_description._string_dict())

        return {self.name: {"Access Description": access_descriptions}}

    def _to_cryptography(self) -> x509.AuthorityInformationAccess:
        access_descriptions = []
        for access_description in self.access_description:
            access_descriptions.append(access_description._to_cryptography())
        return x509.AuthorityInformationAccess(access_descriptions)


class SubjectInformationAccess(AuthorityInformationAccess):
    def _to_cryptography(self) -> x509.SubjectInformationAccess:
        access_descriptions = []
        for access_description in self.access_description:
            access_descriptions.append(access_description._to_cryptography())
        return x509.SubjectInformationAccess(access_descriptions)


class Extensions(CryptoParser):
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

    def __iter__(self) -> Iterable[Extension]:
        for field_name, field in self.model_fields.items():
            val = getattr(self, field_name)
            if val is None:
                continue

            yield getattr(self, field_name)

    @classmethod
    def from_cryptography(cls, cert_extensions: x509.Extensions):
        extensions_dict = {"_x509_obj": cert_extensions}

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

    def _to_cryptography(self) -> x509.Extensions:
        extensions = []
        for field_name in self.model_fields:
            att_val = getattr(self, field_name)

            if att_val is None or str(att_val) == "":
                continue

            extensions.append(att_val._to_cryptography())

        return x509.Extensions(extensions)

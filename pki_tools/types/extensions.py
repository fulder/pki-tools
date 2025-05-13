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
    """
    Represents a cryptographic extension.

    Attributes:
        critical: Indicates whether the extension is critical.
    """

    critical: Optional[bool] = False

    @property
    def name(self) -> str:
        """
        Get the name of the extension.

        Returns:
           str: The name of the extension.
        """
        name = "".join(
            [" " + c if c.isupper() else c for c in self.__class__.__name__]
        )[1:]
        if self.critical:
            name += " (critical)"
        return name


class GeneralName(CryptoParser):
    """
    Represents a general name.

    Attributes:
        name: The name of the general name.
        value: The value of the general name.
    """

    name: str
    value: Union[str, Name]

    @classmethod
    def from_cryptography(
        cls: Type["GeneralName"], crypto_obj: x509.GeneralName
    ) -> "GeneralName":
        """
        Create a GeneralName instance from a cryptography GeneralName object.

        Args:
            crypto_obj: The cryptography GeneralName object.

        Returns:
            The GeneralName instance.
        """
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
        val = self.value
        if isinstance(self.value, Name):
            val = str(self.value)

        return {
            "name": self.name,
            "value": val,
        }


class DnsName(GeneralName):
    """
    Represents a DNS name.

    Attributes:
        value: The DNS name value.
    """

    def __init__(self, value: str):
        super().__init__(name="DNSName", value=value)


class DirectoryName(GeneralName):
    """
    Represents a directory name.

    Attributes:
        value: The directory name value.
    """

    def __init__(self, value: Name):
        super().__init__(name="DirectoryName", value=value)

    @classmethod
    def from_cryptography(
        cls: Type["DirectoryName"], crypto_obj: x509.GeneralName
    ) -> "DirectoryName":
        """
        Create a DirectoryName instance from a cryptography DirectoryName
            object.

        Args:
            crypto_obj: The cryptography DirectoryName object.

        Returns:
            The DirectoryName instance.
        """
        return cls(value=Name.from_cryptography(crypto_obj.value))

    def _to_cryptography(self) -> x509.GeneralName:
        return x509.DirectoryName(self.value._to_cryptography())


class IpAddress(GeneralName):
    """
    Represents an IP address. Can either be a IPv4/IPv6 single address or
    network.

    Attributes:
        value: The IP address or network
    """

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
    """
    Represents an other name.

    Attributes:
        value: The other name value.
        oid: The object identifier (OID) of the other name.
    """

    oid: str

    def __init__(self, value: str, oid: str):
        super().__init__(name="OtherName", value=value, oid=oid)

    @classmethod
    def from_cryptography(
        cls: Type["OtherName"], crypto_obj: x509.OtherName
    ) -> "OtherName":
        """
        Create a OtherName instance from a cryptography OtherName object.

        Args:
            crypto_obj: The cryptography OtherName object.

        Returns:
            The OtherName instance.
        """
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
    """
    Represents an RFC822 name.

    Attributes:
        value: The RFC822 name value.
    """

    def __init__(self, value: str):
        super().__init__(name="RFC822Name", value=value)


class RegisteredId(GeneralName):
    """
    Represents a registered ID.

    Attributes:
        value: The registered ID value.
    """

    def __init__(self, value: str):
        super().__init__(name="RegisteredID", value=value)

    @classmethod
    def from_cryptography(
        cls: Type["RegisteredId"], crypto_obj: x509.RegisteredID
    ) -> "RegisteredId":
        """
        Create a RegisteredId instance from a cryptography RegisteredId object.

        Args:
            crypto_obj: The cryptography RegisteredId object.

        Returns:
            The RegisteredId instance.
        """
        return cls(value=str(crypto_obj.value.dotted_string))

    def _to_cryptography(self) -> x509.RegisteredID:
        return x509.RegisteredID(x509.ObjectIdentifier(self.value))


class UniformResourceIdentifier(GeneralName):
    """
    Represents a uniform resource identifier (URI).

    Attributes:
        value: The URI value.
    """

    def __init__(self, value: str):
        super().__init__(name="UniformResourceIdentifier", value=value)


class AuthorityKeyIdentifier(Extension):
    """
    Represents an authority key identifier extension.

    Attributes:
        key_identifier: The key identifier.
        authority_cert_issuer: The issuer of the authority certificate.
        authority_cert_serial_number: The serial number of the authority
            certificate.
    """

    key_identifier: Optional[bytes]
    authority_cert_issuer: Optional[List[GeneralName]]
    authority_cert_serial_number: Optional[int]

    @classmethod
    def from_cryptography(
        cls: Type["AuthorityKeyIdentifier"],
        extension: x509.AuthorityKeyIdentifier,
    ) -> "AuthorityKeyIdentifier":
        """
        Create an AuthorityKeyIdentifier instance from a cryptography
        AuthorityKeyIdentifier object.

        Args:
            extension: The cryptography AuthorityKeyIdentifier object.

        Returns:
            The AuthorityKeyIdentifier instance.
        """
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
            authority_cert_issuer = []
            for general_name in self.authority_cert_issuer:
                authority_cert_issuer.append(general_name._string_dict())
            ret["Authority Cert Issuer"] = authority_cert_issuer
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
    """
    Represents a subject key identifier extension.

    Attributes:
        subject_key_identifier: The subject key identifier.
    """

    subject_key_identifier: bytes

    @classmethod
    def from_cryptography(
        cls: Type["SubjectKeyIdentifier"], extension: x509.SubjectKeyIdentifier
    ) -> "SubjectKeyIdentifier":
        """
        Create a SubjectKeyIdentifier instance from a cryptography
        SubjectKeyIdentifier object.

        Args:
            extension: The cryptography SubjectKeyIdentifier object.

        Returns:
            The SubjectKeyIdentifier instance.
        """
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
    """
    Represents a key usage extension.

    Attributes:
        digital_signature: Indicates if digital signature is allowed.
        content_commitment: Indicates if content commitment is allowed.
        key_encipherment: Indicates if key encipherment is allowed.
        data_encipherment: Indicates if data encipherment is allowed.
        key_agreement: Indicates if key agreement is allowed.
        key_cert_sign: Indicates if key certificate signing is allowed.
        crl_sign: Indicates if CRL signing is allowed.
        encipher_only: Indicates if encipher only is allowed.
        decipher_only: Indicates if decipher only is allowed.
    """

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
    def from_cryptography(
        cls: Type["KeyUsage"], extension: x509.KeyUsage
    ) -> "KeyUsage":
        """
        Create a KeyUsage instance from a cryptography KeyUsage object.

        Args:
            extension: The cryptography KeyUsage object.

        Returns:
            The KeyUsage instance.
        """
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
    """
    Represents a notice reference extension.

    Attributes:
        organization: The organization associated with the notice.
        notice_numbers: List of notice numbers.
    """

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
    """
    Represents a user notice extension.

    Attributes:
        notice_reference: The notice reference associated with the user notice.
        explicit_text: The explicit text of the user notice.
    """

    notice_reference: Optional[NoticeReference]
    explicit_text: Optional[str]

    @classmethod
    def from_cryptography(
        cls: Type["UserNotice"], policy_info: x509.UserNotice
    ) -> "UserNotice":
        """
        Create a UserNotice instance from a cryptography UserNotice object.

        Args:
            policy_info: The cryptography UserNotice object.

        Returns:
            The UserNotice instance.
        """
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
    """
    Represents a policy information extension.

    Attributes:
        policy_identifier: The policy identifier associated with the policy
            information.
        policy_qualifiers: List of policy qualifiers.
    """

    policy_identifier: str
    policy_qualifiers: Optional[List[Union[str, UserNotice]]]

    @classmethod
    def from_cryptography(
        cls: Type["PolicyInformation"], policy_info: x509.PolicyInformation
    ) -> "PolicyInformation":
        """
        Create a PolicyInformation instance from a cryptography
        PolicyInformation object.

        Args:
            policy_info: The cryptography PolicyInformation object.

        Returns:
            The PolicyInformation instance.
        """
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
    """
    Represents a certificate policies extension.

    Attributes:
        policy_information: List of policy information.
    """

    policy_information: List[PolicyInformation]

    @classmethod
    def from_cryptography(
        cls: Type["CertificatePolicies"], extension: x509.CertificatePolicies
    ) -> "CertificatePolicies":
        """
        Create a CertificatePolicies instance from a cryptography
        CertificatePolicies object.

        Args:
            extension: The cryptography CertificatePolicies object.

        Returns:
            The CertificatePolicies instance.
        """
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
    """
    Represents an alternative name extension.

    Attributes:
        general_names: List of general names.
    """

    general_names: List[GeneralName]

    @classmethod
    def from_cryptography(
        cls: Type["AlternativeName"],
        extension: Union[
            x509.SubjectAlternativeName, x509.IssuerAlternativeName
        ],
    ) -> "AlternativeName":
        """
        Create an AlternativeName instance from a cryptography
        SubjectAlternativeName or IssuerAlternativeName object.

        Args:
            extension: The cryptography SubjectAlternativeName or
                IssuerAlternativeName object.

        Returns:
            The AlternativeName instance.
        """
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
    """
    Represents a subject alternative name extension.
    """

    pass


class IssuerAlternativeName(AlternativeName):
    """
    Represents an issuer alternative name extension.
    """

    pass


class SubjectDirectoryAttributes(Extension):
    """
    Represents a subject directory attributes extension.

    Attributes:
        attributes: List of attributes.
    """

    attributes: List[str]

    @classmethod
    def from_cryptography(
        cls: Type["SubjectDirectoryAttributes"],
        extension: x509.UnrecognizedExtension,
    ) -> "SubjectDirectoryAttributes":
        """
        Create a SubjectDirectoryAttributes instance from a cryptography
        UnrecognizedExtension object.

        Args:
            extension: The cryptography UnrecognizedExtension object.

        Returns:
            The SubjectDirectoryAttributes instance.
        """
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
    """
    Represents a basic constraints extension.

    Attributes:
        ca: Indicates if the certificate is a CA.
        path_len_constrain: The path length constraint.
    """

    ca: bool
    path_len_constraint: Optional[int] = None

    @classmethod
    def from_cryptography(
        cls: Type["BasicConstraints"], extension: x509.BasicConstraints
    ) -> "BasicConstraints":
        """
        Create a BasicConstraints instance from a cryptography
        BasicConstraints object.

        Args:
            extension: The cryptography BasicConstraints object.

        Returns:
            The BasicConstraints instance.
        """
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
    """
    Represents a name constraints extension.

    Attributes:
        permitted_subtrees: List of permitted subtrees.
        excluded_subtrees: List of excluded subtrees.
    """

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
    """
    Represents a policy constraints extension.

    Attributes:
        require_explicit_policy: The require explicit policy value.
        inhibit_policy_mapping: The inhibit policy mapping value.
    """

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
    """
    Represents the Extended Key Usage extension in X.509 certificates.

    Attributes:
        ext_key_usage_syntax: List of extended key usage OIDs.
    """

    ext_key_usage_syntax: List[str]

    @classmethod
    def from_cryptography(
        cls: Type["ExtendedKeyUsage"], extension: x509.ExtendedKeyUsage
    ) -> "ExtendedKeyUsage":
        """
        Constructs an ExtendedKeyUsage object from a cryptography
        ExtendedKeyUsage object.

        Args:
            extension: The cryptography ExtendedKeyUsage object.

        Returns:
            The constructed ExtendedKeyUsage object.
        """
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
    """
    Represents an Attribute Type and Value in X.509 certificates.

    Attributes:
        oid: The Object Identifier (OID) of the attribute.
        value: The value of the attribute.
    """

    oid: str
    value: str

    @classmethod
    def from_cryptography(
        cls: Type["AttributeTypeAndValue"], x509_obj: x509.NameAttribute
    ) -> "AttributeTypeAndValue":
        """
        Constructs an AttributeTypeAndValue object from a cryptography
        NameAttribute object.

        Args:
            x509_obj: The cryptography NameAttribute object.

        Returns:
            The constructed AttributeTypeAndValue object.
        """
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
    """
    Represents a Relative Distinguished Name in X.509 certificates.

    Attributes:
        attributes: List of attributes in the RDN.
    """

    attributes: List[AttributeTypeAndValue]

    def __iter__(self) -> Iterable:
        return iter(self.attributes)

    @classmethod
    def from_cryptography(
        cls: Type["RelativeDistinguishedName"],
        x509_obj: x509.RelativeDistinguishedName,
    ) -> "RelativeDistinguishedName":
        """
        Constructs a RelativeDistinguishedName object from a cryptography
        RelativeDistinguishedName object.

        Args:
            x509_obj: The cryptography RelativeDistinguishedName object.

        Returns:
            The constructed RelativeDistinguishedName object.
        """
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
    """
    Reasons for the DistributionPoint extension
    """

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
    """
    Represents a Distribution Point in X.509 certificates.

    Attributes:
        full_name: List of full names associated with the distribution point.
        name_relative_to_crl_issuer: Relative name to the CRL issuer.
        reasons: List of reasons for the distribution point.
        crl_issuer: List of CRL issuers associated with the distribution
            point.
    """

    full_name: Optional[List[GeneralName]] = None
    name_relative_to_crl_issuer: Optional[RelativeDistinguishedName] = None
    reasons: Optional[List[Reason]] = None
    crl_issuer: Optional[List[GeneralName]] = None

    @classmethod
    def from_cryptography(
        cls: Type["DistributionPoint"], extension: x509.DistributionPoint
    ) -> "DistributionPoint":
        """
        Constructs a DistributionPoint object from a cryptography
        DistributionPoint object.

        Args:
            extension: The cryptography DistributionPoint object.

        Returns:
            DistributionPoint: The constructed DistributionPoint object.
        """
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
            ret["Full Name"] = []
            for full_name in self.full_name:
                ret["Full Name"].append(full_name._string_dict())
        if self.name_relative_to_crl_issuer is not None:
            ret[
                "Name Relative To CRL Issuer"
            ] = self.name_relative_to_crl_issuer._string_dict()
        if self.reasons is not None:
            ret["Reasons"] = []
            for reason in self.reasons:
                ret["Reasons"].append(
                    getattr(x509.ReasonFlags, reason.name).value
                )
        if self.crl_issuer is not None:
            ret["CRL Issuer"] = []
            for crl_issuer in self.crl_issuer:
                ret["CRL Issuer"].append(crl_issuer._string_dict())
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
            reasons = frozenset(reasons)

        crl_issuers = None
        if self.crl_issuer is not None:
            crl_issuers = []
            for crl_issuer in self.crl_issuer:
                crl_issuers.append(crl_issuer._to_cryptography())

        return x509.DistributionPoint(
            full_name=full_names,
            relative_name=relative_names,
            reasons=reasons,
            crl_issuer=crl_issuers,
        )


class CrlDistributionPoints(Extension):
    """
    Represents the CRL Distribution Points extension in X.509 certificates.

    Attributes:
        crl_distribution_points: List of CRL distribution points.
    """

    crl_distribution_points: List[DistributionPoint]

    def __iter__(self) -> Iterable[DistributionPoint]:
        return iter(self.crl_distribution_points)

    @classmethod
    def from_cryptography(
        cls: Type["CrlDistributionPoints"],
        extension: x509.CRLDistributionPoints,
    ) -> "CrlDistributionPoints":
        """
        Constructs a CrlDistributionPoints object from a cryptography
        CRLDistributionPoints object.

        Args:
            extension: The cryptography CRLDistributionPoints object.

        Returns:
            The constructed CrlDistributionPoints object.
        """
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


class IssuingDistributionPoint(Extension):
    """
    Represents the Issuing Distribution Points extension in X.509 certificates.

    Attributes:
        full_name: List of full names associated with the distribution point.
        name_relative_to_crl_issuer: Relative name to the CRL issuer.
    """

    full_name: Optional[List[GeneralName]] = None
    name_relative_to_crl_issuer: Optional[RelativeDistinguishedName] = None
    only_contains_user_certs: bool = False
    only_contains_ca_certs: bool = False
    indirect_crl: bool = False
    only_contains_attribute_certs: bool = False
    only_some_reasons: Optional[List[Reason]] = None

    @classmethod
    def from_cryptography(
        cls: Type["IssuingDistributionPoint"],
        extension: x509.IssuingDistributionPoint,
    ) -> "IssuingDistributionPoint":
        """
        Constructs a IssuingDistributionPoint object from a cryptography
        IssuingDistributionPoint object.

        Args:
            extension: The cryptography IssuingDistributionPoint object.

        Returns:
            IssuingDistributionPoint: The constructed IssuingDistributionPoint
            object.
        """
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
        if extension.only_some_reasons is not None:
            reasons = []
            for reason in extension.only_some_reasons:
                reasons.append(getattr(Reason, reason.name))

        return cls(
            full_name=full_names,
            name_relative_to_crl_issuer=relative_name,
            only_contains_user_certs=extension.only_contains_user_certs,
            only_contains_ca_certs=extension.only_contains_ca_certs,
            only_contains_attribute_certs=extension.only_contains_attribute_certs,
            indirect_crl=extension.indirect_crl,
            only_some_reasons=reasons,
            _x509_obj=extension,
        )

    def _string_dict(self):
        ret = {
            "Only User Certs": self.only_contains_user_certs,
            "Only CA Certs": self.only_contains_ca_certs,
            "Only Attribute Certs": self.only_contains_attribute_certs,
            "Indirect CRL": self.indirect_crl,
        }
        if self.full_name is not None:
            ret["Full Name"] = []
            for full_name in self.full_name:
                ret["Full Name"].append(full_name._string_dict())
        if self.name_relative_to_crl_issuer is not None:
            ret[
                "Name Relative To CRL Issuer"
            ] = self.name_relative_to_crl_issuer._string_dict()
        return ret

    def _to_cryptography(self) -> x509.IssuingDistributionPoint:
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
        if self.only_some_reasons is not None:
            reasons = []
            for reason in self.only_some_reasons:
                reasons.append(getattr(x509.ReasonFlags, reason.name))
            reasons = frozenset(reasons)

        return x509.IssuingDistributionPoint(
            full_name=full_names,
            relative_name=relative_names,
            only_contains_user_certs=self.only_contains_user_certs,
            only_contains_ca_certs=self.only_contains_ca_certs,
            only_contains_attribute_certs=self.only_contains_attribute_certs,
            indirect_crl=self.indirect_crl,
            only_some_reasons=reasons,
        )


class InhibitAnyPolicy(Extension):
    """
    Represents the Inhibit Any Policy extension in X.509 certificates.

    Attributes:
        skip_certs: Number of certificates to skip.
    """

    skip_certs: int

    @classmethod
    def from_cryptography(
        cls: Type["InhibitAnyPolicy"], extension: x509.InhibitAnyPolicy
    ) -> "InhibitAnyPolicy":
        """
        Constructs an InhibitAnyPolicy object from a cryptography
        InhibitAnyPolicy object.

        Args:
            extension: The cryptography InhibitAnyPolicy object.

        Returns:
            The constructed InhibitAnyPolicy object.
        """
        return cls(
            skip_certs=extension.skip_certs,
            _x509_obj=extension,
        )

    def _string_dict(self):
        return {self.name: {"Skip Certs": self.skip_certs}}

    def _to_cryptography(self) -> x509.InhibitAnyPolicy:
        return x509.InhibitAnyPolicy(self.skip_certs)


class FreshestCrl(CrlDistributionPoints):
    """
    Represents the Freshest CRL extension in X.509 certificates.
    """

    def _to_cryptography(self) -> x509.FreshestCRL:
        dist_points = []
        for dist_point in self.crl_distribution_points:
            dist_points.append(dist_point._to_cryptography())

        return x509.FreshestCRL(dist_points)


class AccessDescriptionId(Enum):
    """
    Enumeration of access description identifiers for X.509 certificates.
    """

    CA_ISSUERS = "1.3.6.1.5.5.7.48.2"
    OCSP = "1.3.6.1.5.5.7.48.1"


class AccessDescription(CryptoParser):
    """
    Represents an Access Description in X.509 certificates.

    Attributes:
        access_method: The access method identifier.
        access_location: The access location.
    """

    access_method: AccessDescriptionId
    access_location: GeneralName

    @classmethod
    def from_cryptography(
        cls: Type["AccessDescription"], extension: x509.AccessDescription
    ) -> "AccessDescription":
        """
        Constructs an AccessDescription object from a cryptography
        AccessDescription object.

        Args:
            extension: The cryptography AccessDescription object.

        Returns:
            The constructed AccessDescription object.
        """
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
    """
    Represents the Authority Information Access extension in X.509
    certificates.

    Attributes:
        access_description: List of access descriptions.
    """

    access_description: List[AccessDescription]

    def __iter__(self) -> Iterable[AccessDescription]:
        return iter(self.access_description)

    @classmethod
    def from_cryptography(
        cls: Type["AuthorityInformationAccess"],
        extension: x509.AuthorityInformationAccess,
    ) -> "AuthorityInformationAccess":
        """
        Constructs an AuthorityInformationAccess object from a
        cryptography AuthorityInformationAccess object.

        Args:
            extension: The cryptography AuthorityInformationAccess object.

        Returns:
            The constructed AuthorityInformationAccess object.
        """
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
    """
    Represents the Subject Information Access extension in X.509
    certificates.
    """

    def _to_cryptography(self) -> x509.SubjectInformationAccess:
        access_descriptions = []
        for access_description in self.access_description:
            access_descriptions.append(access_description._to_cryptography())
        return x509.SubjectInformationAccess(access_descriptions)


class Extensions(CryptoParser):
    """
    Extensions in X.509 certificates.

    Attributes:
        authority_key_identifier: Authority Key Identifier extension.
        subject_key_identifier: Subject Key Identifier extension.
        key_usage: Key Usage extension.
        certificate_policies: Certificate Policies extension.
        subject_alternative_name: Subject Alternative Name extension.
        issuer_alternative_name: Issuer Alternative Name extension.
        subject_directory_attributes: Subject Directory Attributes extension.
        basic_constraints: Basic Constraints extension.
        name_constraints: Name Constraints extension.
        policy_constraints: Policy Constraints extension.
        extended_key_usage: Extended Key Usage extension.
        crl_distribution_points: CRL Distribution Points extension.
        issuing_distribution_point: Issuer Distribution Points extension.
        inhibit_any_policy: Inhibit Any Policy extension.
        freshest_crl: Freshest CRL extension.
        authority_information_access: Authority Information Access extension.
        subject_information_access: Subject Information Access extension.
    """

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
    issuing_distribution_point: Optional[IssuingDistributionPoint] = Field(
        alias=ExtensionOID.ISSUING_DISTRIBUTION_POINT.dotted_string,
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
    def from_cryptography(
        cls: Type["Extensions"], cert_extensions: x509.Extensions
    ) -> "Extensions":
        """
        Constructs an Extensions object from cryptography X.509 Extensions.

        Args:
            cert_extensions: The cryptography X.509 Extensions.

        Returns:
            The constructed Extensions object.
        """
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

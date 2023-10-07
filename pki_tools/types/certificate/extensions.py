import typing
from typing import List, Type, Union, Optional, ClassVar


from cryptography.hazmat._oid import NameOID, ExtensionOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier


from cryptography.x509.extensions import (
    Extensions as x509Extensions,
AuthorityKeyIdentifier as x509AuthorityKeyIdentifier,
    ExtensionNotFound,
    ExtensionTypeVar,
)

from loguru import logger
from pydantic import constr, BaseModel, Field, ConfigDict



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
    pass


class Extensions(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    authority_key_identifier: Optional[AuthorityKeyIdentifier] = Field(alias=ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string, default=None)
    # subject_key_identifier: Optional[SubjectKeyIdentifier] = Field \
    #     (alias=ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string, default=None)

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
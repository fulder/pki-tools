from collections import defaultdict
from typing import List, Type

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier

from pydantic import Field, ConfigDict

from pki_tools.types.crypto_parser import CryptoParser


class Name(CryptoParser):
    """
    Name type describes certificate subject or issuer.
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
    def from_cryptography(cls: Type["Name"], name: x509.Name) -> "Name":
        subject = defaultdict(set)
        for attribute in name:
            for att in name.get_attributes_for_oid(attribute.oid):
                subject[att.oid.dotted_string].add(att.value)
        subject = dict(subject)
        subject["_x509_obj"] = name
        return cls(**subject)

    def to_crypto_name(self) -> x509.Name:
        name_list = []
        for attr_name in vars(self):
            vals = getattr(self, attr_name)
            if not vals:
                continue

            oid = Name.model_fields[attr_name].alias
            for val in vals:
                name_list.append(
                    x509.NameAttribute(x509.ObjectIdentifier(oid), val)
                )

        return x509.Name(name_list)

    def _to_cryptography(self) -> x509.Name:
        name_attributes = []
        for name, field in self.model_fields.items():
            object_identifier = ObjectIdentifier(field.alias)
            field_vals = getattr(self, name)
            for val in field_vals:
                name_attr = x509.NameAttribute(object_identifier, val)
                name_attributes.append(name_attr)
        return x509.Name(name_attributes)

    def _string_dict(self):
        ret = defaultdict(list)
        for a in set(self.model_dump()):
            for val in getattr(self, a):
                ret[a.upper()].append(val)
        return ret

    def __str__(self):
        name_list = []
        for k, v in self._string_dict().items():
            name_list.append(f"{k}: {','.join(v)}")
        return ", ".join(name_list)

    def __eq__(self, other):
        for key in self.model_dump():
            val_list = getattr(self, key)
            if set(val_list) != set(getattr(other, key)):
                return False
        return True

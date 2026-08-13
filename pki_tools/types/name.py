from collections import defaultdict

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from pydantic import ConfigDict, Field

from pki_tools.types.crypto_parser import CryptoParser


class Name(CryptoParser):
    """
    Name type describes e.g. certificate subject or issuer.
    The attributes are following the
    [RFC5280#Section-4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4)

    Note that every attribute is a list of string in order to support
    multivalued RDNs.

    Attributes:
        c: Country Name (2.5.4.6)
        o:  Organization Name (2.5.4.10)
        ou:  Organizational Unit Name (2.5.4.11)
        dnq:  Distinguished Name Qualifier (2.5.4.46)
        s:  State Or Province Name (2.5.4.8)
        cn:  Common Name (2.5.4.3)
        serial:  Serial Number (2.5.4.5)
        ln:  Locality Name (2.5.4.7)
        t:  Title (2.5.4.12)
        sn:  Surname (2.5.4.4)
        gn:  Given Name (2.5.4.42)
        i:  Initials (2.5.4.43)
        p:  Pseudonym (2.5.4.65)
        gq:  Generation Qualifier (2.5.4.44)
        dc:  Domain Component (0.9.2342.19200300.100.1.25)
    """

    model_config = ConfigDict(populate_by_name=True)

    c: list[str] = Field(alias=NameOID.COUNTRY_NAME.dotted_string, default=[])
    o: list[str] = Field(
        alias=NameOID.ORGANIZATION_NAME.dotted_string, default=[]
    )
    ou: list[str] = Field(
        alias=NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, default=[]
    )
    dnq: list[str] = Field(
        alias=NameOID.DN_QUALIFIER.dotted_string, default=[]
    )
    s: list[str] = Field(
        alias=NameOID.STATE_OR_PROVINCE_NAME.dotted_string, default=[]
    )
    cn: list[str] = Field(alias=NameOID.COMMON_NAME.dotted_string, default=[])
    serial: list[str] = Field(
        alias=NameOID.SERIAL_NUMBER.dotted_string, default=[]
    )

    ln: list[str] = Field(
        alias=NameOID.LOCALITY_NAME.dotted_string, default=[]
    )
    t: list[str] = Field(alias=NameOID.TITLE.dotted_string, default=[])
    sn: list[str] = Field(alias=NameOID.SURNAME.dotted_string, default=[])
    gn: list[str] = Field(alias=NameOID.GIVEN_NAME.dotted_string, default=[])
    i: list[str] = Field(alias=NameOID.INITIALS.dotted_string, default=[])
    p: list[str] = Field(alias=NameOID.PSEUDONYM.dotted_string, default=[])
    gq: list[str] = Field(
        alias=NameOID.GENERATION_QUALIFIER.dotted_string, default=[]
    )
    dc: list[str] = Field(
        alias=NameOID.DOMAIN_COMPONENT.dotted_string, default=[]
    )

    @classmethod
    def from_cryptography(cls: type["Name"], name: x509.Name) -> "Name":
        """
        Create a Name instance from a cryptography Name object.

        Args:
            name: The cryptography Name object.

        Returns:
            The Name instance.
        """
        subject = defaultdict(set)
        for attribute in name:
            for att in name.get_attributes_for_oid(attribute.oid):
                subject[att.oid.dotted_string].add(att.value)
        subject = dict(subject)
        subject["_x509_obj"] = name
        return cls(**subject)

    def _to_cryptography(self) -> x509.Name:
        name_attributes = []
        for name, field in Name.model_fields.items():
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
        for k in sorted(self._string_dict()):
            v = self._string_dict()[k]
            name_list.append(f"{k}: {','.join(v)}")
        return ", ".join(name_list)

    def __eq__(self, other):
        for key in self.model_dump():
            val_list = getattr(self, key)
            if set(val_list) != set(getattr(other, key)):
                return False
        return True

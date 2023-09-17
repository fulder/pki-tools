import re
from typing import List

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from pydantic import constr, BaseModel, Field, ConfigDict


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


PEM_REGEX = re.compile(r"-+BEGIN CERTIFICATE-+[\w+/\s=]*-+END CERTIFICATE-+")


class OcspIssuerUri(BaseModel):
    """
    Describes the OCSP Issuer (usually a CA) URI where the public certificate
    can be downloaded

    Examples::
        OcspIssuerUri(uri="https://my.ca.link.com/ca.pem")
    Attributes:
        uri -- The URI for the public issuer certificate
        cache_time_seconds -- Specifies how long the public cert should be
        cached, default is 1 month.
    """

    uri: constr(pattern=r"https*://.*")
    cache_time_seconds: int = 60 * 60 * 24 * 30


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


def _is_pem_str(check):
    return _check_str(PEM_REGEX, check)


def _check_str(pattern, check):
    if not isinstance(check, str):
        return False

    return re.match(pattern, check)

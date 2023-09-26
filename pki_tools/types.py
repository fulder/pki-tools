import re
import time
from datetime import datetime
from functools import lru_cache
from typing import List, Type

import requests
from cryptography import x509
from cryptography.hazmat._oid import NameOID
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
    cache_time_seconds: int = 60 * 60 * 24 * 30


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
        chain = Chain.from_pem(PemCert(pem_string))
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
    def from_pem(cls: Type["Chain"], pem_certs: List[PemCert]) -> "Chain":
        """
        Creates a Chain from a list of
        [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)

        Arguments:
             pem_certs -- List of
             [types.PemCert](https://pki-tools.fulder.dev/pki_tools/types/#pemcert)
             to load into the chain
        """
        certificates = []
        for pem_cert in pem_certs:
            certificates.append(pki_tools.cert_from_pem(pem_cert))
        return cls(certificates=certificates)

    @classmethod
    def from_uri(cls: Type["Chain"], chain_uri: ChainUri) -> "Chain":
        """
        Creates a Chain from a
        [types.ChainUri](https://pki-tools.fulder.dev/pki_tools/types/#chainuri)

        Arguments:
             chain_uri --
             [types.ChainUri](https://pki-tools.fulder.dev/pki_tools/types/#chainuri)
             containing the URI where the certificate chain can be fetched
             from.
        """
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
    if not isinstance(check, PemCert) and not isinstance(check, str):
        return False

    return re.match(PEM_REGEX, check)

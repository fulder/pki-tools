import json
import os

import datetime
from typing import Dict

import pytest
from loguru import logger

from pki_tools import (
    Chain,
    Certificate,
    Name,
    DSAKeyPair,
    Ed25519KeyPair,
    Ed448KeyPair,
    EllipticCurveKeyPair,
    EllipticCurveName,
)
from pki_tools.types import RSAKeyPair, CertificateRevocationList
from pki_tools.types.certificate import Validity
from pki_tools.types.crl import RevokedCertificate
from pki_tools.types.crypto_parser import InitCryptoParser
from pki_tools.types.csr import CertificateSigningRequest
from pki_tools.types.extensions import (
    DistributionPoint,
    RelativeDistinguishedName,
    AccessDescription,
    AuthorityKeyIdentifier,
    Extensions,
    SubjectKeyIdentifier,
    KeyUsage,
    PolicyInformation,
    CertificatePolicies,
    UserNotice,
    NoticeReference,
    SubjectAlternativeName,
    IssuerAlternativeName,
    BasicConstraints,
    NameConstraints,
    PolicyConstraints,
    ExtendedKeyUsage,
    EKU_OID_MAPPING,
    InhibitAnyPolicy,
    FreshestCrl,
    CrlDistributionPoints,
    SubjectInformationAccess,
    AuthorityInformationAccess,
    DnsName,
    DirectoryName,
    IpAddress,
    OtherName,
    RFC822Name,
    RegisteredId,
    UniformResourceIdentifier,
    Reason,
    AttributeTypeAndValue,
    AccessDescriptionId,
)

from pki_tools.types.ocsp import (
    OCSPResponse,
    OcspResponseStatus,
    OcspCertificateStatus,
    OCSPRequest,
)
from pki_tools.types.signature_algorithm import (
    HashAlgorithm,
    HashAlgorithmName,
    SHA256,
    SHA512,
)
from pki_tools.types.utils import _byte_to_hex, _download_cached

TEST_DISTRIBUTION_POINT_URL = "test_url"
TEST_ACCESS_DESCRIPTION = "test-url"
CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))


def test_loguru_sink(message):
    try:
        rec = message.record
        extras = json.dumps(rec["extra"])
        print(f"{rec['time']} - {rec['level']} - {extras} - {rec['message']}")
    except Exception as e:
        print(f"Record was: {message.record}")
        pytest.fail(f"Loguru error: {str(e)}")


@pytest.fixture(scope="function", autouse=True)
def setup_loguru_logging(request):
    # Create a custom Loguru logger configuration that outputs to stdout
    logger.remove()
    logger.add(
        sink=test_loguru_sink,  # Custom sink to print to stdout
        level="TRACE",  # Set the log level as desired
    )


@pytest.fixture(scope="function")
def mocked_requests_get(mocker):
    _download_cached.cache_clear()
    return mocker.patch("httpx.Client.get")


@pytest.fixture()
def key_pair():
    return DSAKeyPair.generate(key_size=1024)
    return Ed448KeyPair.generate()
    return EllipticCurveKeyPair.generate(curve_name=EllipticCurveName.SECP521R1)
    return RSAKeyPair.generate()


@pytest.fixture()
def cert(key_pair):
    return _create_cert(key_pair)


@pytest.fixture()
def crypto_cert(cert):
    return cert._to_cryptography()


@pytest.fixture()
def cert_pem_string(cert):
    return cert.pem_string


@pytest.fixture()
def chain(cert):
    return Chain(certificates=[cert])


@pytest.fixture
def init_crypto_parsers(
    cert, csr, key_pair, ocsp_request
) -> Dict[str, InitCryptoParser]:
    parsers = [
        cert,
        csr,
        _create_crl(key_pair, [cert.serial_number]),
        _create_ocsp_response(cert, key_pair),
        ocsp_request,
    ]

    keys_pairs = [
        RSAKeyPair.generate(),
        DSAKeyPair.generate(key_size=1024),
        Ed25519KeyPair.generate(),
        Ed448KeyPair.generate(),
        EllipticCurveKeyPair.generate(curve_name=EllipticCurveName.SECP521R1),
    ]

    for key_pair in keys_pairs:
        parsers.append(key_pair.private_key)
        parsers.append(key_pair.public_key)

    ret = {}
    for parser in parsers:
        ret[parser.__class__.__name__] = parser

    return ret


TEST_SUBJECT = Name(
    c=["US"],
    ou=["Org Unit"],
    dnq=["DNQ"],
    cn=["mysite.com"],
    o=["My Company", "My Company222"],
    s=["California"],
    ln=["San Francisco"],
    serial=["123123123"],
    t=["Mr."],
    gn=["John"],
    sn=["Doe"],
    i=["J.D."],
    p=["JD"],
    gq=["Second"],
    dc=["DC"],
)


def _create_cert(key_pair, add_crl_extension=True, add_aia_extension=True):
    general_names = [
        DnsName("TEST_DNS_NAME"),
        DirectoryName(TEST_SUBJECT),
        IpAddress("192.168.1.0/24"),
        OtherName(
            oid="1.2.3.4.5", value=_byte_to_hex(key_pair.public_key.der_bytes)
        ),
        RFC822Name("TEST_RFC_NAME"),
        RegisteredId("1.2.3.4.5"),
        UniformResourceIdentifier("http://TEST_URI"),
    ]

    crl_dist_points = [
        DistributionPoint(
            full_name=None,
            name_relative_to_crl_issuer=RelativeDistinguishedName(
                attributes=[
                    AttributeTypeAndValue(oid="1.2.3.4.5", value="TEST_VALUE")
                ]
            ),
            reasons=[
                Reason.key_compromise,
                Reason.ca_compromise,
                Reason.affiliation_changed,
                Reason.superseded,
                Reason.cessation_of_operation,
                Reason.certificate_hold,
                Reason.privilege_withdrawn,
                Reason.aa_compromise,
            ],
            crl_issuer=general_names,
        ),
        DistributionPoint(
            full_name=general_names,
            reasons=[Reason.key_compromise],
            crl_issuer=general_names,
        ),
    ]

    access_descriptions = [
        AccessDescription(
            access_method=AccessDescriptionId.OCSP,
            access_location=UniformResourceIdentifier("http://TEST_URI"),
        )
    ]

    today = datetime.datetime.today()
    one_day = datetime.timedelta(days=1)

    cert = Certificate(
        subject=TEST_SUBJECT,
        issuer=TEST_SUBJECT,
        extensions=Extensions(
            authority_key_identifier=AuthorityKeyIdentifier(
                key_identifier="TEST_KEY_IDENTIFIER".encode(),
                authority_cert_issuer=[RFC822Name("TEST_NAME")],
                authority_cert_serial_number=123123,
                critical=True,
            ),
            subject_key_identifier=SubjectKeyIdentifier(
                subject_key_identifier="TEST_DIGEST".encode(),
            ),
            key_usage=KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=True,
                decipher_only=True,
            ),
            certificate_policies=CertificatePolicies(
                policy_information=[
                    PolicyInformation(
                        policy_identifier="2.23.140.1.2.1",
                        policy_qualifiers=[
                            UserNotice(
                                notice_reference=NoticeReference(
                                    organization="TEST_ORGANIZATION",
                                    notice_numbers=[123, 456],
                                ),
                                explicit_text="TEST_EXPLICIT_TEXT",
                            )
                        ],
                    ),
                    PolicyInformation(
                        policy_identifier="2.23.140.1.2.1",
                        policy_qualifiers=["TEST_CPS"],
                    ),
                ],
            ),
            subject_alternative_name=SubjectAlternativeName(
                general_names=general_names,
            ),
            issuer_alternative_name=IssuerAlternativeName(
                general_names=general_names,
            ),
            basic_constraints=BasicConstraints(
                ca=True,
                path_len_constraint=3,
            ),
            name_constraints=NameConstraints(
                permitted_subtrees=general_names,
                excluded_subtrees=general_names,
            ),
            policy_constraints=PolicyConstraints(
                require_explicit_policy=1,
                inhibit_policy_mapping=2,
            ),
            extended_key_usage=ExtendedKeyUsage(
                ext_key_usage_syntax=EKU_OID_MAPPING.keys()
            ),
            inhibit_any_policy=InhibitAnyPolicy(
                skip_certs=10,
            ),
            freshest_crl=FreshestCrl(
                crl_distribution_points=CrlDistributionPoints(
                    crl_distribution_points=crl_dist_points
                )
            ),
            subject_information_access=SubjectInformationAccess(
                access_description=access_descriptions
            ),
        ),
        validity=Validity(
            not_before=today,
            not_after=today + one_day,
        ),
    )

    if add_crl_extension:
        cert.extensions.crl_distribution_points = CrlDistributionPoints(
            crl_distribution_points=crl_dist_points
        )

    if add_aia_extension:
        cert.extensions.authority_information_access = (
            AuthorityInformationAccess(access_description=access_descriptions)
        )

    cert.sign(key_pair, SHA256)
    return cert


def _create_csr(key_pair):
    csr = CertificateSigningRequest(
        subject=TEST_SUBJECT,
        extensions=Extensions(
            basic_constraints=BasicConstraints(ca=False, critical=True),
            attributes={"1.2.840.113549.1.9.7": b"changit"},
        ),
    )

    csr.sign(key_pair, SHA512)
    return csr


@pytest.fixture()
def crypto_csr(csr):
    return csr._to_cryptography()


@pytest.fixture()
def csr(key_pair):
    return _create_csr(key_pair)


@pytest.fixture()
def cert_with_subject_directory_attributes():
    return """
    -----BEGIN CERTIFICATE-----
    MIIDEDCCAnmgAwIBAgIESZYC0jANBgkqhkiG9w0BAQUFADBIMQswCQYDVQQGEwJE
    RTE5MDcGA1UECgwwR01EIC0gRm9yc2NodW5nc3plbnRydW0gSW5mb3JtYXRpb25z
    dGVjaG5payBHbWJIMB4XDTA0MDIwMTEwMDAwMFoXDTA4MDIwMTEwMDAwMFowZTEL
    MAkGA1UEBhMCREUxNzA1BgNVBAoMLkdNRCBGb3JzY2h1bmdzemVudHJ1bSBJbmZv
    cm1hdGlvbnN0ZWNobmlrIEdtYkgxHTAMBgNVBCoMBVBldHJhMA0GA1UEBAwGQmFy
    emluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc50zVodVa6wHPXswg88P8
    p4fPy1caIaqKIK1d/wFRMN5yTl7T+VOS57sWxKcdDzGzqZJqjwjqAP3DqPK7AW3s
    o7lBG6JZmiqMtlXG3+olv+3cc7WU+qDv5ZXGEqauW4x/DKGc7E/nq2BUZ2hLsjh9
    Xy9+vbw+8KYE9rQEARdpJQIDAQABo4HpMIHmMGQGA1UdCQRdMFswEAYIKwYBBQUH
    CQQxBBMCREUwDwYIKwYBBQUHCQMxAxMBRjAdBggrBgEFBQcJATERGA8xOTcxMTAx
    NDEyMDAwMFowFwYIKwYBBQUHCQIxCwwJRGFybXN0YWR0MA4GA1UdDwEB/wQEAwIG
    QDASBgNVHSAECzAJMAcGBSskCAEBMB8GA1UdIwQYMBaAFAABAgMEBQYHCAkKCwwN
    Dg/+3LqYMDkGCCsGAQUFBwEDBC0wKzApBggrBgEFBQcLAjAdMBuBGW11bmljaXBh
    bGl0eUBkYXJtc3RhZHQuZGUwDQYJKoZIhvcNAQEFBQADgYEAj4yAu7LYa3X04h+C
    7+DyD2xViJCm5zEYg1m5x4znHJIMZsYAU/vJJIJQkPKVsIgm6vP/H1kXyAu0g2Ep
    z+VWPnhZK1uw+ay1KRXw8rw2mR8hQ2Ug6QZHYdky2HH3H/69rWSPp888G8CW8RLU
    uIKzn+GhapCuGoC4qWdlGLWqfpc=
    -----END CERTIFICATE-----
    """


@pytest.fixture
def ocsp_request(cert):
    req = OCSPRequest(
        hash_algorithm=SHA512.algorithm, serial_number=cert.serial_number
    )

    req.create(cert, cert)
    return req


def _create_mocked_ocsp_response(
    cert, key_pair, status=OcspCertificateStatus.GOOD, revocation_time=None
):
    res = _create_ocsp_response(cert, key_pair, status, revocation_time)
    return res.der_bytes


def _create_ocsp_response(
    cert, key_pair, status=OcspCertificateStatus.GOOD, revocation_time=None
):
    res = OCSPResponse(
        response_status=OcspResponseStatus.SUCCESSFUL,
        certificate_status=status,
        revocation_time=revocation_time,
    )
    res.sign(
        cert,
        cert,
        HashAlgorithm(name=HashAlgorithmName.SHA256),
        key_pair.private_key,
    )
    return res


def _create_crl(keypair, revoked_serials):
    today = datetime.datetime.today()
    one_day = datetime.timedelta(days=1)

    revoked_certs = []
    for serial in revoked_serials:
        revoked_certs.append(
            RevokedCertificate(
                serial=serial,
                date=today,
            )
        )

    crl = CertificateRevocationList(
        issuer=TEST_SUBJECT,
        revoked_certs=revoked_certs,
        last_update=today,
        next_update=today + one_day,
    )

    crl.sign(
        private_key=keypair.private_key,
        algorithm=HashAlgorithm(name=HashAlgorithmName.SHA256),
    )
    return crl

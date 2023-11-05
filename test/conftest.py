import ipaddress
import json
import os

from cryptography.hazmat.primitives.asymmetric import rsa


from cryptography import x509

import datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import ocsp, RFC822Name
from loguru import logger

from pki_tools.crl import _get_crl_from_url
from pki_tools import Chain, Name, Certificate

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


@pytest.fixture()
def mocked_requests_get(mocker):
    _get_crl_from_url.cache_clear()
    return mocker.patch("httpx.Client.get")


@pytest.fixture()
def key_pair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture()
def cert(crypto_cert):
    return Certificate.from_cryptography(crypto_cert)


@pytest.fixture()
def crypto_cert(key_pair):
    return _create_cert(key_pair)


@pytest.fixture()
def chain(crypto_cert):
    return Chain.from_cryptography([crypto_cert])


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
    subject = issuer = TEST_SUBJECT.to_crypto_name()

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(
            subject,
        )
        .issuer_name(
            issuer,
        )
        .serial_number(
            x509.random_serial_number(),
        )
        .public_key(
            key_pair.public_key(),
        )
        .not_valid_before(
            datetime.datetime.utcnow(),
        )
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10),
        )
    )

    cert_builder = cert_builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier="TEST_KEY_IDENTIFIER".encode(),
            authority_cert_issuer=[RFC822Name("TEST_NAME")],
            authority_cert_serial_number=123132,
        ),
        critical=True,
    )

    cert_builder = cert_builder.add_extension(
        x509.SubjectKeyIdentifier("TEST_DIGEST".encode()),
        critical=False,
    )

    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
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
        critical=False,
    )

    cert_builder = cert_builder.add_extension(
        x509.CertificatePolicies(
            [
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("2.23.140.1.2.1"),
                    policy_qualifiers=[
                        x509.UserNotice(
                            notice_reference=x509.NoticeReference(
                                organization="TEST_ORGANIZATION",
                                notice_numbers=[123, 456],
                            ),
                            explicit_text="TEST_EXPLICIT_TEXT",
                        )
                    ],
                ),
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("2.23.140.1.2.1"),
                    policy_qualifiers=["TEST_CPS"],
                ),
            ]
        ),
        critical=False,
    )

    key_der = key_pair.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    general_names = [
        x509.DNSName(value="TEST_DNS_NAME"),
        x509.DirectoryName(value=subject),
        x509.IPAddress(ipaddress.IPv4Network("192.168.1.0/24")),
        x509.OtherName(
            type_id=x509.ObjectIdentifier("1.2.3.4.5"), value=key_der
        ),
        x509.RFC822Name(value="TEST_RFC_NAME"),
        x509.RegisteredID(value=x509.ObjectIdentifier("1.2.3.4.5")),
        x509.UniformResourceIdentifier(value="http://TEST_URI"),
    ]

    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName(general_names), critical=False
    )

    cert_builder = cert_builder.add_extension(
        x509.IssuerAlternativeName(general_names), critical=False
    )

    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(
            ca=True,
            path_length=3,
        ),
        critical=False,
    )

    cert_builder = cert_builder.add_extension(
        x509.NameConstraints(
            permitted_subtrees=general_names, excluded_subtrees=general_names
        ),
        critical=False,
    )

    cert_builder = cert_builder.add_extension(
        x509.PolicyConstraints(
            require_explicit_policy=1,
            inhibit_policy_mapping=2,
        ),
        critical=False,
    )

    cert_builder = cert_builder.add_extension(
        x509.ExtendedKeyUsage(
            [
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.CODE_SIGNING,
                x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                x509.ExtendedKeyUsageOID.TIME_STAMPING,
                x509.ExtendedKeyUsageOID.OCSP_SIGNING,
                x509.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
                x509.ExtendedKeyUsageOID.SMARTCARD_LOGON,
                x509.ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC,
                x509.ExtendedKeyUsageOID.IPSEC_IKE,
                x509.ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY,
            ]
        ),
        critical=False,
    )

    crl_dist_points = [
        x509.DistributionPoint(
            full_name=None,
            relative_name=x509.RelativeDistinguishedName(
                [
                    x509.NameAttribute(
                        oid=x509.ObjectIdentifier("1.2.3.4.5"),
                        value="TEST_VALUE",
                    )
                ]
            ),
            reasons=frozenset(
                [
                    x509.ReasonFlags.key_compromise,
                    x509.ReasonFlags.ca_compromise,
                    x509.ReasonFlags.affiliation_changed,
                    x509.ReasonFlags.superseded,
                    x509.ReasonFlags.cessation_of_operation,
                    x509.ReasonFlags.certificate_hold,
                    x509.ReasonFlags.privilege_withdrawn,
                    x509.ReasonFlags.aa_compromise,
                ]
            ),
            crl_issuer=general_names,
        ),
        x509.DistributionPoint(
            full_name=general_names,
            relative_name=None,
            reasons=frozenset([x509.ReasonFlags.key_compromise]),
            crl_issuer=general_names,
        ),
    ]
    if add_crl_extension:
        cert_builder = cert_builder.add_extension(
            x509.CRLDistributionPoints(crl_dist_points),
            critical=False,
        )

    cert_builder = cert_builder.add_extension(
        x509.InhibitAnyPolicy(skip_certs=10), critical=False
    )

    cert_builder = cert_builder.add_extension(
        x509.FreshestCRL(crl_dist_points), critical=False
    )

    access_descriptions = [
        x509.AccessDescription(
            access_method=x509.AuthorityInformationAccessOID.OCSP,
            access_location=x509.UniformResourceIdentifier(
                value="http://TEST_URI",
            ),
        )
    ]
    if add_aia_extension:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityInformationAccess(access_descriptions),
            critical=False,
        )

    cert_builder = cert_builder.add_extension(
        x509.SubjectInformationAccess(access_descriptions), critical=False
    )

    cert = cert_builder.sign(key_pair, hashes.SHA256())

    return cert


@pytest.fixture()
def cert_pem_string(cert):
    return cert.pem_string


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


def _create_mocked_ocsp_response(
    cert, key_pair, status=ocsp.OCSPCertStatus.GOOD, revocation_time=None
):
    cert = cert._x509_obj
    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=cert,
        issuer=cert,
        algorithm=hashes.SHA256(),
        cert_status=status,
        this_update=datetime.datetime.now(),
        next_update=datetime.datetime.now(),
        revocation_time=revocation_time,
        revocation_reason=None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, cert)
    return builder.sign(key_pair, hashes.SHA256()).public_bytes(Encoding.DER)


def _create_crl(keypair, revoked_serials, cert):
    one_day = datetime.timedelta(days=1)
    crl = x509.CertificateRevocationListBuilder()
    crl = crl.issuer_name(cert._x509_obj.subject)
    crl = crl.last_update(datetime.datetime.today())
    crl = crl.next_update(datetime.datetime.today() + one_day)

    for serial in revoked_serials:
        next_revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(
                serial,
            )
            .revocation_date(
                datetime.datetime.today(),
            )
            .build()
        )

        crl = crl.add_revoked_certificate(next_revoked_cert)

    return crl.sign(private_key=keypair, algorithm=hashes.SHA256())

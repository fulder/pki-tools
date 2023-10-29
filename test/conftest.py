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
from pki_tools import Chain, Name

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
def cert(key_pair):
    return _create_cert(key_pair)


@pytest.fixture()
def chain(cert_pem_string):
    return Chain.from_pem_str(cert_pem_string)


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

    if add_crl_extension:
        cert_builder = cert_builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                value=TEST_DISTRIBUTION_POINT_URL,
                            ),
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    ),
                ]
            ),
            critical=False,
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
    generic_names = [
        x509.DNSName(value="TEST_DNS_NAME"),
        x509.DirectoryName(value=subject),
        x509.IPAddress(ipaddress.IPv4Address("192.168.1.1")),
        x509.OtherName(
            type_id=x509.ObjectIdentifier("1.2.3.4.5"), value=key_der
        ),
        x509.RFC822Name(value="TEST_RFC_NAME"),
        x509.RegisteredID(value=x509.ObjectIdentifier("1.2.3.4.5")),
        x509.UniformResourceIdentifier(value="TEST_UNIFORM_RESOURCE_ID"),
    ]

    cert_builder = cert_builder.add_extension(
        x509.SubjectAlternativeName(generic_names), critical=False
    )

    cert_builder = cert_builder.add_extension(
        x509.IssuerAlternativeName(generic_names), critical=False
    )

    cert_builder = cert_builder.add_extension(
        x509.PolicyConstraints(
            require_explicit_policy=1,
            inhibit_policy_mapping=2,
        ),
        critical=False,
    )

    if add_aia_extension:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        access_method=x509.AuthorityInformationAccessOID.OCSP,
                        access_location=x509.UniformResourceIdentifier(
                            value=TEST_ACCESS_DESCRIPTION,
                        ),
                    )
                ]
            ),
            critical=False,
        )

    cert = cert_builder.sign(key_pair, hashes.SHA256())

    return cert


@pytest.fixture()
def cert_pem_string(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _create_mocked_ocsp_response(
    cert, key_pair, status=ocsp.OCSPCertStatus.GOOD, revocation_time=None
):
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
    crl = crl.issuer_name(cert.subject)
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

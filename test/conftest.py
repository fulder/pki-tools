from cryptography.hazmat.primitives.asymmetric import rsa


from cryptography import x509
from cryptography.x509 import NameOID

import datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import ocsp


TEST_DISTRIBUTION_POINT_URL = "test_url"
TEST_ACCESS_DESCRIPTION = "test-url"


@pytest.fixture()
def mocked_requests_get(mocker):
    return mocker.patch("requests.get")


@pytest.fixture()
def key_pair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture()
def cert(key_pair):
    return _create_cert(key_pair)


def _create_cert(key_pair, add_crl_extension=True, add_aia_extension=True):
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        ]
    )

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
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
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


def _create_crl(keypair, revoked_serials):
    one_day = datetime.timedelta(days=1)
    crl = x509.CertificateRevocationListBuilder()
    crl = crl.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "cryptography.io CA"),
            ]
        )
    )
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

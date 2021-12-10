import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID

TEST_DISTRIBUTION_POINT_URL = "test_url"


@pytest.fixture()
def key_pair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture()
def cert(key_pair):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])

    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        key_pair.public_key()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[
                    x509.UniformResourceIdentifier(
                        value=TEST_DISTRIBUTION_POINT_URL
                    )
                ],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            ),
        ]),
        critical=False
    ).sign(key_pair, hashes.SHA256())

    return cert_builder.public_bytes(serialization.Encoding.PEM)


def test_check_revoked_false(cert):
    print(cert)

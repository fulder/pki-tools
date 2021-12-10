import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID

from src import check_revoked

TEST_DISTRIBUTION_POINT_URL = "test_url"


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

    return cert_builder.public_bytes(serialization.Encoding.PEM).decode()


def _create_crl(keypair, revoked_serials):
    one_day = datetime.timedelta(days=1)
    crl = x509.CertificateRevocationListBuilder()
    crl = crl.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io CA'),
    ]))
    crl = crl.last_update(datetime.datetime.today())
    crl = crl.next_update(datetime.datetime.today() + one_day)

    for serial in revoked_serials:
        next_revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            serial
        ).revocation_date(
            datetime.datetime.today()
        ).build()

        crl = crl.add_revoked_certificate(next_revoked_cert)

    crl = crl.sign(private_key=keypair, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


def test_check_revoked_not_revoked_cert(key_pair, mocked_requests_get, cert):
    crl = _create_crl(key_pair, [])

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl

    check_revoked(cert)


import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID, ocsp

from pki_tools.ocsp import (
    ExtensionMissing,
    OcspFetchFailure,
    Revoked,
    check_revoked,
    check_revoked_crypto_cert,
)

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


def _create_cert(key_pair, add_aia_extension=True):
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

    if add_aia_extension:
        cert_builder = cert_builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        access_method=x509.AuthorityInformationAccessOID.OCSP,
                        access_location=x509.UniformResourceIdentifier(
                            value="test_server",
                        ),
                    )
                ]
            ),
            critical=False,
        )

    cert = cert_builder.sign(key_pair, hashes.SHA256())

    return cert


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


@pytest.fixture()
def cert_pem_string(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_not_revoked_cert(mocked_requests_get, cert, key_pair):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert, key_pair
    )

    check_revoked_crypto_cert(cert, cert)


def test_not_revoked_cert_pem(
    mocked_requests_get, cert_pem_string, cert, key_pair
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert, key_pair
    )

    check_revoked(cert_pem_string, cert_pem_string)


def test_check_revoked_revoked_cert(key_pair, mocked_requests_get, cert):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert,
        key_pair,
        status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=datetime.datetime.now(),
    )

    exp_msg = f"Certificate with serial: {cert.serial_number} is revoked since"
    with pytest.raises(Revoked, match=exp_msg):
        check_revoked_crypto_cert(cert, cert)


def test_cert_missing_extension(key_pair):
    cert = _create_cert(key_pair, add_aia_extension=False)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    with pytest.raises(ExtensionMissing):
        check_revoked(cert_pem, cert_pem)


def test_ocsp_fetch_error(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(OcspFetchFailure):
        check_revoked(cert_pem_string, cert_pem_string)

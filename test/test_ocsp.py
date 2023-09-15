import datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.x509 import ocsp

from pki_tools.exceptions import ExtensionMissing, Revoked, OcspFetchFailure
from pki_tools.ocsp import check_revoked_pem
from conftest import _create_cert


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


def test_not_revoked_cert(
    mocked_requests_get, cert, key_pair, cert_pem_string
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert, key_pair
    )

    check_revoked_pem(cert_pem_string, cert_pem_string)


def test_not_revoked_cert_pem(
    mocked_requests_get, cert_pem_string, cert, key_pair
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert, key_pair
    )

    check_revoked_pem(cert_pem_string, cert_pem_string)


def test_check_revoked_revoked_cert(
    key_pair, mocked_requests_get, cert, cert_pem_string
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert,
        key_pair,
        status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=datetime.datetime.now(),
    )

    exp_msg = f"Certificate with serial: {cert.serial_number} is revoked since"
    with pytest.raises(Revoked, match=exp_msg):
        check_revoked_pem(cert_pem_string, cert_pem_string)


def test_cert_missing_extension(key_pair):
    cert = _create_cert(key_pair, add_aia_extension=False)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    with pytest.raises(ExtensionMissing):
        check_revoked_pem(cert_pem, cert_pem)


def test_ocsp_fetch_error(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(OcspFetchFailure):
        check_revoked_pem(cert_pem_string, cert_pem_string)

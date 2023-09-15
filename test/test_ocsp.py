import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from pki_tools.exceptions import ExtensionMissing, Revoked, OcspFetchFailure
from pki_tools.ocsp import check_revoked_pem
from conftest import _create_cert, _create_mocked_ocsp_response


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

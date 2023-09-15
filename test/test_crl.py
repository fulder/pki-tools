import pytest
from cryptography.hazmat.primitives import serialization


from pki_tools.exceptions import (
    ExtensionMissing,
    CrlFetchFailure,
    CrlLoadError,
)
from pki_tools.crl import is_revoked_pem
from conftest import _create_cert, _create_crl


def test_not_revoked_cert(key_pair, mocked_requests_get, cert_pem_string):
    crl = _create_crl(key_pair, [])
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl_der

    is_revoked_pem(cert_pem_string)


def test_not_revoked_cert_pem_crl(
    key_pair, mocked_requests_get, cert_pem_string
):
    crl = _create_crl(key_pair, [])
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl_pem

    is_revoked_pem(cert_pem_string)


def test_is_revoked_revoked_cert(
    key_pair, mocked_requests_get, cert, cert_pem_string
):
    crl = _create_crl(key_pair, [cert.serial_number])
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = crl_der

    assert is_revoked_pem(cert_pem_string)


def test_cert_missing_crl_extension(key_pair):
    cert = _create_cert(key_pair, add_crl_extension=False)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    with pytest.raises(ExtensionMissing):
        is_revoked_pem(cert_pem)


def test_crl_fetch_error(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(CrlFetchFailure):
        is_revoked_pem(cert_pem_string)


def test_crl_load_failure(key_pair, mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = "INVALID_DATA"

    with pytest.raises(CrlLoadError):
        is_revoked_pem(cert_pem_string)

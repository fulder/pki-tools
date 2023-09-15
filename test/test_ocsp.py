import pytest
from cryptography.hazmat.primitives import serialization

from pki_tools.exceptions import ExtensionMissing, OcspFetchFailure
from pki_tools.ocsp import is_revoked_pem
from conftest import _create_cert


def test_cert_missing_extension(key_pair):
    cert = _create_cert(key_pair, add_aia_extension=False)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    with pytest.raises(ExtensionMissing):
        is_revoked_pem(cert_pem, cert_pem)


def test_ocsp_fetch_error(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(OcspFetchFailure):
        is_revoked_pem(cert_pem_string, cert_pem_string)

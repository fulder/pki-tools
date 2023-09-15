import pytest

from pki_tools.exceptions import CertLoadError
from pki_tools.utils import cert_from_pem, is_revoked_pem
from conftest import _create_mocked_ocsp_response


def test_cert_load_error():
    with pytest.raises(CertLoadError):
        cert_from_pem("BAD_PEM_DATA")


def test_is_revoked_pem(
    cert_pem_string, mocked_requests_get, cert, key_pair
):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = _create_mocked_ocsp_response(
        cert, key_pair
    )

    assert is_revoked_pem(cert_pem_string, cert_pem_string)

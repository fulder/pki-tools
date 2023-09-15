import pytest


from pki_tools.exceptions import (
    CrlFetchFailure,
    CrlLoadError,
)
from pki_tools.crl import is_revoked_pem


def test_crl_fetch_error(mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 503

    with pytest.raises(CrlFetchFailure):
        is_revoked_pem(cert_pem_string)


def test_crl_load_failure(key_pair, mocked_requests_get, cert_pem_string):
    mocked_requests_get.return_value.status_code = 200
    mocked_requests_get.return_value.content = "INVALID_DATA"

    with pytest.raises(CrlLoadError):
        is_revoked_pem(cert_pem_string)
